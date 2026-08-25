#!/usr/bin/env bash

# ====== НАСТРОЙКИ ======
SERVER="192.168.1.100"
USER="Admin"
PASSWORD="123"
BASE_DIR="./"          # Корневая папка, в которой лежат подпапки с сертификатами
# ========================

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

for cmd in curl jq base64; do
    command -v "$cmd" >/dev/null 2>&1 || { echo -e "${RED}Ошибка: $cmd не установлен${NC}"; exit 1; }
done
OPENSSL_AVAILABLE=0
command -v openssl >/dev/null 2>&1 && OPENSSL_AVAILABLE=1

api_call() {
    local method="$1"; local args_json="$2"
    curl -s -X POST "http://${SERVER}:4040/web_api/${method}" \
        -H 'Content-Type: application/json' -d "$args_json"
}

find_file() {
    for p in "$@"; do
        [ -f "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}

normalize_cert_to_pem() {
    local file="$1"
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        openssl x509 -in "$file" -outform PEM 2>/dev/null || cat "$file"
    else
        cat "$file"
    fi
}

normalize_key_to_pem() {
    local key_file="$1"
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        # Пытаемся конвертировать в традиционный RSA PEM, если это PKCS#8
        if grep -q "BEGIN PRIVATE KEY" "$key_file"; then
            openssl rsa -in "$key_file" -traditional 2>/dev/null || cat "$key_file"
        else
            cat "$key_file"
        fi
    else
        cat "$key_file"
    fi
}

# Аутентификация
echo -e "${YELLOW}Аутентификация...${NC}"
auth_token=$(api_call "v2.core.login" "$(jq -nc --arg u "$USER" --arg p "$PASSWORD" '[$u, $p, {}]')" | jq -r '.auth_token // empty')
[ -z "$auth_token" ] && { echo -e "${RED}Ошибка аутентификации${NC}"; exit 1; }
echo -e "${GREEN}Успешная аутентификация${NC}"

# Получение списка сертификатов
echo -e "${YELLOW}Получение списка сертификатов...${NC}"
list_resp=$(api_call "v2.settings.certificates.list" "$(jq -nc --arg t "$auth_token" '[$t, 0, 1000, {}]')")
if echo "$list_resp" | grep -q '"faultCode"'; then
    echo -e "${RED}Ошибка получения списка: $list_resp${NC}"; exit 1
fi
certs_array=$(echo "$list_resp" | jq '.items')
[ "$certs_array" = "null" ] && { echo -e "${RED}Не удалось извлечь items${NC}"; exit 1; }

get_cert_id() {
    echo "$certs_array" | jq -r --arg n "$1" '.[] | select(.name == $n) | .id' | head -1
}

overall_status=0
for dir in "$BASE_DIR"/*/; do
    [ -d "$dir" ] || continue
    domain=$(basename "$dir")
    echo -e "\n${YELLOW}=== Обработка: $domain ===${NC}"

    cert_file=$(find_file "${dir}public.cer" "${dir}public.crt" "${dir}certificate.crt" "${dir}certificate.cer" "${dir}cert.pem" "${dir}${domain}.crt" "${dir}${domain}.cer" "${dir}"*.crt "${dir}"*.cer "${dir}"*.pem)
    [ -z "$cert_file" ] && { echo -e "  ${RED}Не найден файл сертификата${NC}"; overall_status=1; continue; }

    key_file=$(find_file "${dir}privat.key" "${dir}private.key" "${dir}${domain}.key" "${dir}"*.key "${dir}"*.pem "${dir}"*.priv)
    [ -z "$key_file" ] && { echo -e "  ${RED}Не найден файл ключа${NC}"; overall_status=1; continue; }

    echo "  Сертификат: $(basename "$cert_file")"
    echo "  Ключ:       $(basename "$key_file")"

    # Извлекаем только leaf (первый сертификат) в PEM
    leaf_pem=$(normalize_cert_to_pem "$cert_file")
    [ -z "$leaf_pem" ] && { echo -e "  ${RED}Не удалось извлечь сертификат${NC}"; overall_status=1; continue; }

    # Ключ нормализуем
    key_pem=$(normalize_key_to_pem "$key_file")
    [ -z "$key_pem" ] && { echo -e "  ${RED}Не удалось прочитать ключ${NC}"; overall_status=1; continue; }

    # Проверяем соответствие
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        cert_mod=$(echo "$leaf_pem" | openssl x509 -noout -modulus 2>/dev/null | openssl md5 | awk '{print $2}')
        key_mod=$(echo "$key_pem" | openssl rsa -noout -modulus 2>/dev/null | openssl md5 | awk '{print $2}')
        if [ -n "$cert_mod" ] && [ -n "$key_mod" ] && [ "$cert_mod" != "$key_mod" ]; then
            echo -e "  ${YELLOW}Внимание: ключ и сертификат не совпадают (модули разные)${NC}"
        else
            echo "  Ключ и сертификат совпадают"
        fi
    fi

    # Base64
    cert_b64=$(echo "$leaf_pem" | base64 -w0 2>/dev/null || echo "$leaf_pem" | base64 | tr -d '\n')
    key_b64=$(echo "$key_pem" | base64 -w0 2>/dev/null || echo "$key_pem" | base64 | tr -d '\n')

    cert_id=$(get_cert_id "$domain")

    if [ -n "$cert_id" ]; then
        echo -e "  Найден сертификат с ID=$cert_id. Обновляем leaf и ключ..."
        update_data=$(jq -nc --arg cert_b64 "$cert_b64" --arg key_b64 "$key_b64" \
            '{ cert_data: { __base64__: $cert_b64 }, key_data: { __base64__: $key_b64 } }')
        args=$(jq -nc --arg t "$auth_token" --arg id "$cert_id" --argjson data "$update_data" '[$t, ($id|tonumber), $data]')
        response=$(api_call "v2.settings.certificate.update" "$args")
        if ! echo "$response" | grep -q '"faultCode"'; then
            echo -e "  ${GREEN}✓ Обновлён${NC}"
        else
            echo -e "  ${RED}✗ Ошибка: $response${NC}"
            overall_status=1
        fi
    else
        echo -e "  Сертификат не найден. Добавляем..."
        cert_data=$(jq -nc --arg name "$domain" --arg cert_b64 "$cert_b64" --arg key_b64 "$key_b64" \
            '{ name: $name, cert_data: { __base64__: $cert_b64 }, key_data: { __base64__: $key_b64 }, role: "none" }')
        args=$(jq -nc --arg t "$auth_token" --argjson cert "$cert_data" '[$t, $cert]')
        response=$(api_call "v2.settings.certificate.add" "$args")
        if ! echo "$response" | grep -q '"faultCode"'; then
            new_id=$(echo "$response" | jq -r 'if type == "number" then . else .id // empty end')
            echo -e "  ${GREEN}✓ Добавлен, ID=$new_id${NC}"
        else
            echo -e "  ${RED}✗ Ошибка: $response${NC}"
            overall_status=1
        fi
    fi
done

echo ""
if [ $overall_status -eq 0 ]; then
    echo -e "${GREEN}Все сертификаты обработаны успешно${NC}"
else
    echo -e "${RED}Некоторые сертификаты не обработаны${NC}"
    exit 1
fi
