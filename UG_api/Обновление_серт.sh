#!/usr/bin/env bash

# ====== НАСТРОЙКИ ======
SERVER="192.168.1.100"
USER="Admin"
PASSWORD="123"
BASE_DIR="./"          # Корневая папка с подпапками сертификатов
# ========================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Проверка зависимостей
for cmd in curl jq base64; do
    command -v "$cmd" >/dev/null 2>&1 || { echo -e "${RED}Ошибка: $cmd не установлен${NC}"; exit 1; }
done
OPENSSL_AVAILABLE=0
command -v openssl >/dev/null 2>&1 && OPENSSL_AVAILABLE=1

api_call() {
    local method="$1"
    local args_json="$2"
    curl -s -X POST "http://${SERVER}:4040/web_api/${method}" \
        -H 'Content-Type: application/json' -d "$args_json"
}

find_file() {
    for p in "$@"; do
        [ -f "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}

# Конвертация сертификата DER -> PEM, если нужно
normalize_cert_to_pem() {
    local file="$1"
    if grep -q "BEGIN CERTIFICATE" "$file" 2>/dev/null; then
        cat "$file"
    elif [ $OPENSSL_AVAILABLE -eq 1 ]; then
        openssl x509 -inform DER -in "$file" -outform PEM 2>/dev/null
    else
        cat "$file"
    fi
}

# Нормализация ключа: PKCS#8 -> традиционный RSA PEM, если нужно
normalize_key_to_pem() {
    local key_file="$1"
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        if grep -q "BEGIN PRIVATE KEY" "$key_file"; then
            openssl rsa -in "$key_file" -traditional 2>/dev/null || cat "$key_file"
        else
            cat "$key_file"
        fi
    else
        cat "$key_file"
    fi
}

# Извлечение leaf-сертификата и цепочки из файла
extract_leaf_chain() {
    local cert_file="$1"
    local leaf_file="$2"
    local chain_file="$3"
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        # leaf: первый сертификат
        openssl x509 -in "$cert_file" -outform PEM > "$leaf_file" 2>/dev/null
        # цепочка: все последующие
        awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++; if(n>1) print_flag=1} print_flag{print}' "$cert_file" > "$chain_file"
    else
        # fallback с awk
        awk 'BEGIN{RS="-----END CERTIFICATE-----"} /BEGIN CERTIFICATE/ {print $0 "-----END CERTIFICATE-----"}' "$cert_file" | head -1 > "$leaf_file"
        awk 'BEGIN{RS="-----END CERTIFICATE-----"} /BEGIN CERTIFICATE/ {print $0 "-----END CERTIFICATE-----"}' "$cert_file" | tail -n +2 > "$chain_file"
    fi
}

# ---------- Аутентификация ----------
echo -e "${YELLOW}Аутентификация...${NC}"
auth_token=$(api_call "v2.core.login" "$(jq -nc --arg u "$USER" --arg p "$PASSWORD" '[$u, $p, {}]')" | jq -r '.auth_token // empty')
[ -z "$auth_token" ] && { echo -e "${RED}Ошибка аутентификации${NC}"; exit 1; }
echo -e "${GREEN}Успешная аутентификация${NC}"

# ---------- Получение списка сертификатов ----------
echo -e "${YELLOW}Получение списка сертификатов...${NC}"
list_resp=$(api_call "v2.settings.certificates.list" "$(jq -nc --arg t "$auth_token" '[$t, 0, 1000, {}]')")
if echo "$list_resp" | grep -q '"faultCode"'; then
    echo -e "${RED}Ошибка получения списка: $list_resp${NC}"
    exit 1
fi
certs_array=$(echo "$list_resp" | jq '.items')
[ "$certs_array" = "null" ] && { echo -e "${RED}Не удалось извлечь items${NC}"; exit 1; }

get_cert_id() {
    echo "$certs_array" | jq -r --arg n "$1" '.[] | select(.name == $n) | .id' | head -1
}

# ---------- Обработка подпапок ----------
overall_status=0
for dir in "$BASE_DIR"/*/; do
    [ -d "$dir" ] || continue
    domain=$(basename "$dir")
    echo -e "\n${YELLOW}=== Обработка: $domain ===${NC}"

    # Поиск файла сертификата
    cert_file=$(find_file \
        "${dir}public.cer" "${dir}public.crt" "${dir}certificate.crt" \
        "${dir}certificate.cer" "${dir}cert.pem" "${dir}${domain}.crt" \
        "${dir}${domain}.cer" "${dir}"*.crt "${dir}"*.cer "${dir}"*.pem)
    [ -z "$cert_file" ] && { echo -e "  ${RED}Не найден файл сертификата${NC}"; overall_status=1; continue; }

    # Поиск файла ключа
    key_file=$(find_file \
        "${dir}privat.key" "${dir}private.key" "${dir}${domain}.key" \
        "${dir}"*.key "${dir}"*.pem "${dir}"*.priv)
    [ -z "$key_file" ] && { echo -e "  ${RED}Не найден файл ключа${NC}"; overall_status=1; continue; }

    # Если key_file совпадает с cert_file (оба .pem), ищем отдельный .key
    if [ "$key_file" = "$cert_file" ]; then
        key_file=$(find_file "${dir}"*.key)
        [ -z "$key_file" ] && { echo -e "  ${RED}Не найден отдельный файл ключа (.key)${NC}"; overall_status=1; continue; }
    fi

    echo "  Сертификат: $(basename "$cert_file")"
    echo "  Ключ:       $(basename "$key_file")"

    # Извлекаем leaf и цепочку
    tmp_leaf=$(mktemp)
    tmp_chain=$(mktemp)
    extract_leaf_chain "$cert_file" "$tmp_leaf" "$tmp_chain"
    leaf_pem=$(cat "$tmp_leaf")
    if [ -s "$tmp_chain" ]; then
        chain_pem=$(cat "$tmp_chain")
    else
        chain_pem=""
    fi
    rm -f "$tmp_leaf" "$tmp_chain"

    # Если цепочки нет в файле, ищем отдельный файл цепочки
    if [ -z "$chain_pem" ]; then
        chain_file=$(find_file \
            "${dir}chain.pem" "${dir}chain.cer" "${dir}chain.crt" \
            "${dir}fullchain.pem" "${dir}fullchain.cer" "${dir}fullchain.crt" \
            "${dir}ca.pem" "${dir}ca.cer" "${dir}ca.crt")
        if [ -n "$chain_file" ]; then
            chain_pem=$(normalize_cert_to_pem "$chain_file")
            echo "  Найден отдельный файл цепочки: $(basename "$chain_file")"
        fi
    fi

    # Нормализуем ключ
    key_pem=$(normalize_key_to_pem "$key_file")
    [ -z "$key_pem" ] && { echo -e "  ${RED}Не удалось прочитать ключ${NC}"; overall_status=1; continue; }

    # Проверка соответствия leaf и ключа (информационно)
    if [ $OPENSSL_AVAILABLE -eq 1 ]; then
        cert_mod=$(echo "$leaf_pem" | openssl x509 -noout -modulus 2>/dev/null | openssl md5 | awk '{print $2}')
        key_mod=$(echo "$key_pem" | openssl rsa -noout -modulus 2>/dev/null | openssl md5 | awk '{print $2}')
        if [ -n "$cert_mod" ] && [ -n "$key_mod" ]; then
            if [ "$cert_mod" = "$key_mod" ]; then
                echo "  Ключ и leaf-сертификат совпадают"
            else
                echo -e "  ${YELLOW}Внимание: ключ и leaf-сертификат не совпадают${NC}"
            fi
        fi
    fi

    # Base64
    cert_b64=$(echo "$leaf_pem" | base64 -w0 2>/dev/null || echo "$leaf_pem" | base64 | tr -d '\n')
    key_b64=$(echo "$key_pem" | base64 -w0 2>/dev/null || echo "$key_pem" | base64 | tr -d '\n')
    chain_b64=""
    if [ -n "$chain_pem" ]; then
        chain_b64=$(echo "$chain_pem" | base64 -w0 2>/dev/null || echo "$chain_pem" | base64 | tr -d '\n')
    fi

    cert_id=$(get_cert_id "$domain")

    if [ -n "$cert_id" ]; then
        echo -e "  Найден сертификат с ID=$cert_id. Обновляем..."
        update_data=$(jq -nc --arg cert_b64 "$cert_b64" --arg key_b64 "$key_b64" \
            '{ cert_data: { __base64__: $cert_b64 }, key_data: { __base64__: $key_b64 } }')
        if [ -n "$chain_b64" ]; then
            update_data=$(echo "$update_data" | jq --arg chain_b64 "$chain_b64" '. + { chain_data: { __base64__: $chain_b64 } }')
        fi
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
        if [ -n "$chain_b64" ]; then
            cert_data=$(echo "$cert_data" | jq --arg chain_b64 "$chain_b64" '. + { chain_data: { __base64__: $chain_b64 } }')
        fi
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
