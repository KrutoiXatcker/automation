#!/usr/bin/env bash

# ====== НАСТРОЙКИ ======
SERVER="192.168.1.100"
USER="Admin"
PASSWORD="123"
BASE_DIR="./"          # Корневая папка, в которой лежат подпапки с сертификатами
# ========================


# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ========================

# Проверка зависимостей
for cmd in curl jq base64; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}Ошибка: $cmd не установлен${NC}"
        exit 1
    fi
done

# ---------- API вызов ----------
api_call() {
    local method="$1"
    local args_json="$2"
    local url="http://${SERVER}:4040/web_api/${method}"
    curl -s -X POST "$url" -H 'Content-Type: application/json' -d "$args_json"
}

# ---------- Аутентификация ----------
echo -e "${YELLOW}Аутентификация...${NC}"
auth_token=$(api_call "v2.core.login" \
    "$(jq -nc --arg u "$USER" --arg p "$PASSWORD" '[$u, $p, {}]')" | jq -r '.auth_token // empty')

if [ -z "$auth_token" ]; then
    echo -e "${RED}Ошибка аутентификации${NC}"
    exit 1
fi
echo -e "${GREEN}Успешная аутентификация${NC}"

# ---------- Получение списка сертификатов ----------
echo -e "${YELLOW}Получение списка существующих сертификатов...${NC}"
list_resp=$(api_call "v2.settings.certificates.list" \
    "$(jq -nc --arg t "$auth_token" '[$t, 0, 1000, {}]')")

if [ $? -ne 0 ] || echo "$list_resp" | grep -q '"faultCode"'; then
    echo -e "${RED}Ошибка получения списка сертификатов: $list_resp${NC}"
    exit 1
fi

certs_array=$(echo "$list_resp" | jq '.items')
if [ "$certs_array" = "null" ]; then
    echo -e "${RED}Не удалось извлечь items из ответа${NC}"
    exit 1
fi

# Функция поиска ID сертификата по имени
get_cert_id() {
    local name="$1"
    echo "$certs_array" | jq -r --arg n "$name" '.[] | select(.name == $n) | .id' | head -1
}

# ---------- Обработка каждой подпапки ----------
overall_status=0
for dir in "$BASE_DIR"/*/; do
    [ -d "$dir" ] || continue
    domain=$(basename "$dir")
    echo ""
    echo -e "${YELLOW}=== Обработка домена: $domain ===${NC}"

    cert_file="${dir}public.cer"
    key_file="${dir}privat.key"

    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
        echo -e "${RED}  Пропуск: отсутствует public.cer или privat.key${NC}"
        overall_status=1
        continue
    fi

    # Base64 без переносов
    if base64 --help 2>&1 | grep -q -- '-w'; then
        cert_b64=$(base64 -w0 < "$cert_file")
        key_b64=$(base64 -w0 < "$key_file")
    else
        cert_b64=$(base64 < "$cert_file" | tr -d '\n')
        key_b64=$(base64 < "$key_file" | tr -d '\n')
    fi

    cert_id=$(get_cert_id "$domain")

    if [ -n "$cert_id" ]; then
        echo -e "  Найден существующий сертификат с ID=${cert_id}. Обновляем...${NC}"
        # Объект с обновляемыми полями
        update_data=$(jq -nc \
            --arg cert_b64 "$cert_b64" \
            --arg key_b64 "$key_b64" \
            '{ cert_data: { __base64__: $cert_b64 }, key_data: { __base64__: $key_b64 } }')
        args=$(jq -nc --arg t "$auth_token" --arg id "$cert_id" --argjson data "$update_data" '[$t, ($id|tonumber), $data]')
        response=$(api_call "v2.settings.certificate.update" "$args")
        if [ $? -eq 0 ] && ! echo "$response" | grep -q '"faultCode"'; then
            echo -e "  ${GREEN}✓ Сертификат успешно обновлён${NC}"
        else
            echo -e "  ${RED}✗ Ошибка обновления: $response${NC}"
            overall_status=1
        fi
    else
        echo -e "  Сертификат не найден. Добавляем новый...${NC}"
        cert_data=$(jq -nc \
            --arg name "$domain" \
            --arg cert_b64 "$cert_b64" \
            --arg key_b64 "$key_b64" \
            '{ name: $name, cert_data: { __base64__: $cert_b64 }, key_data: { __base64__: $key_b64 }, role: "none" }')
        args=$(jq -nc --arg t "$auth_token" --argjson cert "$cert_data" '[$t, $cert]')
        response=$(api_call "v2.settings.certificate.add" "$args")
        if [ $? -eq 0 ] && ! echo "$response" | grep -q '"faultCode"'; then
            # Метод возвращает ID (число) или объект с id
            new_id=$(echo "$response" | jq -r 'if type == "number" then . else .id // empty end')
            echo -e "  ${GREEN}✓ Сертификат успешно добавлен, ID=${new_id}${NC}"
        else
            echo -e "  ${RED}✗ Ошибка добавления: $response${NC}"
            overall_status=1
        fi
    fi
done

echo ""
if [ $overall_status -eq 0 ]; then
    echo -e "${GREEN}Все сертификаты обработаны успешно${NC}"
else
    echo -e "${RED}Возникли ошибки при обработке некоторых сертификатов${NC}"
    exit 1
fi
