#!/usr/bin/env bash

# Параметры по умолчанию
SERVER="192.168.1.100"
USER="Admin"
PASSWORD="123"

# Можно переопределить через аргументы командной строки: script.sh [server] [user] [password]
if [ $# -ge 1 ]; then SERVER="$1"; fi
if [ $# -ge 2 ]; then USER="$2"; fi
if [ $# -ge 3 ]; then PASSWORD="$3"; fi

# URL для входа
URL="http://${SERVER}:4040/web_api/v2.core.login"

# Формируем JSON с помощью jq, если он установлен, иначе используем python3
if command -v jq >/dev/null 2>&1; then
    JSON_DATA=$(jq -n --arg u "$USER" --arg p "$PASSWORD" '[$u, $p, {}]')
elif command -v python3 >/dev/null 2>&1; then
    JSON_DATA=$(python3 -c 'import json,sys; print(json.dumps([sys.argv[1], sys.argv[2], {}]))' "$USER" "$PASSWORD")
else
    echo "false"
    exit 1
fi

# Отправляем POST-запрос и сохраняем ответ
RESPONSE=$(curl -s -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "$JSON_DATA" 2>/dev/null)

# Проверяем, что curl выполнился успешно
if [ $? -ne 0 ]; then
    echo "false"
    exit 1
fi

# Проверяем наличие auth_token в ответе
if echo "$RESPONSE" | grep -q '"auth_token"'; then
    echo "successful"
else
    echo "false"
fi
