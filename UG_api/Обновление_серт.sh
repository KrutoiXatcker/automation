#!/bin/bash

# Запуск: ./auto.sh SERVER USER PASSWORD RESOURCE CRT KEY
SERVER="${1:?Укажи адрес UG}"
USER="${2:?Укажи пользователя}"
PASSWORD="${3:?Укажи пароль}"
RESOURCE="${4:?Укажи имя правила публикации}"
CRT_FILE="${5:?Укажи CRT-файл}"
KEY_FILE="${6:?Укажи KEY-файл}"

BASE_URL="http://${SERVER}:4040/web_api"

# Экранирование строк для JSON
json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

# Запрос к API
api() {
    curl -fsS --max-time 30 "${BASE_URL}/$1" \
        -H 'Content-Type: application/json' \
        --data-binary @- <<< "$2"
}

# Проверяем файлы
if [[ ! -r "$CRT_FILE" || ! -s "$CRT_FILE" ||
      ! -r "$KEY_FILE" || ! -s "$KEY_FILE" ]]; then
    echo "CRT или KEY недоступен либо пуст"
    exit 1
fi

# Авторизация
JSON_DATA="[\"$(json_escape "$USER")\",\"$(json_escape "$PASSWORD")\",{}]"
RESPONSE=$(api v2.core.login "$JSON_DATA") || exit 1

TOKEN_REGEX='"auth_token"[[:space:]]*:[[:space:]]*"([^"]+)"'

if [[ "$RESPONSE" =~ $TOKEN_REGEX ]]; then
    TOKEN="${BASH_REMATCH[1]}"
else
    echo "Ошибка авторизации: $RESPONSE"
    exit 1
fi

# Закрываем сессию при завершении
trap 'api v2.core.logout "[\"${TOKEN}\"]" >/dev/null 2>&1' EXIT

# Ищем правило публикации
RULE_ID=""
OLD_CERT_ID=""
MATCHES=0
OFFSET=0

RULE_REGEX='"id"[[:space:]]*:[[:space:]]*([0-9]+)[^}]*"name"[[:space:]]*:[[:space:]]*"([^"]*)"[^}]*"certificate_id"[[:space:]]*:[[:space:]]*([0-9]+)'
COUNT_REGEX='"count"[[:space:]]*:[[:space:]]*([0-9]+)'
CERT_REGEX='"certificate_id"[[:space:]]*:[[:space:]]*([0-9]+)'

while true; do
    RESPONSE=$(api v1.reverseproxy.rules.list \
        "[\"${TOKEN}\", ${OFFSET}, 100, {}]") || exit 1

    if [[ "$RESPONSE" =~ $COUNT_REGEX ]]; then
        COUNT="${BASH_REMATCH[1]}"
    else
        echo "Ошибка получения правил: $RESPONSE"
        exit 1
    fi

    RULES="$RESPONSE"

    while [[ "$RULES" =~ $RULE_REGEX ]]; do
        MATCH="${BASH_REMATCH[0]}"
        ID="${BASH_REMATCH[1]}"
        NAME="${BASH_REMATCH[2]}"
        CERT_ID="${BASH_REMATCH[3]}"

        if [[ "$NAME" == "$RESOURCE" ]]; then
            RULE_ID="$ID"
            OLD_CERT_ID="$CERT_ID"
            MATCHES=$((MATCHES + 1))
        fi

        RULES="${RULES#*"$MATCH"}"
    done

    OFFSET=$((OFFSET + 100))
    if (( OFFSET >= COUNT )); then
        break
    fi
done

if (( MATCHES != 1 )); then
    echo "Для '$RESOURCE' найдено правил: $MATCHES. Нужно одно."
    exit 1
fi

if [[ "$OLD_CERT_ID" == "0" ]]; then
    echo "У правила не выбран сертификат"
    exit 1
fi

NEW_NAME="${RESOURCE}-${OLD_CERT_ID}"

echo "Ресурс: $RESOURCE"
echo "ID правила: $RULE_ID"
echo "Старый сертификат ID: $OLD_CERT_ID"

# CRT в PEM: первый сертификат — сайт, остальные — цепочка УЦ
CERT=""
CHAIN=""
NUMBER=0
IN_CERT=0

while IFS= read -r LINE || [[ -n "$LINE" ]]; do
    LINE="${LINE%$'\r'}"

    if [[ "$LINE" == "-----BEGIN CERTIFICATE-----" ]]; then
        if (( IN_CERT )); then
            echo "Некорректный PEM в CRT"
            exit 1
        fi
        NUMBER=$((NUMBER + 1))
        IN_CERT=1
    fi

    if (( IN_CERT )); then
        if (( NUMBER == 1 )); then
            CERT+="$LINE"$'\n'
        else
            CHAIN+="$LINE"$'\n'
        fi
    fi

    if [[ "$LINE" == "-----END CERTIFICATE-----" ]]; then
        IN_CERT=0
    fi
done < "$CRT_FILE"

if [[ -z "$CERT" ]] || (( IN_CERT )); then
    echo "CRT должен содержать полные PEM-блоки CERTIFICATE"
    exit 1
fi

# Кодируем сертификат, цепочку и ключ
CERT_B64=$(printf '%s' "$CERT" | base64 -w 0) || exit 1
CHAIN_B64=$(printf '%s' "$CHAIN" | base64 -w 0) || exit 1
KEY_B64=$(base64 -w 0 < "$KEY_FILE") || exit 1

JSON_DATA="[\"${TOKEN}\",{
    \"name\":\"$(json_escape "$NEW_NAME")\",
    \"role\":\"none\",
    \"cert_data\":{\"__base64__\":\"${CERT_B64}\"},
    \"key_data\":{\"__base64__\":\"${KEY_B64}\"}"

if [[ -n "$CHAIN" ]]; then
    JSON_DATA+=",\"chain_data\":{\"__base64__\":\"${CHAIN_B64}\"}"
fi

JSON_DATA+="}]"

# Создаём новый сертификат
echo "Создаём сертификат: $NEW_NAME"
RESPONSE=$(api v2.settings.certificate.add "$JSON_DATA") || exit 1

NEW_ID_REGEX='^[[:space:]]*([0-9]+)[[:space:]]*$'

if [[ "$RESPONSE" =~ $NEW_ID_REGEX ]]; then
    NEW_CERT_ID="${BASH_REMATCH[1]}"
else
    echo "Создание сертификата не подтверждено: $RESPONSE"
    exit 1
fi

if [[ "$NEW_CERT_ID" == "0" || "$NEW_CERT_ID" == "$OLD_CERT_ID" ]]; then
    echo "API вернул неожиданный ID: $NEW_CERT_ID"
    exit 1
fi

echo "Новый сертификат ID: $NEW_CERT_ID"

# Получаем полные настройки существующего правила
RULE=$(api v1.reverseproxy.rule.fetch \
    "[\"${TOKEN}\", ${RULE_ID}]") || exit 1

if [[ "$RULE" =~ $CERT_REGEX ]]; then
    CERT_FIELD="${BASH_REMATCH[0]}"
    CURRENT_CERT_ID="${BASH_REMATCH[1]}"
else
    echo "Не удалось прочитать сертификат правила: $RULE"
    exit 1
fi

if [[ "$CURRENT_CERT_ID" != "$OLD_CERT_ID" ]]; then
    echo "Сертификат правила уже изменён. Операция остановлена."
    exit 1
fi

# Меняем только ссылку на сертификат
RULE="${RULE/"$CERT_FIELD"/\"certificate_id\":${NEW_CERT_ID}}"

# Убираем служебные поля
for FIELD in id guid position position_layer; do
    FIELD_REGEX="\"${FIELD}\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)[[:space:]]*,[[:space:]]*"

    if [[ "$RULE" =~ $FIELD_REGEX ]]; then
        REMOVE="${BASH_REMATCH[0]}"
        RULE="${RULE/"$REMOVE"/}"
    else
        FIELD_REGEX=",[[:space:]]*\"${FIELD}\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)"

        if [[ "$RULE" =~ $FIELD_REGEX ]]; then
            REMOVE="${BASH_REMATCH[0]}"
            RULE="${RULE/"$REMOVE"/}"
        fi
    fi
done

# Обновляем существующее правило
RESPONSE=$(api v1.reverseproxy.rule.update \
    "[\"${TOKEN}\", ${RULE_ID}, ${RULE}]") || exit 1

if [[ ! "$RESPONSE" =~ ^[[:space:]]*true[[:space:]]*$ ]]; then
    echo "Ошибка переключения правила: $RESPONSE"
    exit 1
fi

# Проверяем, что правило использует новый сертификат
RESPONSE=$(api v1.reverseproxy.rule.fetch \
    "[\"${TOKEN}\", ${RULE_ID}]") || exit 1

if [[ "$RESPONSE" =~ $CERT_REGEX ]]; then
    CURRENT_CERT_ID="${BASH_REMATCH[1]}"
else
    echo "Не удалось проверить правило. Старый сертификат сохранён."
    exit 1
fi

if [[ "$CURRENT_CERT_ID" != "$NEW_CERT_ID" ]]; then
    echo "Переключение не подтверждено. Старый сертификат сохранён."
    exit 1
fi

echo "Правило $RESOURCE переключено: $OLD_CERT_ID → $NEW_CERT_ID"

# Удаляем старый сертификат
# Если он ещё используется, UG отклонит удаление с ошибкой 502
RESPONSE=$(api v2.settings.certificate.delete \
    "[\"${TOKEN}\", ${OLD_CERT_ID}]") || exit 1

if [[ "$RESPONSE" =~ ^[[:space:]]*true[[:space:]]*$ ]]; then
    echo "Старый сертификат ID=$OLD_CERT_ID удалён."
else
    echo "Правило переключено, но старый сертификат не удалён: $RESPONSE"
    exit 1
fi

echo "Готово."
