#!/usr/bin/env bash

# Каталог, в котором находится скрипт
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# По умолчанию используется arm.txt рядом со скриптом.
# Также можно указать другой файл: ./RDP.sh hosts.txt
HOSTS_FILE="${1:-${SCRIPT_DIR}/arm.txt}"

# Рабочие учётные данные Remmina
USERNAME='ДОМЕН\username'
ENCRYPTED_PASSWORD='Зашифрованый_пароль'

# Задержка между подключениями
DELAY_SECONDS=1

if ! command -v remmina >/dev/null 2>&1; then
    echo "Ошибка: Remmina не установлена."
    exit 1
fi

if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "Ошибка: файл не найден: $HOSTS_FILE"
    exit 1
fi

COUNT=0

echo "Файл со списком: $HOSTS_FILE"
echo

while IFS= read -r HOST || [[ -n "$HOST" ]]; do
    # Удаляем символ CR, если файл создавался в Windows
    HOST="${HOST//$'\r'/}"

    # Удаляем пробелы в начале строки
    HOST="${HOST#"${HOST%%[![:space:]]*}"}"

    # Удаляем пробелы в конце строки
    HOST="${HOST%"${HOST##*[![:space:]]}"}"

    # Пропускаем пустые строки
    [[ -z "$HOST" ]] && continue

    # Пропускаем строки-комментарии
    [[ "$HOST" == \#* ]] && continue

    COUNT=$((COUNT + 1))

    echo "Открываю RDP-сессию: $HOST"

    remmina -c "rdp://${USERNAME}:${ENCRYPTED_PASSWORD}@${HOST}" &

    sleep "$DELAY_SECONDS"

done < "$HOSTS_FILE"

echo
echo "Запущено подключений: $COUNT"
