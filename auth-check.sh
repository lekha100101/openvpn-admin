#!/bin/bash

# URL API авторизации
API_URL="http://127.0.0.1:5000/api/authenticate"

# Безопасная отправка данных с URL-кодированием
response=$(curl -s -o /dev/null -w "%{http_code}" \
  --data-urlencode "username=$username" \
  --data-urlencode "password=$password" \
  "$API_URL")

# Обработка ответа
if [ "$response" == "200" ]; then
    exit 0
else
    exit 1
fi
