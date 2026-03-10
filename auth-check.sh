#!/bin/bash
API_URL="http://127.0.0.1:5000/api/authenticate"

# Реальный IP клиента из OpenVPN (если доступен)
CLIENT_IP="${untrusted_ip:-unknown}"
CLIENT_PORT="${untrusted_port:-unknown}"

response=$(curl -s -o /dev/null -w "%{http_code}" \
  --data-urlencode "username=$username" \
  --data-urlencode "password=$password" \
  --data-urlencode "client_ip=$CLIENT_IP" \
  --data-urlencode "client_port=$CLIENT_PORT" \
  "$API_URL")

if [ "$response" = "200" ]; then
  exit 0
else
  exit 1
fi
