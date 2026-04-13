#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://digitca.digit.com}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-secret}"
AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$USERNAME" "$PASSWORD" | base64)"
CURL_OPTS=(-sS)
[[ "${CURL_INSECURE:-false}" == "true" ]] && CURL_OPTS+=(-k)

CN="${CN:-ldap-sample.internal}"

# Prepare one certificate with target CN
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/root" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Root","validity_days":3650}' >/dev/null
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/certificates" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d "{\"common_name\":\"${CN}\",\"profile\":\"server-tls\",\"issuer\":\"root\",\"dns_names\":[\"${CN}\"],\"ip_sans\":[],\"validity_days\":30}" >/dev/null

curl "${CURL_OPTS[@]}" "${API_BASE}/api/v1/ldap/certificates?cn=${CN}" -H "$AUTH_HEADER"
echo

