#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://digitca.digit.com}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-secret}"
AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$USERNAME" "$PASSWORD" | base64)"
CURL_OPTS=(-sS)
[[ "${CURL_INSECURE:-false}" == "true" ]] && CURL_OPTS+=(-k)

# Ensure root exists and at least one cert exists
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/root" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Root","validity_days":3650}' >/dev/null
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/certificates" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"list-sample.internal","profile":"server-tls","issuer":"root","dns_names":["list-sample.internal"],"ip_sans":[],"validity_days":30}' >/dev/null

curl "${CURL_OPTS[@]}" "${API_BASE}/api/v1/certificates?include_revoked=true&page=1&per_page=20" -H "$AUTH_HEADER"
echo

