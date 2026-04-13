#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://digitca.digit.com}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-secret}"
AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$USERNAME" "$PASSWORD" | base64)"
CURL_OPTS=(-sS)
[[ "${CURL_INSECURE:-false}" == "true" ]] && CURL_OPTS+=(-k)

# Ensure root and intermediate exist
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/root" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Root","validity_days":3650}' >/dev/null
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/intermediate" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Intermediate","validity_days":1825}' >/dev/null

curl "${CURL_OPTS[@]}" "${API_BASE}/api/v1/ca/intermediate" -H "$AUTH_HEADER"
echo

