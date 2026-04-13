#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://digitca.digit.com}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-secret}"
AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$USERNAME" "$PASSWORD" | base64)"
CURL_OPTS=(-sS)
[[ "${CURL_INSECURE:-false}" == "true" ]] && CURL_OPTS+=(-k)

# Prepare one revoked intermediate-issued certificate for CRL
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/root" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Root","validity_days":3650}' >/dev/null
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/intermediate" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Intermediate","validity_days":1825}' >/dev/null
ISSUE_RESPONSE=$(curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/certificates" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"int-crl-sample.internal","profile":"server-tls","issuer":"intermediate","dns_names":["int-crl-sample.internal"],"ip_sans":[],"validity_days":30}')
SERIAL=$(echo "$ISSUE_RESPONSE" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
[[ -n "$SERIAL" ]] || { echo "Cannot parse serial"; exit 1; }
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/certificates/${SERIAL}/revoke" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"reason":"caCompromise"}' >/dev/null

curl "${CURL_OPTS[@]}" "${API_BASE}/crl/intermediate.crl" -H "$AUTH_HEADER"
echo

