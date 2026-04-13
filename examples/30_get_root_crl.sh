#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://digitca.digit.com}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-secret}"
AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$USERNAME" "$PASSWORD" | base64)"
CURL_OPTS=(-sS)
[[ "${CURL_INSECURE:-false}" == "true" ]] && CURL_OPTS+=(-k)

# Prepare one revoked root-issued certificate for CRL
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/ca/root" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"DigitCA Root","validity_days":3650}' >/dev/null
ISSUE_RESPONSE=$(curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/certificates" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"common_name":"root-crl-sample.internal","profile":"server-tls","issuer":"root","dns_names":["root-crl-sample.internal"],"ip_sans":[],"validity_days":30}')
SERIAL=$(echo "$ISSUE_RESPONSE" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
[[ -n "$SERIAL" ]] || { echo "Cannot parse serial"; exit 1; }
curl "${CURL_OPTS[@]}" -X POST "${API_BASE}/api/v1/certificates/${SERIAL}/revoke" \
  -H "$AUTH_HEADER" -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}' >/dev/null

curl "${CURL_OPTS[@]}" "${API_BASE}/crl/root.crl" -H "$AUTH_HEADER"
echo

