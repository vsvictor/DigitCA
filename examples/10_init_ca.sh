#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8080"
AUTH="Authorization: Basic $(printf 'admin:secret' | base64)"

init_root_payload='{"common_name":"DigitCA Root","validity_days":3650}'
init_int_payload='{"common_name":"DigitCA Intermediate","validity_days":1825}'

echo "Initializing Root CA..."
curl -s -X POST "$API/api/v1/ca/root" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d "$init_root_payload"
echo

echo "Initializing Intermediate CA..."
curl -s -X POST "$API/api/v1/ca/intermediate" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d "$init_int_payload"
echo

