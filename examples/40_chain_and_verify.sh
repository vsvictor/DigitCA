#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8080"
AUTH="Authorization: Basic $(printf 'admin:secret' | base64)"

echo "Issuing certificate for chain/verify example..."
ISSUE_RESPONSE=$(curl -s -X POST "$API/api/v1/certificates" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"chain-check.internal","profile":"server-tls","issuer":"auto","dns_names":["chain-check.internal"],"ip_sans":[],"validity_days":365}')

echo "$ISSUE_RESPONSE"
SERIAL=$(echo "$ISSUE_RESPONSE" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')

if [[ -z "$SERIAL" ]]; then
  echo "Failed to parse serial from issue response"
  exit 1
fi

echo "Verify certificate serial=$SERIAL:"
curl -s "$API/api/v1/certificates/$SERIAL/verify" -H "$AUTH"
echo

echo "Export chain for serial=$SERIAL:"
curl -s "$API/api/v1/certificates/$SERIAL/chain" -H "$AUTH"
echo

