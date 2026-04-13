#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8080"
AUTH="Authorization: Basic $(printf 'admin:secret' | base64)"

echo "Issuing certificate to revoke..."
ISSUE_RESPONSE=$(curl -s -X POST "$API/api/v1/certificates" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"to-revoke.internal","profile":"server-tls","issuer":"root","dns_names":["to-revoke.internal"],"ip_sans":[],"validity_days":365}')

echo "$ISSUE_RESPONSE"
SERIAL=$(echo "$ISSUE_RESPONSE" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')

if [[ -z "$SERIAL" ]]; then
  echo "Failed to parse serial from issue response"
  exit 1
fi

echo "Revoking serial=$SERIAL with reason=keyCompromise..."
curl -s -X POST "$API/api/v1/certificates/$SERIAL/revoke" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}'
echo

echo "Root CRL:"
curl -s "$API/crl/root.crl" -H "$AUTH"
echo

echo "Intermediate CRL (may be empty/not-found if no intermediate setup):"
curl -s "$API/crl/intermediate.crl" -H "$AUTH"
echo

