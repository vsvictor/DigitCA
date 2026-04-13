#!/usr/bin/env bash
set -euo pipefail

API="http://localhost:8080"
AUTH="Authorization: Basic $(printf 'admin:secret' | base64)"

issue_server_payload='{"common_name":"service.internal","profile":"server-tls","issuer":"auto","dns_names":["service.internal","api.internal"],"ip_sans":["127.0.0.1"],"validity_days":365}'
issue_client_payload='{"common_name":"workstation-007","profile":"client-auth","issuer":"root","dns_names":[],"ip_sans":[],"validity_days":365}'

echo "Issuing server certificate..."
curl -s -X POST "$API/api/v1/certificates" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d "$issue_server_payload"
echo

echo "Issuing client-auth certificate..."
curl -s -X POST "$API/api/v1/certificates" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d "$issue_client_payload"
echo

echo "Listing certificates (page=1, per_page=20):"
curl -s "$API/api/v1/certificates?include_revoked=true&page=1&per_page=20" \
  -H "$AUTH"
echo

