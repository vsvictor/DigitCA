#!/usr/bin/env bash
# OCSP client example for digitca-ocsp — bash
#
# Usage:
#   chmod +x ocsp_example.sh
#   OCSP_REQUEST_DER=./request.der ./ocsp_example.sh
#
# Generate request.der with:
#   openssl ocsp -issuer issuer.pem -cert leaf.pem -reqout request.der
set -euo pipefail

OCSP_BASE="${OCSP_BASE:-http://localhost:8082}"
OCSP_REQUEST_DER="${OCSP_REQUEST_DER:-./request.der}"
OCSP_RESPONSE_DER="${OCSP_RESPONSE_DER:-./response.der}"

if [[ ! -f "${OCSP_REQUEST_DER}" ]]; then
  echo "[bash] error: request DER file not found: ${OCSP_REQUEST_DER}" >&2
  exit 1
fi

echo "[bash] GET ${OCSP_BASE}/health"
curl -fsS "${OCSP_BASE}/health"
echo

echo "[bash] POST ${OCSP_BASE}/ocsp"
curl -fsS \
  -X POST "${OCSP_BASE}/ocsp" \
  -H "Content-Type: application/ocsp-request" \
  --data-binary "@${OCSP_REQUEST_DER}" \
  -o "${OCSP_RESPONSE_DER}"

echo "[bash] OCSP response saved: ${OCSP_RESPONSE_DER}"

