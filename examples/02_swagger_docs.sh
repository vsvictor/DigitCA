#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-https://digitca.digit.com}"
CURL_OPTS=(-sS -i)
[[ "${CURL_INSECURE:-false}" == "true" ]] && CURL_OPTS+=(-k)

curl "${CURL_OPTS[@]}" "${API_BASE}/docs"

