#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/3] Starting MongoDB + LDAP + API containers..."
docker compose up -d

echo "[2/3] Waiting for API to be ready..."
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:8080/health" >/dev/null; then
    break
  fi
  sleep 1
done

echo "[3/3] Health check response:"
curl -s "http://localhost:8080/health"
echo

