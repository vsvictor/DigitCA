#!/usr/bin/env bash
set -euo pipefail

# Deploy DigitCA as a production REST API service (Linux + systemd + nginx)
# for domain: digitca.digit.com (default).
#
# Usage:
#   ./scripts/deploy_production.sh
#   DOMAIN=digitca.digit.com ENV_FILE=/Users/victor/DigitCA/.env ./scripts/deploy_production.sh
#   DOMAIN=digitca.digit.com WITH_CERTBOT=true ./scripts/deploy_production.sh

DOMAIN="${DOMAIN:-digitca.digit.com}"
APP_USER="${APP_USER:-digitca}"
APP_GROUP="${APP_GROUP:-digitca}"
APP_DIR="${APP_DIR:-/opt/digitca}"
SERVICE_NAME="${SERVICE_NAME:-digitca}"
WITH_CERTBOT="${WITH_CERTBOT:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_DIR}/.env}"

SYSTEMD_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NGINX_SITE_FILE="/etc/nginx/sites-available/${DOMAIN}"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/${DOMAIN}"

log() { printf "[deploy] %s\n" "$*"; }
fail() { printf "[deploy][error] %s\n" "$*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

[[ "$(uname -s)" == "Linux" ]] || fail "This script supports Linux only (systemd + nginx)."

require_cmd cargo
require_cmd sudo
require_cmd systemctl
require_cmd nginx

[[ -f "${ENV_FILE}" ]] || fail "Environment file not found: ${ENV_FILE}"

if ! grep -q '^ROOT_CA_KEY_PASSPHRASE=' "${ENV_FILE}"; then
  fail "ROOT_CA_KEY_PASSPHRASE is missing in ${ENV_FILE}"
fi
if ! grep -q '^INTERMEDIATE_CA_KEY_PASSPHRASE=' "${ENV_FILE}"; then
  fail "INTERMEDIATE_CA_KEY_PASSPHRASE is missing in ${ENV_FILE}"
fi

log "Building release binary..."
cd "${REPO_DIR}"
cargo build --release

log "Ensuring system user/group exist..."
if ! getent group "${APP_GROUP}" >/dev/null; then
  sudo groupadd --system "${APP_GROUP}"
fi
if ! id -u "${APP_USER}" >/dev/null 2>&1; then
  sudo useradd --system --gid "${APP_GROUP}" --home-dir "${APP_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
fi

log "Installing application files to ${APP_DIR}..."
sudo mkdir -p "${APP_DIR}"
sudo cp "${REPO_DIR}/target/release/digitca" "${APP_DIR}/digitca"
sudo cp "${ENV_FILE}" "${APP_DIR}/.env"
sudo chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
sudo chmod 750 "${APP_DIR}/digitca"
sudo chmod 600 "${APP_DIR}/.env"

log "Writing systemd service: ${SYSTEMD_FILE}"
sudo tee "${SYSTEMD_FILE}" >/dev/null <<EOF
[Unit]
Description=DigitCA REST API
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/digitca serve
Restart=always
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

log "Configuring nginx site: ${DOMAIN}"
sudo tee "${NGINX_SITE_FILE}" >/dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

if [[ ! -L "${NGINX_SITE_LINK}" ]]; then
  sudo ln -s "${NGINX_SITE_FILE}" "${NGINX_SITE_LINK}"
fi

if [[ "${WITH_CERTBOT}" == "true" ]]; then
  require_cmd certbot
  log "Requesting/renewing TLS certificate via certbot..."
  sudo certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email
else
  log "Skipping certbot step (WITH_CERTBOT=${WITH_CERTBOT})."
  log "Make sure certificate files exist: /etc/letsencrypt/live/${DOMAIN}/"
fi

log "Reloading services..."
sudo systemctl daemon-reload
sudo systemctl enable --now "${SERVICE_NAME}"
sudo nginx -t
sudo systemctl reload nginx

log "Done. Service status:"
sudo systemctl --no-pager --full status "${SERVICE_NAME}" | sed -n '1,20p'

log "Health check (may fail if DNS/TLS is not fully ready):"
set +e
curl -fsS "https://${DOMAIN}/health"
health_rc=$?
set -e
if [[ $health_rc -ne 0 ]]; then
  log "Health check failed. Verify DNS, firewall, and TLS cert for ${DOMAIN}."
else
  echo
  log "Health check passed."
fi

