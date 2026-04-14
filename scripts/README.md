# Deployment Scripts

## deploy_production.sh

Deploys DigitCA as a Linux production service with:

- systemd service (`digitca.service`)
- systemd service (`digitca-ocsp.service`)
- nginx reverse proxy for `digitca.digit.com`
- optional certbot TLS setup (`WITH_CERTBOT=true`)

## Requirements

- Linux host with `systemd`
- `nginx` installed
- Rust toolchain (`cargo`)
- `sudo` access
- Optional: `certbot`

## Usage

```bash
cd /Users/victor/DigitCA
chmod +x scripts/deploy_production.sh
./scripts/deploy_production.sh
```

With explicit options:

```bash
DOMAIN=digitca.digit.com \
ENV_FILE=/Users/victor/DigitCA/.env \
OCSP_LOCAL_PORT=8082 \
WITH_CERTBOT=true \
./scripts/deploy_production.sh
```

## Notes

- The script copies binary and env to `/opt/digitca`.
- Nginx proxies `/` to API (`127.0.0.1:8080`) and `/ocsp` to OCSP (`127.0.0.1:${OCSP_LOCAL_PORT:-8082}`).
- For production security, set non-empty passphrases in `.env` before running.
- If certbot step is disabled, provide certificates at:
  - `/etc/letsencrypt/live/digitca.digit.com/fullchain.pem`
  - `/etc/letsencrypt/live/digitca.digit.com/privkey.pem`

