# digitca-ocsp

`digitca-ocsp` is an OCSP responder service for DigitCA.

## Features

- RFC-style OCSP responder endpoints:
  - `POST /ocsp` with `application/ocsp-request` body (DER)
  - `GET /ocsp/{base64-der}`
- `GET /health` liveness probe
- Uses DigitCA MongoDB data (`certificates`, `revocations`, `ca_root`, `ca_intermediate`)
- Signs OCSP responses with issuer private key from stored CA records

## Environment variables

Required:

- `MONGODB_URI`
- `MONGODB_DB`

Optional:

- `OCSP_BIND` (default: `0.0.0.0`)
- `OCSP_PORT` (default: `8082`)
- `OCSP_NEXT_UPDATE_SECONDS` (default: `3600`)
- `ROOT_CA_KEY_PASSPHRASE`
- `INTERMEDIATE_CA_KEY_PASSPHRASE`

## Run locally

```bash
cd /Users/victor/DigitCA
cargo run -p digitca-ocsp
```

## Test

```bash
cd /Users/victor/DigitCA
cargo test -p digitca-ocsp
```

