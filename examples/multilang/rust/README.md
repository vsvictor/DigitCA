# Rust REST API Example

## Run

```bash
cd /Users/victor/DigitCA/examples/multilang/rust
API_BASE=https://digitca.digit.com USERNAME=admin PASSWORD=secret cargo run
```

## What it does

- Calls `GET /health`
- Calls `GET /docs`
- Calls `GET /api/v1/certificates` with Basic auth

