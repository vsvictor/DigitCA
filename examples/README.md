# Examples

This directory contains practical examples for running DigitCA locally.

## Prerequisites

- Docker + Docker Compose
- Rust toolchain
- `curl`

## Quick run

1. Start local services:

```bash
./examples/00_start_dev.sh
```

2. Initialize Root + Intermediate CA:

```bash
./examples/10_init_ca.sh
```

3. Issue certificates and list them:

```bash
./examples/20_issue_and_list.sh
```

4. Revoke certificate and fetch CRL:

```bash
./examples/30_revoke_and_crl.sh
```

5. Export chain and verify certificate:

```bash
./examples/40_chain_and_verify.sh
```

## Notes

- These scripts assume local credentials: `admin:secret`.
- API base URL is `http://localhost:8080`.
- If your deployment enforces HTTPS for Basic auth, add header `X-Forwarded-Proto: https` in each request.

