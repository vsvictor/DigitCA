# REST API Examples

All scripts in this directory are autonomous and can be run independently.

## Defaults

- API base URL: `https://digitca.digit.com`
- Basic auth: `admin:secret`

You can override at runtime:

```bash
API_BASE="https://digitca.digit.com" USERNAME="admin" PASSWORD="secret" ./examples/01_health.sh
```

If you use a self-signed certificate:

```bash
CURL_INSECURE=true ./examples/03_openapi_json.sh
```

## Endpoints coverage

- `01_health.sh` -> `GET /health`
- `02_swagger_docs.sh` -> `GET /docs`
- `03_openapi_json.sh` -> `GET /api-doc/openapi.json`
- `10_init_root.sh` -> `POST /api/v1/ca/root`
- `11_export_root.sh` -> `GET /api/v1/ca/root`
- `12_init_intermediate.sh` -> `POST /api/v1/ca/intermediate`
- `13_export_intermediate.sh` -> `GET /api/v1/ca/intermediate`
- `20_issue_certificate.sh` -> `POST /api/v1/certificates`
- `21_list_certificates.sh` -> `GET /api/v1/certificates`
- `22_get_certificate.sh` -> `GET /api/v1/certificates/{serial}`
- `23_verify_certificate.sh` -> `GET /api/v1/certificates/{serial}/verify`
- `24_revoke_certificate.sh` -> `POST /api/v1/certificates/{serial}/revoke`
- `25_get_certificate_chain.sh` -> `GET /api/v1/certificates/{serial}/chain`
- `30_get_root_crl.sh` -> `GET /crl/root.crl`
- `31_get_intermediate_crl.sh` -> `GET /crl/intermediate.crl`
- `40_audit_log.sh` -> `GET /api/v1/audit`
- `50_ldap_search_by_cn.sh` -> `GET /api/v1/ldap/certificates?cn=...`

## Multi-language examples

- `multilang/rust` — автономний приклад на Rust
- `multilang/kotlin` — автономний приклад на Kotlin
- `multilang/flutter` — автономний приклад на Flutter
- `multilang/nodejs` — автономний приклад на Node.js

## OCSP multi-language examples

- `ocsp_multilang/` — окремий набір прикладів для `digitca-ocsp` (`bash`, `rust`, `kotlin`, `flutter`, `nodejs`)

