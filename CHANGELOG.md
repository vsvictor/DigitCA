# Changelog

## [Unreleased]

### Added
- OpenAPI + Swagger UI (`/docs`, `/api-doc/openapi.json`).
- REST endpoint для PEM-ланцюжка сертифіката (`/api/v1/certificates/{serial}/chain`).
- CRL endpoint-и: `/crl/root.crl`, `/crl/intermediate.crl`.
- Підтримка IP SAN (`--ip`) для `server-tls` сертифікатів.
- Пагінація для списку сертифікатів (`page`, `per_page`).
- Нові API інтеграційні тести (`tests/api.rs`).
- Типізовані причини відкликання (`RevocationReason`) з валідацією.

### Changed
- `POST /api/v1/certificates` повертає приватний ключ лише під час issue.
- `GET /api/v1/certificates` та `GET /api/v1/certificates/{serial}` більше не повертають `key_pem`.
- CRL генерація переведена з `501 Not Implemented` на реальну побудову і підпис.

### Security
- Закрито витік `key_pem` у read/list endpoint-ах.
- Додано валідацію `reason` при відкликанні сертифіката.

