# DigitCA

DigitCA — це CLI-проєкт на Rust, який реалізує Certificate Authority з:
- LDAP-автентифікацією та авторизацією через `ldap3`
- зберіганням root CA, сертифікатів і відкликань у MongoDB
- шифруванням приватного ключа root CA через `ROOT_CA_KEY_PASSPHRASE`
- Підтримка `intermediate CA` для безпечнішого випуску leaf-сертифікатів
- **Аудит-лог** усіх операцій у MongoDB

> Репозиторій працює як Cargo workspace: кореневий пакет `digitca` містить основний CLI/API, а `crates/digitca-ocsp` — повноцінний OCSP responder сервіс.

## Можливості

- Ініціалізація Root CA
- Ініціалізація Intermediate CA
- Видача сертифікатів (X.509)
- Профілі сертифікатів: `server-tls`, `client-auth`
- Вибір issuer: `auto`, `root`, `intermediate`
- Відкликання сертифікатів
- Отримання і список сертифікатів
- Перевірка сертифіката (підпис, ревокація, час дії)
- Експорт Root CA та Intermediate CA у PEM
- Експорт CRL: Root і Intermediate (`/crl/root.crl`, `/crl/intermediate.crl`)
- **Аудит-лог** усіх операцій з actor, target і часом
- OpenAPI/Swagger UI для REST API (`/docs`)

## Технології

- Rust + Tokio
- `openssl` для криптографії/X.509 та шифрування приватного ключа
- `mongodb` для persistence
- `ldap3` для контролю доступу
- `clap` для CLI

## Документація

- Технічне завдання (ТЗ): `docs/TZ.md`

## Швидкий старт

1. Скопіюйте `.env.example` у `.env`.
2. За потреби підніміть локальне dev-оточення.
3. Зберіть проєкт і виконайте команди CLI.

```bash
cd /Users/victor/DigitCA
cp .env.example .env
docker compose up -d
cargo build -p digitca
```

> Якщо порт `8080` уже зайнятий, змініть `API_PORT` у `.env` (наприклад, `API_PORT=18080`) і запускайте `docker compose up -d` повторно.
> Якщо зайняті інші порти, використайте `OCSP_PORT`, `MONGO_PORT`, `LDAP_PORT`, `PHPLDAPADMIN_PORT`.

## Локальне dev-оточення

Файл `docker-compose.yml` запускає:
- `mongo` на `localhost:27017`
- `openldap` на `localhost:389`
- `phpldapadmin` на `http://localhost:8081`
- `api` на `http://localhost:8080`
- `ocsp` на `http://localhost:8082`

Початкові dev-облікові дані:
- LDAP bind admin: `cn=admin,dc=example,dc=org` / `admin`
- LDAP користувач для CLI: `admin` / `secret`
- LDAP група доступу: `cn=ca-admins,ou=groups,dc=example,dc=org`

LDIF для bootstrap лежить у `infra/ldap/bootstrap.ldif`.

## Конфігурація

Приклад у `.env.example`:

```dotenv
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=digitca
ROOT_CA_KEY_PASSPHRASE=change-me
INTERMEDIATE_CA_KEY_PASSPHRASE=change-me-too

LDAP_URL=ldap://localhost:389
LDAP_BIND_DN=cn=admin,dc=example,dc=org
LDAP_BIND_PASSWORD=admin
LDAP_BASE_DN=dc=example,dc=org
LDAP_USER_ATTR=uid
LDAP_REQUIRED_GROUP=cn=ca-admins,ou=groups,dc=example,dc=org

# Security
BASIC_AUTH_REQUIRE_HTTPS=false

# CORS (опційно; через кому)
CORS_ALLOWED_ORIGINS=

# Host-порт для docker-compose API (container порт = 8080)
API_PORT=8080
# Host-порт для docker-compose OCSP responder (container порт = 8082)
OCSP_PORT=8082
OCSP_NEXT_UPDATE_SECONDS=3600
# Host-порт MongoDB
MONGO_PORT=27017
# Host-порт OpenLDAP
LDAP_PORT=389
# Host-порт phpLDAPadmin
PHPLDAPADMIN_PORT=8081
```

> `ROOT_CA_KEY_PASSPHRASE` використовується для шифрування приватного ключа root CA перед збереженням у MongoDB і для його подальшого розшифрування під час випуску сертифікатів.
>
> `INTERMEDIATE_CA_KEY_PASSPHRASE` використовується для шифрування приватного ключа intermediate CA. Якщо її не задано, застосунок використовує значення `ROOT_CA_KEY_PASSPHRASE` як fallback.

### Профілі сертифікатів

- `server-tls` — сертифікат для TLS-сервера, потребує хоча б один `--dns` або `--ip`
- `client-auth` — сертифікат клієнтської автентифікації, може бути без `--dns`

### Вибір issuer

- `auto` — якщо `intermediate CA` існує, leaf-сертифікат підписується ним, інакше використовується root
- `root` — примусово підписувати напряму root CA
- `intermediate` — примусово підписувати через intermediate CA

### Причини відкликання (`--reason`)

Підтримувані значення:
- `unspecified`
- `keyCompromise`
- `caCompromise`
- `affiliationChanged`
- `superseded`
- `cessationOfOperation`
- `certificateHold`
- `removeFromCrl`
- `privilegeWithdrawn`
- `aaCompromise`

## Команди

```bash
cargo run -p digitca -- init-root --common-name "DigitCA Root" --validity-days 3650 --username admin --password secret
cargo run -p digitca -- init-intermediate --common-name "DigitCA Intermediate" --validity-days 1825 --username admin --password secret
cargo run -p digitca -- issue --common-name "service.internal" --profile server-tls --issuer auto --dns service.internal --dns api.internal --validity-days 365 --username admin --password secret
cargo run -p digitca -- issue --common-name "workstation-007" --profile client-auth --validity-days 365 --username admin --password secret
cargo run -p digitca -- list --include-revoked --username admin --password secret
cargo run -p digitca -- get --serial <SERIAL> --username admin --password secret
cargo run -p digitca -- verify --serial <SERIAL> --username admin --password secret
cargo run -p digitca -- revoke --serial <SERIAL> --reason "keyCompromise" --username admin --password secret
cargo run -p digitca -- export-root --output ./root-ca.pem --username admin --password secret
cargo run -p digitca -- export-intermediate --output ./intermediate-ca.pem --username admin --password secret
cargo run -p digitca -- audit-log --limit 20 --username admin --password secret
```

## REST API приклади

Swagger UI:
- `http://localhost:8080/docs`

Базовий виклик health:

```bash
curl -s http://localhost:8080/health
```

Відкликання сертифіката з reason:

```bash
curl -s -X POST "http://localhost:8080/api/v1/certificates/<SERIAL>/revoke" \
  -H "Authorization: Basic $(printf 'admin:secret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"reason":"keyCompromise"}'
```

Отримання CRL:

```bash
curl -s "http://localhost:8080/crl/root.crl" \
  -H "Authorization: Basic $(printf 'admin:secret' | base64)"

curl -s "http://localhost:8080/crl/intermediate.crl" \
  -H "Authorization: Basic $(printf 'admin:secret' | base64)"
```

OCSP health:

```bash
curl -s "http://localhost:8082/health"
```

## Структура

- `Cargo.toml` — кореневий маніфест пакета `digitca` та workspace-опис
- `src/lib.rs` — бібліотечний runner, CLI-команди й тестований command-flow
- `src/main.rs` — тонкий вхідний файл
- `crates/digitca-ocsp` — окремий OCSP responder сервіс для перевірки статусу сертифікатів
- `src/ca.rs` — криптографічна логіка CA
- `src/ldap_auth.rs` — LDAP authN/authZ та інтерфейс `Authorizer`
- `src/storage.rs` — MongoDB-репозиторій і `InMemoryStorage` для тестів
- `src/service.rs` — сервісний orchestration-шар з вбудованим audit
- `src/models.rs` — моделі даних (`CertificateRecord`, `AuditEvent`, ...)
- `src/config.rs` — env-конфіг
- `src/error.rs` — типи помилок
- `tests/cli.rs` — інтеграційні тести CLI-потоку без зовнішніх сервісів

## Тести

Проєкт містить:
- unit-тести генерації та використання сертифікатів
- перевірку шифрованого root-ключа
- інтеграційний тест повного CLI-потоку в пам'яті

```bash
cargo test -p digitca
cargo test --workspace
```

## Зауваження щодо безпеки

- Приватний ключ root CA більше не зберігається у відкритому PEM, якщо задано `ROOT_CA_KEY_PASSPHRASE`.
- Leaf-сертифікати за замовчуванням можуть випускатися через `intermediate CA`, що зменшує ризик прямого використання root CA.
- Для production рекомендується винести ключі у HSM/KMS або щонайменше використовувати секрет-менеджер для passphrase.
- Basic auth має працювати лише через HTTPS. Для production рекомендується `BASIC_AUTH_REQUIRE_HTTPS=true` і reverse proxy, який передає `X-Forwarded-Proto=https`.
- CORS не повинен бути permissive у production. Використовуйте явний whitelist через `CORS_ALLOWED_ORIGINS`.
- Корисні наступні кроки для production: аудит-лог, ротація ключів, OCSP endpoint, політики профілів сертифікатів.
