# OCSP Multi-language Examples

This directory contains standalone client examples for the `digitca-ocsp` service.

## Layout

- `bash/` - shell script example
- `rust/` - Rust CLI example
- `kotlin/` - Kotlin JVM example
- `flutter/` - Flutter/Dart CLI-style example
- `nodejs/` - Node.js example

## What each example does

1. Calls `GET /health`
2. Sends an OCSP DER request to `POST /ocsp`
3. Saves DER response to a local file

## Environment variables

All examples use the same variables:

- `OCSP_BASE` (default: `http://localhost:8082`)
- `OCSP_REQUEST_DER` (default: `./request.der`)
- `OCSP_RESPONSE_DER` (default: `./response.der`)

## Generate `request.der` with OpenSSL

Use a real issued certificate and its issuer certificate.

```bash
openssl ocsp \
  -issuer ./issuer.pem \
  -cert ./leaf.pem \
  -reqout ./request.der
```

## Quick run

### Bash

```bash
cd /Users/victor/DigitCA
chmod +x examples/ocsp_multilang/bash/ocsp_example.sh
OCSP_REQUEST_DER=./request.der examples/ocsp_multilang/bash/ocsp_example.sh
```

### Rust

```bash
cd /Users/victor/DigitCA/examples/ocsp_multilang/rust
cargo run -- \
  --ocsp-base http://localhost:8082 \
  --request-der ./request.der \
  --response-der ./response.der
```

### Kotlin

```bash
cd /Users/victor/DigitCA/examples/ocsp_multilang/kotlin
gradle -q run --args="--ocsp-base http://localhost:8082 --request-der ./request.der --response-der ./response.der"
```

### Flutter/Dart

```bash
cd /Users/victor/DigitCA/examples/ocsp_multilang/flutter
dart pub get
dart run bin/main.dart --ocsp-base http://localhost:8082 --request-der ./request.der --response-der ./response.der
```

### Node.js

```bash
cd /Users/victor/DigitCA/examples/ocsp_multilang/nodejs
npm install
node index.mjs --ocsp-base http://localhost:8082 --request-der ./request.der --response-der ./response.der
```

