# Kotlin REST API Example

## Run

```bash
cd /Users/victor/DigitCA/examples/multilang/kotlin
API_BASE=https://digitca.digit.com USERNAME=admin PASSWORD=secret ./gradlew run
```

If you do not have Gradle wrapper, use installed Gradle:

```bash
cd /Users/victor/DigitCA/examples/multilang/kotlin
API_BASE=https://digitca.digit.com USERNAME=admin PASSWORD=secret gradle run
```

## What it does

- Calls `GET /health`
- Calls `GET /docs`
- Calls `GET /api/v1/certificates` with Basic auth

