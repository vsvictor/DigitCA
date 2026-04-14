# Flutter REST API Example

## Run

```bash
cd /Users/victor/DigitCA/examples/multilang/flutter
flutter pub get
flutter run \
  --dart-define=API_BASE=https://digitca.digit.com \
  --dart-define=USERNAME=admin \
  --dart-define=PASSWORD=secret
```

## What it does

Tap the floating action button to run calls:

- `GET /health`
- `GET /docs`
- `GET /api/v1/certificates` with Basic auth

