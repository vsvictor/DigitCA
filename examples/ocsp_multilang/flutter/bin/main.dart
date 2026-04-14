/// OCSP client example for digitca-ocsp — Flutter/Dart
///
/// Usage:
///   dart pub get
///   dart run bin/main.dart --ocsp-base http://localhost:8082 \
///                          --request-der ./request.der \
///                          --response-der ./response.der
///
/// Environment variable overrides:
///   OCSP_BASE, OCSP_REQUEST_DER, OCSP_RESPONSE_DER
import 'dart:io';

import 'package:http/http.dart' as http;

String argValue(List<String> args, String name, String fallback) {
  final idx = args.indexOf(name);
  if (idx == -1 || idx + 1 >= args.length) return fallback;
  return args[idx + 1];
}

Future<void> main(List<String> args) async {
  final ocspBase = argValue(
      args, '--ocsp-base', Platform.environment['OCSP_BASE'] ?? 'http://localhost:8082');
  final requestDer = argValue(
      args, '--request-der', Platform.environment['OCSP_REQUEST_DER'] ?? './request.der');
  final responseDer = argValue(
      args, '--response-der', Platform.environment['OCSP_RESPONSE_DER'] ?? './response.der');

  // 1) Health check
  stdout.writeln('[flutter] GET $ocspBase/health');
  final health = await http.get(Uri.parse('$ocspBase/health'));
  if (health.statusCode < 200 || health.statusCode >= 300) {
    stderr.writeln('[flutter] health failed: ${health.statusCode}');
    exit(1);
  }
  stdout.writeln(health.body);

  // 2) Read request DER
  final requestBytes = await File(requestDer).readAsBytes();
  stdout.writeln('[flutter] POST $ocspBase/ocsp  (${requestBytes.length} bytes)');

  // 3) POST OCSP request
  final ocsp = await http.post(
    Uri.parse('$ocspBase/ocsp'),
    headers: {'Content-Type': 'application/ocsp-request'},
    body: requestBytes,
  );
  if (ocsp.statusCode < 200 || ocsp.statusCode >= 300) {
    stderr.writeln('[flutter] ocsp failed: ${ocsp.statusCode}');
    exit(1);
  }

  // 4) Save DER response
  await File(responseDer).writeAsBytes(ocsp.bodyBytes);
  stdout.writeln(
      '[flutter] OCSP response saved: $responseDer  (${ocsp.bodyBytes.length} bytes)');
}

