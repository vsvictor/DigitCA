import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const apiBase = String.fromEnvironment('API_BASE', defaultValue: 'https://digitca.digit.com');
const username = String.fromEnvironment('USERNAME', defaultValue: 'admin');
const password = String.fromEnvironment('PASSWORD', defaultValue: 'secret');

void main() {
  runApp(const ExampleApp());
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DigitCA Flutter Example',
      home: const ExamplePage(),
    );
  }
}

class ExamplePage extends StatefulWidget {
  const ExamplePage({super.key});

  @override
  State<ExamplePage> createState() => _ExamplePageState();
}

class _ExamplePageState extends State<ExamplePage> {
  String output = 'Press the button to call API';

  Future<void> runCalls() async {
    final auth = base64Encode(utf8.encode('$username:$password'));

    final health = await http.get(Uri.parse('$apiBase/health'));
    final docs = await http.get(Uri.parse('$apiBase/docs'));
    final certs = await http.get(
      Uri.parse('$apiBase/api/v1/certificates?include_revoked=true&page=1&per_page=5'),
      headers: {'Authorization': 'Basic $auth'},
    );

    setState(() {
      output = [
        '/health -> ${health.statusCode}',
        health.body,
        '/docs -> ${docs.statusCode}',
        '/api/v1/certificates -> ${certs.statusCode}',
        certs.body.length > 200 ? certs.body.substring(0, 200) : certs.body,
      ].join('\n\n');
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('DigitCA REST API Example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: SingleChildScrollView(child: Text(output)),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: runCalls,
        child: const Icon(Icons.play_arrow),
      ),
    );
  }
}

