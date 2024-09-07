// cf https://pub.dev/documentation/asn1lib/latest/asn1lib/ASN1Sequence-class.html
// cf https://github.com/pyauth/tsp-client
// cf https://chatgpt.com/c/94d7db76-cf74-4d96-8075-fdb2547605c3
// cf le bas de https://gist.github.com/hnvn/38ef37566471f1135773b5426fb73011

import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:dio/dio.dart';
import 'package:flutter/material.dart';

import 'package:tsa_rfc3161/tsa_rfc3161.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int? _iStatusCode = 0;
  String? _errorMessage = "";

  void _timestamp() async {
    setState(() {
      _iStatusCode = 0;
      _errorMessage = "";
    });

    FilePickerResult? result = await FilePicker.platform.pickFiles();
    int nonceValue =
        DateTime.now().millisecondsSinceEpoch; // Utiliser un entier unique

    if (result == null) {
      return;
    }
    File file = File(result.files.single.path!);

    try {
      TSARequest tsq = TSARequest.fromFile(
          filepath: file.path,
          algorithm: TSAHashAlgo.sha256,
          nonce: nonceValue,
          certReq: true);

      // tsq.write("test.tsq");

      Response response =
          await tsq.run(hostname: "http://timestamp.digicert.com");

      /* // for Certigna server
      Response response = await tsq.run(
          hostname: "https://timestamp.dhimyotis.com/api/v1/",
          credentials: "$user:$password");
      */

      _iStatusCode = response.statusCode;
      if (_iStatusCode == 200) {
        _errorMessage = "good";
      } else {
        _errorMessage = "error";
      }
    } on Exception catch (e) {
      _iStatusCode = 0;
      _errorMessage = "exception : ${e.toString()}";
    }
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'push button for timestamp',
            ),
            if (_iStatusCode != 0)
              Text("status code from tsa server = $_iStatusCode"),
            if (_errorMessage != "") Text(_errorMessage!)
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _timestamp,
        tooltip: 'Timestamp',
        child: const Icon(Icons.add),
      ),
    );
  }
}
