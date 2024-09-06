// cf https://pub.dev/documentation/asn1lib/latest/asn1lib/ASN1Sequence-class.html
// cf https://github.com/pyauth/tsp-client
// cf https://chatgpt.com/c/94d7db76-cf74-4d96-8075-fdb2547605c3
// cf le bas de https://gist.github.com/hnvn/38ef37566471f1135773b5426fb73011

import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:path_provider/path_provider.dart';
import 'package:dio/dio.dart';

import 'package:flutter/material.dart';
import 'package:asn1lib/asn1lib.dart';

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

    String s = "test eliaz coucou\n\n\n";

    Digest digest = sha256.convert(s.codeUnits);

    // build Seq Algorithm
    ASN1Sequence seqAlgorithm = getSeqAlgorithm();

    // build messageImprint
    ASN1Sequence messageImprintSequence =
        getSeqMessageImprintSequence(seqAlgorithm, digest);

    // version 1 algorithm
    ASN1Integer version = ASN1Integer.fromInt(1);

    // build timeStampRequest
    ASN1Sequence timeStampReq = ASN1Sequence();
    timeStampReq.add(version);
    timeStampReq.add(messageImprintSequence);

    // send request to TSA Server

    Options options =
        Options(headers: {'Content-Type': 'application/timestamp-query'});

    final dio = Dio();
    // call digicert's timestamp server
    String tsaUrl = 'http://timestamp.digicert.com'; // URL du serveur TSA

    try {
      Response response = await dio.post(tsaUrl,
          data: timeStampReq.encodedBytes, options: options);
      print(response);
      _iStatusCode = response.statusCode;
    } on DioException catch (e) {
      if (e.response != null) {
        _iStatusCode = e.response!.statusCode;
      } else {
        _errorMessage = e.message;
        _errorMessage =
            "${_errorMessage}\n\nthis flutter app is unable to run on web flutter (because of missing digicert's CORS headers)\n,\n please choose another simulator, android or macos are perfect";
      }
    } on Exception catch (e) {
      _errorMessage = e.toString();
    }
    setState(() {});
  }

  // for future purpose
  _write(ASN1Sequence timeStampReq) async {
    try {
      Uint8List data = timeStampReq.encodedBytes;
      var hex2 =
          data.map((e) => "${e.toRadixString(16).padLeft(2, '0')} ").join();
      print(hex2);

      Directory root = await getTemporaryDirectory();
      File file = await File('${root.path}/file.tsq').create();
      print(file.path);
      file.writeAsBytesSync(data);
    } catch (e) {
      debugPrint(e.toString());
    }
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

ASN1Sequence getSeqMessageImprintSequence(
    ASN1Sequence seqAlgorithm, Digest digest) {
  //
  Uint8List uint8list = Uint8List.fromList(digest.bytes);

  ASN1Object hashedText = ASN1Object.fromBytes(uint8list);

  ASN1Sequence messageImprintSequence = ASN1Sequence();

  messageImprintSequence.add(seqAlgorithm);

  //
  // why must I add this ? -- BEGIN --
  //
  ASN1Object strange = ASN1Object.fromBytes(Uint8List.fromList([0x04, 0x20]));
  messageImprintSequence.add(strange);
  //
  // why must I add this ? -- END --
  //
  messageImprintSequence.add(hashedText);

  return messageImprintSequence;
}

void dumpSequence(Uint8List encodedBytes) {
  var p = ASN1Parser(encodedBytes);
  var s2 = p.nextObject();
  print(s2);
}

ASN1Sequence getSeqAlgorithm() {
  ASN1ObjectIdentifier sha256OidHS = ASN1ObjectIdentifier([
    2,
    16,
    840,
    1,
    101,
    3,
    4,
    2,
    1
  ]); // SHA-256 OID sous forme de liste d'entiers

  var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));

  ASN1Sequence seqAlgorithm = ASN1Sequence();
  seqAlgorithm.add(sha256OidHS);
  seqAlgorithm.add(paramsAsn1Obj);
  return seqAlgorithm;
}
