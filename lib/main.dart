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
import 'package:file_picker/file_picker.dart';
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
        // This is the theme of your application.
        //
        // TRY THIS: Try running your application with "flutter run". You'll see
        // the application has a purple toolbar. Then, without quitting the app,
        // try changing the seedColor in the colorScheme below to Colors.green
        // and then invoke "hot reload" (save your changes or press the "hot
        // reload" button in a Flutter-supported IDE, or press "r" if you used
        // the command line to start the app).
        //
        // Notice that the counter didn't reset back to zero; the application
        // state is not lost during the reload. To reset the state, use hot
        // restart instead.
        //
        // This works for code too, not just values: Most code changes can be
        // tested with just a hot reload.
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _timestamp() async {
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
    // Créer une requête d'horodatage en utilisant l'empreinte SHA-256
    String tsaUrl = 'http://timestamp.digicert.com'; // URL du serveur TSA

    Response response = await dio.post(tsaUrl,
        data: timeStampReq.encodedBytes, options: options);

    print(response);
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
      body: const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text(
              'push button for timestamp',
            ),
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

  // why must I add this ? -- BEGIN --
  ASN1Object strange = ASN1Object.fromBytes(Uint8List.fromList([0x04, 0x20]));
  messageImprintSequence.add(strange);
  // why must I add this ? -- END --
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
  var hexseq = seqAlgorithm.encodedBytes
      .map((e) => "${e.toRadixString(16).padLeft(2, '0')} ")
      .join();
  print(hexseq);
  return seqAlgorithm;
}
