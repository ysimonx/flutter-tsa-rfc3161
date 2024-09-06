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

  void _incrementCounter() async {
    await _pickFile();
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      _counter++;
    });
  }

  Future<void> _pickFile() async {
    // Sélectionner un fichier à horodater
    FilePickerResult? result = await FilePicker.platform.pickFiles();

    if (result != null) {
      File file = File(result.files.single.path!);

      await _timestampFile(file);
    }
  }

  Future<void> _timestampFile(File file) async {
    // Lire le contenu du fichier
    Uint8List fileBytes = await file.readAsBytes();

    // Générer l'empreinte SHA-256 du fichier
    Digest digest = sha256.convert(fileBytes);

    // Créer une requête d'horodatage en utilisant l'empreinte SHA-256
    String tsaUrl = 'http://timestamp.digicert.com'; // URL du serveur TSA

    // construction de l'algorithme de hachage
    ASN1Sequence seqAlgorithm = getSeqAlgorithm();

    // construction du messageImprint
    ASN1Sequence messageImprintSequence =
        getSeqMessageImprintSequence(seqAlgorithm, digest);

    // version 1 de l'algorithm
    ASN1Integer version = ASN1Integer.fromInt(1);

    // construction de la requete
    ASN1Sequence timeStampReq = ASN1Sequence();
    timeStampReq.add(version);
    timeStampReq.add(messageImprintSequence);

    // marche bien sans ca aussi
    //timeStampReq
    //    .add(ASN1Object.fromBytes(Uint8List.fromList([0x01, 0x01, 0xff])));

    // ASN1ObjectIdentifier reqPolicy = ASN1ObjectIdentifier(
    //    [1, 3, 6, 1, 4, 1, 4146, 1]); // Exemple d'OID de politique
    // int nonceValue =
    //    DateTime.now().millisecondsSinceEpoch; // Utiliser un entier unique
    // ASN1Integer nonce = ASN1Integer(BigInt.from(nonceValue));
    // ASN1Boolean certReq = ASN1Boolean(
    //    true); // Demande d'inclusion des certificats dans la réponse
    // timeStampReq.add(reqPolicy);
    // timeStampReq.add(nonce);
    // timeStampReq.add(certReq);

    // Créer la requête d'horodatage
    await _write(timeStampReq);

    // Envoyer la requête au serveur TSA

    Options options =
        Options(headers: {'Content-Type': 'application/timestamp-query'});

    final dio = Dio();

    Response response = await dio.post(tsaUrl,
        data: timeStampReq.encodedBytes, options: options);

    print(response);
  }

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
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // TRY THIS: Try changing the color here to a specific color (to
        // Colors.amber, perhaps?) and trigger a hot reload to see the AppBar
        // change color while the other colors stay the same.
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          //
          // TRY THIS: Invoke "debug painting" (choose the "Toggle Debug Paint"
          // action in the IDE, or press "p" in the console), to see the
          // wireframe for each widget.
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}

ASN1Sequence getSeqMessageImprintSequence(
    ASN1Sequence seqAlgorithm, Digest digest) {
  Uint8List uint8list = Uint8List.fromList(digest.bytes);

  print(digest.toString());

  ASN1Object strange = ASN1Object.fromBytes(Uint8List.fromList([0x04, 0x20]));
  ASN1Object x = ASN1Object.fromBytes(uint8list);

  ASN1Sequence messageImprintSequence = ASN1Sequence();

  messageImprintSequence.add(seqAlgorithm);
  messageImprintSequence.add(strange);
  messageImprintSequence.add(x);

  dumpSequence(messageImprintSequence.encodedBytes);

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
