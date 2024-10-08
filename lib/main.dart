import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:tsa_rfc3161/tsa_rfc3161.dart';

/// main program
void main() {
  runApp(const MyApp());
}

/// MyApp Widget
class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TSA Rfc3161s Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'TSA Rfc3161'),
    );
  }
}

/// HomePage
class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  TSARequest? tsq;
  TSAResponse? tsr;
  String? _errorMessage = "";
  String? _dumpTSA = "";
  String? _dumpTST = "";

  late StreamSubscription _intentDataStreamSubscription;

  @override
  void dispose() {
    _intentDataStreamSubscription.cancel();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Padding(
        padding: const EdgeInsets.all(8.0),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.max,
            mainAxisAlignment: MainAxisAlignment.start,
            children: <Widget>[
              const Padding(
                padding: EdgeInsets.only(left: 16.0, right: 16.0),
                child: Row(mainAxisSize: MainAxisSize.max, children: [
                  Text(
                    "press button, choose a file and wait for digicert timestamp",
                  )
                ]),
              ),
              if (tsr != null)
                Padding(
                    padding: const EdgeInsets.only(left: 16.0, right: 16.0),
                    child: Row(mainAxisSize: MainAxisSize.max, children: [
                      Text(
                          "status code from tsa server = ${tsr!.response.statusCode}")
                    ])),
              if (_errorMessage != "")
                Padding(
                    padding: const EdgeInsets.only(left: 16.0, right: 16.0),
                    child: Row(mainAxisSize: MainAxisSize.max, children: [
                      Text(_errorMessage!),
                    ])),
              if (tsr != null)
                Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    mainAxisSize: MainAxisSize.max,
                    children: [
                      IconButton(
                          onPressed: _shareOriginalFileAndItsTimestampResponse,
                          icon: const Icon(Icons.share)),
                      const Text(
                          "Share 2 files : the original one and the timestamp response")
                    ]),
              const SizedBox(height: 50),
              if (_dumpTST != "")
                Container(
                    color: Colors.lightGreen,
                    child: Column(
                      children: [
                        const SizedBox(height: 10),
                        const Text("TimeStampToken Sequence"),
                        const SizedBox(height: 10),
                        SelectableText(_dumpTST!),
                      ],
                    )),
              const SizedBox(height: 50),
              if (_dumpTSA != "")
                Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    children: [
                      const SizedBox(height: 10),
                      const Text("Full ASN.1 Sequence"),
                      const SizedBox(height: 10),
                      SelectableText(_dumpTSA!),
                    ],
                  ),
                )
            ],
          ),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _pickFileAndTimestamp,
        child: const Icon(Icons.add),
      ),
    );
  }

  void _shareOriginalFileAndItsTimestampResponse() async {
    if (tsr != null) {
      await tsr!.share();
    }
  }

  void _pickFileAndTimestamp() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();
    if (result == null) {
      return;
    }
    _timestampFile(result.files.single.path!);
  }

  Future<void> _timestampFile(filepath) async {
    setState(() {
      tsr = null;
      _dumpTSA = "";
      _dumpTST = "";
      _errorMessage = "";
    });

    int nonceValue =
        DateTime.now().millisecondsSinceEpoch; // Utiliser un entier unique

    try {
      tsq = TSARequest.fromFile(
          filepath: filepath,
          algorithm: TSAHash.sha256,
          nonce: nonceValue,
          certReq: true);

      tsq!.write("file.digicert.tsq");

      Map<String, dynamic> json = tsq!.toJSON();
      TSARequest tsq2 = TSARequest.fromJSON(json);
      TSAResponse tsr =
          await tsq2.run(hostname: 'http://timestamp.digicert.com');

      // if (tsr != null) {
      tsr.write("file.digicert.tsr");
      _errorMessage = "ok";

      // ASN1Sequence tsr.asn1sequence contains the parsed response
      // we can "dump"
      _dumpTSA = tsr.explore(tsr.asn1sequence, 0);

      if (tsr.asn1SequenceTSTInfo != null) {
        _dumpTST = tsr.explore(tsr.asn1SequenceTSTInfo!, 0);
      }
      setState(() {});
      //} else {
      //  _errorMessage = "error";
      //}
    } on Exception catch (e) {
      _errorMessage = "exception : ${e.toString()}";
    }
    setState(() {});
  }
}
