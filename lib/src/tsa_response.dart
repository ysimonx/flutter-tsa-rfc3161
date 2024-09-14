import 'dart:io';

// import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/asn1.dart';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:tsa_rfc3161/src/tsa_request.dart';

import 'tsa_common.dart';
import 'tsa_oid.dart';

class TSAResponse extends TSACommon {
  late Response response;
  final TSARequest tsq;
  final String hostnameTSAProvider;
  ASN1Sequence? asn1SequenceTSTInfo;

  String? serialNumber;
  int? nonce;
  DateTime? timestamp;

  TSAResponse(this.tsq, {required this.hostnameTSAProvider});

  Future<TSAResponse?> run() async {
    try {
      response = await tsq.run(hostname: hostnameTSAProvider);
      if (response.statusCode == 200) {
        _parseFromHTTPResponse();
      }
    } on Exception {
      rethrow;
    }
    return this;
  }

  _parseFromHTTPResponse() {
    ASN1Parser parser = ASN1Parser(response.data);
    asn1sequence = parser.nextObject() as ASN1Sequence;

    // Poc fix
    ASN1Sequence asn1sequenceproto = asn1sequence;
    asn1sequenceproto = _fix(asn1sequenceproto) as ASN1Sequence;
    asn1sequence = asn1sequenceproto;
    String result = TSACommon.dump(asn1sequence, 0);
    if (kDebugMode) {
      print("\n$result");
    }

    Map<String, ASN1Sequence> mapOidSeq = {};

    mapOidSeq = _buildMapOidSeq(asn1sequence, mapOidSeq);

    if (mapOidSeq.containsKey(TSAOid.nameToOID("id-ct-TSTInfo"))) {
      asn1SequenceTSTInfo = mapOidSeq["1.2.840.113549.1.9.16.1.4"]!;
    } else {
      asn1SequenceTSTInfo = null;
    }
  }

  // trying to build a map OID => sequence that contains the OID
  Map<String, ASN1Sequence> _buildMapOidSeq(
      ASN1Object obj, Map<String, ASN1Sequence> mapOidSeq) {
    ASN1ObjectIdentifier? asn1oid;

    Map<String, ASN1Sequence> compl = {};

    if (obj is ASN1Sequence) {
      for (var i = 0; i < obj.elements!.length; i++) {
        ASN1Object item = obj.elements!.elementAt(i);
        if (item is ASN1ObjectIdentifier) {
          asn1oid = item;
        }
        if (item is ASN1Sequence) {
          compl = _buildMapOidSeq(item, mapOidSeq);
        }
      }
      if (asn1oid != null) {
        if (asn1oid.objectIdentifierAsString != null) {
          mapOidSeq[asn1oid.objectIdentifierAsString!] = obj;
        }
      }
    }
    if (obj is ASN1Set) {
      for (var i = 0; i < obj.elements!.length; i++) {
        ASN1Object item = obj.elements!.elementAt(i);
        compl = _buildMapOidSeq(item, mapOidSeq);
      }
    }

    if (compl.keys.isNotEmpty) {
      for (var i = 0; i < compl.keys.length; i++) {
        String k = compl.keys.elementAt(i);
        mapOidSeq[k] = compl[k] as ASN1Sequence;
      }
    }

    return mapOidSeq;
  }

  @override
  void write(String filename) async {
    try {
      Uint8List data = response.data;

      Directory root = await getTemporaryDirectory();
      File file = await File('${root.path}/$filename').create();
      debugPrint(file.path);
      file.writeAsBytesSync(data);
    } catch (e) {
      debugPrint(e.toString());
    }
  }

  Future<void> share() async {
    Uint8List? data = asn1sequence.encodedBytes;

    if (data == null) {
      return;
    }

    String filename = tsq.filepath!.split('/').last;
    String filenameTSR = "${tsq.filepath!.split('/').last}.tsr";
    final result = await Share.shareXFiles([
      XFile(tsq.filepath!),
      XFile.fromData(data, mimeType: 'application/timestamp-reply')
    ], fileNameOverrides: [
      filename,
      filenameTSR
    ]);
    if (result.status == ShareResultStatus.success) {
      if (kDebugMode) {
        print('Thank you for sharing the picture!');
      }
    }
  }

  ASN1Object _fixASN1Object(ASN1Object obj) {
    if (obj is ASN1OctetString) {}

    if (obj.tag == 160 || obj.tag == 163) {
      int offset = 0;

      // je recherche le prochain objet
      while (obj.encodedBytes![offset] != 48) {
        // c'est pourri, mais ca peut marcher
        offset++;
        if (offset == obj.encodedBytes!.length) {
          return obj;
        }
      }

      Uint8List content = obj.encodedBytes!.sublist(offset);

      List<ASN1Object> elements = [];

      ASN1Parser parser = ASN1Parser(content);

      while (parser.hasNext()) {
        ASN1Object result = parser.nextObject();
        elements.add(result);
      }

      if (elements.length == 1) {
        return elements[0];
      }
      ASN1Sequence newseq = ASN1Sequence();
      newseq.elements = elements;
      return newseq;
    }

    return obj;
  }

  /*

  sometimes, tag can be 160 or 163 

  "160, 130, 23, 100 .... "

  "160, 129, 146, 4, 129, 143 ..."

  it is a "context specific" tag, not parsed by asnlib1,
  but it is also a "structured" data ... so, let's try
  to constructed a SEQ with the content bytes, a quick and dirty
  solution ;-)

  */

  ASN1Object _fix(ASN1Object obj) {
    ASN1Object result = obj;
    if (result is ASN1Sequence) {
      for (var i = 0; i < result.elements!.length; i++) {
        ASN1Object element = result.elements!.elementAt(i);

        element = _fixASN1Object(element);

        result.elements![i] = _fix(element);
      }
    }
    if (result is ASN1Set) {
      for (var i = 0; i < result.elements!.length; i++) {
        ASN1Object element = result.elements!.elementAt(i);

        element = _fixASN1Object(element);

        result.elements!.remove(element);
        result.elements!.add(_fix(element));
      }
    }
    return result;
  }
}
