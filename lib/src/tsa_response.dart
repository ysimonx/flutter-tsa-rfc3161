import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:share_plus/share_plus.dart';
import 'package:tsa_rfc3161/src/tsa_request.dart';

import 'tsa_common.dart';
import 'tsa_oid.dart';

class TSAResponse extends TSACommon {
  late Response response;

  final TSARequest tsq;
  final String hostname;
  ASN1Sequence? asn1SequenceTSTInfo;

  TSAResponse(this.tsq, {required this.hostname});

  Future<TSAResponse?> run() async {
    try {
      response = await tsq.run(hostname: hostname);
      if (response.statusCode == 200) {
        _parseFromHTTPResponse();
      }
    } on Exception {
      rethrow;
    }
    return this;
  }

  _parseFromHTTPResponse() {
    ASN1Parser parser = ASN1Parser(response.data, relaxedParsing: true);
    asn1sequence = parser.nextObject() as ASN1Sequence;

    // Poc fix
    ASN1Sequence asn1sequenceproto = asn1sequence;
    asn1sequenceproto = fix(asn1sequenceproto) as ASN1Sequence;
    asn1sequence = asn1sequenceproto;
    String result = TSACommon.explore(asn1sequence, 0);
    if (kDebugMode) {
      print("\n$result");
    }

    Map<String, ASN1Sequence> mapOidSeq = {};

    mapOidSeq = buildMapOidSeq(asn1sequence, mapOidSeq);

    if (mapOidSeq.containsKey(TSAOid.nameToOID("id-ct-TSTInfo"))) {
      asn1SequenceTSTInfo = mapOidSeq["1.2.840.113549.1.9.16.1.4"]!;
    } else {
      asn1SequenceTSTInfo = null;
    }
  }

  // trying to build a map OID => sequence that contains the OID
  Map<String, ASN1Sequence> buildMapOidSeq(
      ASN1Object obj, Map<String, ASN1Sequence> mapOidSeq) {
    ASN1ObjectIdentifier? asn1oid;

    Map<String, ASN1Sequence> compl = {};

    if (obj is ASN1Sequence) {
      for (var i = 0; i < obj.elements.length; i++) {
        ASN1Object item = obj.elements.elementAt(i);
        if (item is ASN1ObjectIdentifier) {
          asn1oid = item;
        }
        if (item is ASN1Sequence) {
          compl = buildMapOidSeq(item, mapOidSeq);
        }
      }
      if (asn1oid != null) {
        if (asn1oid.identifier != null) {
          mapOidSeq[asn1oid.identifier!] = obj;
        }
      }
    }
    if (obj is ASN1Set) {
      for (var i = 0; i < obj.elements.length; i++) {
        ASN1Object item = obj.elements.elementAt(i);
        compl = buildMapOidSeq(item, mapOidSeq);
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

  Future<void> share() async {
    Uint8List data = asn1sequence.encodedBytes;

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
}
