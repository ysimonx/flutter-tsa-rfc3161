import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'tsa_common.dart';
import 'tsa_oid.dart';

class TSAResponse extends TSACommon {
  late Response response;

  ASN1Sequence? asn1SequenceTSTInfo;

  TSAResponse();

  TSAResponse.fromHTTPResponse({required this.response}) {
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

  Map<String, ASN1Sequence> buildMapOidSeq(
      ASN1Object obj, Map<String, ASN1Sequence> mapOidSeq) {
    ASN1ObjectIdentifier? asn1oid;
    ASN1Sequence? asn1seq;

    Map<String, ASN1Sequence> compl = {};

    if (obj is ASN1Sequence) {
      for (var i = 0; i < obj.elements.length; i++) {
        ASN1Object item = obj.elements.elementAt(i);
        if (item is ASN1ObjectIdentifier) {
          asn1oid = item;
        }
        if (item is ASN1Sequence) {
          asn1seq = item;
          compl = buildMapOidSeq(asn1seq, mapOidSeq);
        }
      }
      if (asn1oid != null && asn1seq != null) {
        if (asn1oid.identifier != null) {
          mapOidSeq[asn1oid.identifier!] = asn1seq;
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
}
