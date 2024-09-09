import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'tsa_common.dart';

class TSAResponse extends TSACommon {
  late Response response;

  late ASN1Sequence content;
  late ASN1Sequence asn1sequenceproto;

  TSAResponse();

  TSAResponse.fromHTTPResponse({required this.response}) {
    ASN1Parser parser = ASN1Parser(response.data, relaxedParsing: true);
    asn1sequence = parser.nextObject() as ASN1Sequence;

    // Poc fix
    asn1sequenceproto = asn1sequence;
    asn1sequenceproto = fix(asn1sequenceproto) as ASN1Sequence;
    String result = explore(asn1sequenceproto, 0);
    if (kDebugMode) {
      print("\n$result");
    }

    // parse niv 1
    /*
    asn1sequence.elements
    status          [0] = ASN1Sequence (Seq[ASN1Integer(0) ])

                    PKIStatusInfo ::= SEQUENCE {
                    status        PKIStatus,
                    statusString  PKIFreeText     OPTIONAL,
                    failInfo      PKIFailureInfo  OPTIONAL  }

    timeStampToken  [1] = ASN1Sequence (Seq[ObjectIdentifier(1.2.840.113549.1.7.2) ASN1Object(tag=a0 valueBteLength=5988) startpos=4 bytes=[0xa0, 0x82, 0x17, 0x64, 0x3…)

                    OPTIONAL

                    TimeStampToken ::= ContentInfo
                      -- contentType is id-signedData ([CMS])
                      -- content is SignedData ([CMS])


    */
  }
}
