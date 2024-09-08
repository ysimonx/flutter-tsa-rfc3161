import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';

import 'tsa_common.dart';

class TSAResponse extends TSACommon {
  late Response response;

  TSAResponse();

  TSAResponse.fromHTTPResponse({required this.response}) {
    ASN1Parser parser = ASN1Parser(response.data, relaxedParsing: true);
    asn1sequence = parser.nextObject() as ASN1Sequence;

    ASN1Sequence item1 = asn1sequence.elements[1] as ASN1Sequence;
    ASN1Object content = item1.elements[1];

    Uint8List econtent = content.encodedBytes.sublist(4);

    ASN1Parser parserEcontent = ASN1Parser(econtent, relaxedParsing: true);
    ASN1Object test = parserEcontent.nextObject() as ASN1Sequence;

    String result = explore(test, 0);
    print(result);
  }
}
