import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';

import 'tsa_common.dart';

class TSAResponse extends TSACommon {
  late Response response;

  TSAResponse();

  TSAResponse.fromHTTPResponse({required this.response}) {
    ASN1Parser parser = ASN1Parser(response.data, relaxedParsing: true);
    asn1sequence = parser.nextObject() as ASN1Sequence;
  }
}
