import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';

import 'tsa_hash_algo.dart';
import 'tsa_common.dart';
import 'tsa_response.dart';

class TSARequest extends TSACommon {
  int version = 1;
  int? nonce;
  bool? certReq;
  String? filepath;
  TSAHash? algorithm;

  TSARequest();

  Future<TSAResponse> run(
      {required String hostname, String? credentials}) async {
    // send request to TSA Server

    Map<String, dynamic> headers = {
      'Content-Type': 'application/timestamp-query'
    };

    if (credentials != null) {
      String basicAuth = 'Basic ${base64.encode(utf8.encode(credentials))}';
      headers.addAll({'authorization': basicAuth});
    }

    Options options =
        Options(headers: headers, responseType: ResponseType.bytes);

    final dio = Dio();

    // call digicert's timestamp server
    String tsaUrl = hostname; // URL du serveur TSA

    try {
      Response response = await dio.post(tsaUrl,
          data: asn1sequence.encodedBytes, options: options);

      TSAResponse tsr =
          TSAResponse(this, hostnameTimeStampProvider: 'hostname');
      tsr.response = response;
      tsr.parseFromHTTPResponse();
      return tsr;
    } on DioException catch (e) {
      if (e.response != null) {
        TSAResponse tsr =
            TSAResponse(this, hostnameTimeStampProvider: 'hostname');
        tsr.response = e.response!;
        return tsr;
      } else {
        rethrow;
      }
    } on Exception {
      rethrow;
    }
  }

  TSARequest.restoreFromUint8List(dynamic bytes) {
    Uint8List content = bytes;
    var parser = ASN1Parser(content);
    asn1sequence = parser.nextObject() as ASN1Sequence;
    nonce = _findNonce(asn1sequence);
    certReq = _findcertReq(asn1sequence);
  }

  TSARequest.fromFile(
      {required this.filepath,
      this.nonce,
      this.certReq,
      required this.algorithm}) {
    File file = File(filepath!);
    List<int> fileBytes = file.readAsBytesSync();
    //
    ASN1Sequence messageImprint =
        _getSeqMessageImprintSequence(message: fileBytes, algorithm: algorithm);

    _init(messageImprint: messageImprint, nonce: nonce, certReq: certReq);
  }

  TSARequest.fromString(
      {required String s, required this.algorithm, this.nonce, this.certReq}) {
    //
    ASN1Sequence messageImprint = _getSeqMessageImprintSequence(
        message: s.codeUnits, algorithm: algorithm);

    _init(messageImprint: messageImprint, nonce: nonce, certReq: certReq);
  }

  void _init(
      {required ASN1Sequence messageImprint, int? nonce, bool? certReq}) {
    ASN1Integer asn1version = ASN1Integer.fromInt(version);
    ASN1Sequence timeStampReq = ASN1Sequence();

    timeStampReq.add(asn1version);
    timeStampReq.add(messageImprint);

    // policyId
    // timeStampReq.add(ASN1Null());

    if (nonce != null) {
      ASN1Integer asn1nonce = ASN1Integer(BigInt.from(nonce));
      timeStampReq.add(asn1nonce);
      //  should be similar to 02 08 38 8e bc 2c d8 bf 32 41
      //                       02 08 61 d0 dd 7e 47 a9 16 0a
    }
    if (certReq != null) {
      ASN1Boolean asncertReq = ASN1Boolean(
          certReq); // Demande d'inclusion des certificats dans la réponse
      timeStampReq.add(asncertReq);
    }

    asn1sequence = timeStampReq;
  }

  static _getSeqMessageImprintSequence(
      {required List<int> message, required TSAHash? algorithm}) {
    //
    // seqAlgorithm

    ASN1Sequence seqAlgorithm;
    ASN1Object hashedText;
    switch (algorithm) {
      case TSAHash.sha256:
        seqAlgorithm = TSAHashAlgoSHA256.getASN1Sequence();
        hashedText = TSAHashAlgoSHA256.getASN1ObjectHashed(message: message);
        break;
      case TSAHash.sha512:
        seqAlgorithm = TSAHashAlgoSHA512.getASN1Sequence();
        hashedText = TSAHashAlgoSHA512.getASN1ObjectHashed(message: message);
        break;
      case TSAHash.sha1:
        seqAlgorithm = TSAHashAlgoSHA1.getASN1Sequence();
        hashedText = TSAHashAlgoSHA1.getASN1ObjectHashed(message: message);
        break;
      case TSAHash.sha384:
        seqAlgorithm = TSAHashAlgoSHA384.getASN1Sequence();
        hashedText = TSAHashAlgoSHA384.getASN1ObjectHashed(message: message);
        break;
      default:
        seqAlgorithm = TSAHashAlgoSHA256.getASN1Sequence();
        hashedText = TSAHashAlgoSHA256.getASN1ObjectHashed(message: message);
    }

    //
    ASN1Sequence messageImprintSequence = ASN1Sequence();
    messageImprintSequence.add(seqAlgorithm);
    messageImprintSequence.add(hashedText);
    return messageImprintSequence;
  }
}

bool? _findcertReq(ASN1Sequence asn1sequence) {
  bool? result;
  for (var i = 0; i < asn1sequence.elements.length; i++) {
    ASN1Object obj = asn1sequence.elements.elementAt(i);
    if (obj is ASN1Boolean) {
      // it is optional
      result = obj.booleanValue;
    }
  }
  return result;
}

int? _findNonce(ASN1Sequence asn1sequence) {
  int? result;

  for (var i = 0; i < asn1sequence.elements.length; i++) {
    ASN1Object obj = asn1sequence.elements.elementAt(i);
    if (obj is ASN1Integer) {
      // it is optional
      if (obj.intValue > 2) {
        // it may be the "version" (=1)
        result = obj.intValue;
      }
    }
  }
  return result;
}
