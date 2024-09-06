// ignore_for_file: unnecessary_getters_setters, file_names

import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'tsahashalgo.dart';

class TSARequest {
  String _filepath = "";
  String _hashalgo = "";
  late Uint8List _encodedBytes;

  TSARequest();

  String get filepath {
    return _filepath;
  }

  set filepath(String filepath) {
    _filepath = filepath;
  }

  String get hashalgo {
    return _hashalgo;
  }

  set hashalgo(String hashalgo) {
    _hashalgo = hashalgo;
  }

  Uint8List get encodedBytes {
    return _encodedBytes;
  }

  set encodedBytes(Uint8List encodedBytes) {
    _encodedBytes = encodedBytes;
  }

  Future<Response> run({required String hostname}) async {
    // send request to TSA Server

    Options options =
        Options(headers: {'Content-Type': 'application/timestamp-query'});

    final dio = Dio();

    // call digicert's timestamp server
    String tsaUrl = hostname; // URL du serveur TSA

    try {
      Response response =
          await dio.post(tsaUrl, data: encodedBytes, options: options);

      return response;
    } on DioException catch (e) {
      if (e.response != null) {
        return e.response!;
      } else {
        rethrow;
      }
    } on Exception {
      rethrow;
    }
  }

  TSARequest.fromFile(
      {required String filepath,
      required int algorithm,
      int? nonce,
      bool? certReq}) {
    File file = File(filepath);
    List<int> fileBytes = file.readAsBytesSync();
    //
    ASN1Sequence messageImprint =
        _getSeqMessageImprintSequence(message: fileBytes, algorithm: algorithm);

    _init(messageImprint: messageImprint, nonce: nonce, certReq: certReq);
  }

  TSARequest.fromString(
      {required String s, required int algorithm, int? nonce, bool? certReq}) {
    //
    ASN1Sequence messageImprint = _getSeqMessageImprintSequence(
        message: s.codeUnits, algorithm: algorithm);

    _init(messageImprint: messageImprint, nonce: nonce, certReq: certReq);
  }

  void _init(
      {required ASN1Sequence messageImprint, int? nonce, bool? certReq}) {
    ASN1Integer version = ASN1Integer.fromInt(1);
    ASN1Sequence timeStampReq = ASN1Sequence();

    timeStampReq.add(version);
    timeStampReq.add(messageImprint);

    if (nonce != null) {
      ASN1Integer asn1nonce = ASN1Integer(BigInt.from(nonce));
      timeStampReq.add(asn1nonce);
    }
    if (certReq != null) {
      ASN1Boolean asncertReq = ASN1Boolean(
          certReq); // Demande d'inclusion des certificats dans la réponse

      timeStampReq.add(asncertReq);
    }

    encodedBytes = timeStampReq.encodedBytes;
  }

  static _getSeqMessageImprintSequence(
      {required List<int> message, required int algorithm}) {
    //
    // seqAlgorithm

    ASN1Sequence seqAlgorithm;
    ASN1Object hashedText;
    switch (algorithm) {
      case TSAHashAlgo.sha256:
        seqAlgorithm = TSAHashAlgoSHA256.getASN1Sequence();
        hashedText = TSAHashAlgoSHA256.getASN1ObjectHashed(message: message);
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

  // for future purpose
  // ignore: unused_element
  static _write(ASN1Sequence timeStampReq) async {
    try {
      Uint8List data = timeStampReq.encodedBytes;
      var hex2 =
          data.map((e) => "${e.toRadixString(16).padLeft(2, '0')} ").join();
      debugPrint(hex2);

      Directory root = await getTemporaryDirectory();
      File file = await File('${root.path}/file.tsq').create();
      debugPrint(file.path);
      file.writeAsBytesSync(data);
    } catch (e) {
      debugPrint(e.toString());
    }
  }
}
