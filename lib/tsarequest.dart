// ignore_for_file: unnecessary_getters_setters

import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

class TSARequest {
  String _filepath = "";
  String _hashalgo = "";
  late Uint8List _encodedBytes;

  static List<int> sha256oid = [2, 16, 840, 1, 101, 3, 4, 2, 1];
  static List<int> sha256lng = [0x04, 0x20];

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

  static TSARequest fromFile({required String filepath}) {
    TSARequest tsq = TSARequest();
    tsq.filepath = filepath;
    tsq.hashalgo = "sha256";

    File file = File(tsq.filepath);
    List<int> fileBytes = file.readAsBytesSync();
    Digest digest = sha256.convert(fileBytes);

    //
    ASN1Sequence messageImprint = _getSeqMessageImprintSequence(digest);
    ASN1Integer version = ASN1Integer.fromInt(1);

    ASN1Sequence timeStampReq = ASN1Sequence();
    timeStampReq.add(version);
    timeStampReq.add(messageImprint);

    tsq.encodedBytes = timeStampReq.encodedBytes;

    return tsq;
  }

  static _getSeqAlgorithm() {
    //
    //

    ASN1ObjectIdentifier sha256OidHS = ASN1ObjectIdentifier(
        sha256oid); // SHA-256 OID sous forme de liste d'entiers

    var paramsAns1Null = ASN1Null();

    ASN1Sequence seqAlgorithm = ASN1Sequence();
    seqAlgorithm.add(sha256OidHS);
    seqAlgorithm.add(paramsAns1Null);
    return seqAlgorithm;
  }

  static _getSeqMessageImprintSequence(Digest digest) {
    //
    // seqAlgorithm
    ASN1Sequence seqAlgorithm = _getSeqAlgorithm();

    //
    // hashText (sha256lng + digest)
    List<int> intList = digest.bytes.toList();
    for (var i = 0; i < sha256lng.length; i++) {
      intList.insert(i, sha256lng[i]);
    }
    Uint8List uint8list = Uint8List.fromList(intList);
    ASN1Object hashedText = ASN1OctetString.fromBytes(uint8list);

    //
    ASN1Sequence messageImprintSequence = ASN1Sequence();
    messageImprintSequence.add(seqAlgorithm);
    messageImprintSequence.add(hashedText);
    return messageImprintSequence;
  }

  // for future purpose
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
}

void dumpSequence(Uint8List encodedBytes) {
  var p = ASN1Parser(encodedBytes);
  var s2 = p.nextObject();
  print(s2);
}
