import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';

import 'package:path_provider/path_provider.dart';
// import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/asn1.dart';

import 'tsa_oid.dart';

class TSACommon {
  late ASN1Sequence asn1sequence;

  TSACommon();

  void dumpASN1SequenceHexa() {
    Uint8List? data = asn1sequence.valueBytes;
    if (data != null) {
      var hex2 =
          data.map((e) => "${e.toRadixString(16).padLeft(2, '0')} ").join();
      debugPrint(hex2);
    }
  }

  static String formatTag(ASN1Object obj) {
    if (obj is ASN1Sequence) {
      return "ASN1Sequence";
    }

    if (obj is ASN1Set) {
      return "ASN1Set";
    }

    if (obj is ASN1Integer) {
      return "ASN1Integer : ${obj.integer}";
    }

    if (obj is ASN1ObjectIdentifier) {
      String label = TSAOid.nameFromOID(obj.objectIdentifierAsString);
      return "ASN1ObjectIdentifier : ${obj.objectIdentifierAsString} - $label";
    }

    if (obj is ASN1PrintableString) {
      return "ASN1PrintableString : ${obj.stringValue}";
    }

    if (obj is ASN1OctetString) {
      obj.octets;

      String hexa = "'${obj.dump()}'";
      if (hexa.length > 80) {
        hexa = "${hexa.substring(0, 50)} ...";
      }
      return "ASN1OctetString  : length ${obj.totalEncodedByteLength} $hexa";
    }
    if (obj is ASN1Null) {
      return "ASN1Null";
    }

    if (obj is ASN1GeneralizedTime) {
      return "ASN1GeneralizedTime : ${obj.dateTimeValue}";
    }

    if (obj is ASN1UtcTime) {
      return "ASN1UtcTime : ${obj.time}";
    }

    if (obj is ASN1BitString) {
      return "ASN1BitString : ${obj.stringValues}";
    }

    if (obj is ASN1Boolean) {
      return "ASN1Boolean : ${obj.boolValue}";
    }

    return "ASN1Object : length ${obj.totalEncodedByteLength} ${obj.dump()}";
  }

  static String ident(n) => List.filled(n + 1, '    ').join();

  static String dump(ASN1Object obj, int? level) {
    level ??= 0;

    String s = "${ident(level)}${formatTag(obj)}\n";
    if (obj is ASN1Sequence) {
      for (var i = 0; i < obj.elements!.length; i++) {
        s = "$s${dump(obj.elements![i], level + 1)}";
      }
    }
    if (obj is ASN1Set) {
      for (var i = 0; i < obj.elements!.length; i++) {
        s = "$s${dump(obj.elements!.elementAt(i), level + 1)}";
      }
    }
    return s;
  }

  void write(String filename) async {
    try {
      // Uint8List? data = asn1sequence.valueBytes;
      Uint8List data = asn1sequence.encode();

      Directory root = await getTemporaryDirectory();
      File file = await File('${root.path}/$filename').create();
      debugPrint(file.path);
      file.writeAsBytesSync(data);
    } catch (e) {
      debugPrint(e.toString());
    }
  }
}
