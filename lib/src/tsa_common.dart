import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:path_provider/path_provider.dart';

class TSACommon {
  late ASN1Sequence asn1sequence;

  TSACommon();

  void hexaPrint() {
    Uint8List data = asn1sequence.encodedBytes;
    var hex2 =
        data.map((e) => "${e.toRadixString(16).padLeft(2, '0')} ").join();
    debugPrint(hex2);
  }

  String nameFromOID(String? oid) {
    String result = "unknown";
    Map<String, String> oids = {
      "2.16.840.1.101.3.4.2.3": "sha512",
      "2.16.840.1.101.3.4.2.1": "sha256",
      "1.2.840.113549.1.1.1": "rsaEncryption",
      "2.5.4.3": "commonName",
      "2.5.4.10": "organizationName",
      "2.5.4.6": "countryName",
      "1.2.840.113549.1.9.16.1.4": "id-ct-TSTInfo",
    };

    if (oids.containsKey(oid)) {
      result = oids[oid]!;
    }

    return result;
  }

  String tagName(ASN1Object obj) {
    if (obj is ASN1Sequence) {
      return "ASN1Sequence";
    }
    if (obj is ASN1Set) {
      return "ASN1Set";
    }
    if (obj is ASN1Integer) {
      return "ASN1Integer : ${obj.intValue}";
    }
    if (obj is ASN1ObjectIdentifier) {
      String label = nameFromOID(obj.identifier);

      return "ASN1ObjectIdentifier : ${obj.identifier} - $label";
    }
    if (obj is ASN1PrintableString) {
      return "ASN1PrintableString : ${obj.stringValue}";
    }
    if (obj is ASN1OctetString) {
      return "ASN1OctetString  : length ${obj.totalEncodedByteLength}";
    }
    if (obj is ASN1Null) {
      return "ASN1Null";
    }
    return "ASN1Object : length ${obj.totalEncodedByteLength}";
  }

  String ident(n) => List.filled(n + 1, '    ').join();

  String explore(ASN1Object obj, int? level) {
    level ??= 0;

    String s = "${ident(level)}${tagName(obj)}\n";

    if (obj is ASN1Sequence) {
      for (var i = 0; i < obj.elements.length; i++) {
        s = "$s\n${explore(obj.elements[i], level + 1)}";
      }
    }
    if (obj is ASN1Set) {
      for (var i = 0; i < obj.elements.length; i++) {
        s = "$s\n${explore(obj.elements.elementAt(i), level + 1)}";
      }
    }
    return s;
  }

  write(String filename) async {
    try {
      Uint8List data = asn1sequence.encodedBytes;

      Directory root = await getTemporaryDirectory();
      File file = await File('${root.path}/$filename').create();
      debugPrint(file.path);
      file.writeAsBytesSync(data);
    } catch (e) {
      debugPrint(e.toString());
    }
  }
}
