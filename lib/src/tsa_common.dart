import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:path_provider/path_provider.dart';

import 'tsa_oid.dart';

class TSACommon {
  late ASN1Sequence asn1sequence;

  TSACommon();

  void hexaPrint() {
    Uint8List data = asn1sequence.encodedBytes;
    var hex2 =
        data.map((e) => "${e.toRadixString(16).padLeft(2, '0')} ").join();
    debugPrint(hex2);
  }

  String tagName(ASN1Object obj) {
    if (obj is ASN1Sequence) {
      return "ASN1Sequence";
    }

    if (obj is ASN1Set) {
      return "ASN1Set";
    }

    if (obj is ASN1Integer) {
      return "ASN1Integer : ${obj.intValue} : ${obj.valueAsBigInteger} ${obj.valueAsBigInteger.toRadixString(16)}";
    }

    if (obj is ASN1ObjectIdentifier) {
      String label = TSAOid.nameFromOID(obj.identifier);
      return "ASN1ObjectIdentifier : ${obj.identifier} - $label";
    }

    if (obj is ASN1PrintableString) {
      return "ASN1PrintableString : ${obj.stringValue}";
    }

    if (obj is ASN1OctetString) {
      String decoded = "";
      Uint8List bytes = obj.valueBytes();
      try {
        decoded = "'${utf8.decode(bytes)}'";
      } catch (e) {
        // debugPrint(e.toString());
      }

      return "ASN1OctetString  : length ${obj.totalEncodedByteLength}";
    }
    if (obj is ASN1Null) {
      return "ASN1Null";
    }

    if (obj is ASN1GeneralizedTime) {
      return "ASN1GeneralizedTime : ${obj.dateTimeValue}";
    }

    if (obj is ASN1UtcTime) {
      return "ASN1UtcTime : ${obj.dateTimeValue}";
    }

    if (obj is ASN1BitString) {
      return "ASN1BitString : ${obj.stringValue}";
    }

    if (obj is ASN1Boolean) {
      return "ASN1Boolean : ${obj.booleanValue}";
    }
    String decoded = "";
    Uint8List bytes = obj.valueBytes();
    try {
      decoded = "'${utf8.decode(bytes)}'";
    } catch (e) {
      debugPrint(e.toString());
    }
    return "ASN1Object : length ${obj.totalEncodedByteLength} $decoded";
  }

  String ident(n) => List.filled(n + 1, '    ').join();

  String explore(ASN1Object obj, int? level) {
    level ??= 0;

    String s = "${ident(level)}${tagName(obj)}\n";
    if (obj is ASN1Sequence) {
      for (var i = 0; i < obj.elements.length; i++) {
        s = "$s${explore(obj.elements[i], level + 1)}";
      }
    }
    if (obj is ASN1Set) {
      for (var i = 0; i < obj.elements.length; i++) {
        s = "$s${explore(obj.elements.elementAt(i), level + 1)}";
      }
    }
    return s;
  }

  void write(String filename) async {
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

  ASN1Object fixASN1Object(ASN1Object obj) {
    if (obj is ASN1OctetString) {}

    if (obj.tag == 160 || obj.tag == 163) {
      int offset = 0;

      // je recherche le prochain objet
      while (obj.encodedBytes[offset] != 48) {
        // c'est pourri, mais ca peut marcher
        offset++;
        if (offset == obj.encodedBytes.length) {
          return obj;
        }
      }

      Uint8List content = obj.encodedBytes.sublist(offset);

      List<ASN1Object> elements = [];
      int position = 0;
      int remaining = content.length;

      while (remaining > 0) {
        Uint8List content = obj.encodedBytes.sublist(offset + position);
        ASN1Parser parser = ASN1Parser(content, relaxedParsing: true);
        ASN1Object result = parser.nextObject();
        elements.add(result);
        position = position + result.totalEncodedByteLength;
        remaining = remaining - position;
      }

      if (elements.length == 1) {
        return elements[0];
      }
      ASN1Sequence newseq = ASN1Sequence();
      newseq.elements = elements;
      return newseq;
    }

    return obj;
  }

  ASN1Object fix(ASN1Object asn1sequenceproto) {
    ASN1Object result = asn1sequenceproto;
    if (result is ASN1Sequence) {
      for (var i = 0; i < result.elements.length; i++) {
        ASN1Object element = result.elements.elementAt(i);

        element = fixASN1Object(element);

        result.elements[i] = fix(element);
      }
    }
    if (result is ASN1Set) {
      for (var i = 0; i < result.elements.length; i++) {
        ASN1Object element = result.elements.elementAt(i);

        element = fixASN1Object(element);

        result.elements.remove(element);
        result.elements.add(fix(element));
      }
    }
    return result;
  }
}
