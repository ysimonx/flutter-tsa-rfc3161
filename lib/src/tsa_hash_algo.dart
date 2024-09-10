import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';

class TSAHashAlgo {
  static const int sha256 = 256;
  static const int sha512 = 512;
  static const int sha384 = 384;
  static const int sha1 = 1;

  static ASN1Sequence getASN1Sequence(List<int> oid) {
    ASN1ObjectIdentifier asn1OId = ASN1ObjectIdentifier(oid);

    var paramsAns1Null = ASN1Null();

    ASN1Sequence seqAlgorithm = ASN1Sequence();
    seqAlgorithm.add(asn1OId);
    seqAlgorithm.add(paramsAns1Null);
    return seqAlgorithm;
  }

  static ASN1Object getASN1ObjectHashed(Digest digest, List<int> lng) {
    List<int> intList = digest.bytes.toList();
    for (var i = 0; i < lng.length; i++) {
      intList.insert(i, lng[i]);
    }
    Uint8List uint8list = Uint8List.fromList(intList);
    ASN1Object result = ASN1OctetString.fromBytes(uint8list);
    return result;
  }
}

class TSAHashAlgoSHA256 extends TSAHashAlgo {
  static List<int> oid = [2, 16, 840, 1, 101, 3, 4, 2, 1];

  static List<int> lng = [0x04, 0x20];

  TSAHashAlgoSHA256() : super();

  static ASN1Sequence getASN1Sequence() {
    return TSAHashAlgo.getASN1Sequence(oid);
  }

  static ASN1Object getASN1ObjectHashed({required List<int> message}) {
    Digest digest = sha256.convert(message);
    return TSAHashAlgo.getASN1ObjectHashed(digest, lng);
  }
}

class TSAHashAlgoSHA512 extends TSAHashAlgo {
  static List<int> oid = [2, 16, 840, 1, 101, 3, 4, 2, 1];

  static List<int> lng = [0x04, 0x20];

  TSAHashAlgoSHA512() : super();

  static ASN1Sequence getASN1Sequence() {
    return TSAHashAlgo.getASN1Sequence(oid);
  }

  static ASN1Object getASN1ObjectHashed({required List<int> message}) {
    Digest digest = sha256.convert(message);
    return TSAHashAlgo.getASN1ObjectHashed(digest, lng);
  }
}

class TSAHashAlgoSHA1 extends TSAHashAlgo {
  static List<int> oid = [1, 3, 14, 3, 2, 26];

  static List<int> lng = [0x04, 0x14];

  TSAHashAlgoSHA1() : super();

  static ASN1Sequence getASN1Sequence() {
    return TSAHashAlgo.getASN1Sequence(oid);
  }

  static ASN1Object getASN1ObjectHashed({required List<int> message}) {
    Digest digest = sha1.convert(message);
    return TSAHashAlgo.getASN1ObjectHashed(digest, lng);
  }
}

class TSAHashAlgoSHA384 extends TSAHashAlgo {
  static List<int> oid = [2, 16, 840, 1, 101, 3, 4, 2, 2];

  static List<int> lng = [0x04, 0x30];

  TSAHashAlgoSHA384() : super();

  static ASN1Sequence getASN1Sequence() {
    return TSAHashAlgo.getASN1Sequence(oid);
  }

  static ASN1Object getASN1ObjectHashed({required List<int> message}) {
    Digest digest = sha384.convert(message);
    return TSAHashAlgo.getASN1ObjectHashed(digest, lng);
  }
}
