class TSAOid {
  TSAOid();

  static String? nameToOID(String name) {
    Map<String, String> oids = {"id-ct-TSTInfo": "1.2.840.113549.1.9.16.1.4"};
    if (oids.containsKey(name)) {
      return oids[name];
    }
    return null;
  }

  static String nameFromOID(String? oid) {
    String result = "unknown";
    Map<String, String> oids = {
      "2.16.840.1.101.3.4.2.3": "sha512",
      "2.16.840.1.101.3.4.2.1": "sha256",
      "1.2.840.113549.1.1.1": "rsaEncryption",
      "2.5.4.3": "commonName",
      "2.5.4.10": "organizationName",
      "2.5.4.6": "countryName",
      "2.5.4.5": "serialNumber",
      "2.5.4.97": "organizationIdentifier",
      "1.2.840.113549.1.9.16.1.4": "id-ct-TSTInfo",
      "2.16.840.1.114412.7": "time-stamping",
      "2.16.840.1.114412.7.1": "time-stamping",
      "1.2.840.113549.1.7.2": "signedData",
      "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
      "2.5.29.19": "basicConstraints",
      "1.2.840.113549.1.9.3": "contentType",
      "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
      "2.5.29.31": "cRLDistributionPoints",
      "2.5.29.14": "subjectKeyIdentifier",
      "2.5.29.35": "authorityKeyIdentifier",
      "2.5.29.32": "certificatePolicies",
      "2.5.29.37": "extKeyUsage",
      "2.5.29.15": "keyUsage",
      "1.2.840.113549.1.9.5": "signing-time",
      "1.2.840.113549.1.9.16.2.12": "signing-certificate",
      "1.2.840.113549.1.9.4": "id-messageDigest",
      "2.5.4.11": "organizationalUnitName",
      "1.2.840.113549.1.9.16.2.47": "id-aa-signingCertificateV2",
      "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
      "2.16.840.1.101.3.4.2.2": "sha384",
      "1.3.14.3.2.26": "sha1",
      "1.3.6.1.4.1.6449.2.1.1": "Default Time-stamping Policy",
      "1.2.3.4.1": "tsa_policy1",
      "1.3.6.1.4.1.601.10.3.1": "tsa_policy",
      "1.3.6.1.4.1.4146.2.3.1.2": "tsa_policy",
      "1.2.250.1.177.2.9.1": "tsa_policy_certigna",
      "2.5.4.8": "stateOrProvinceName",
      "2.5.4.7": "localityName",
      "2.5.4.13": "description",
      "1.2.840.113549.1.9.1": "emailAddress",
      "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
      "1.2.840.113635.100.6.2.9": "OID_CA_EXTENSION_APPLE_TIMESTAMP",
      "1.2.840.113549.1.1.5": "sha1-with-rsa-signature",
      "1.3.6.1.4.1.311.20.2": "domainController",
      "1.2.840.113549.1.9.16.2.15": "id-aa-ets-sigPolicyId",
      "1.2.840.113549.1.9.16.2.18": "id-aa-ets-signerAttr"
    };

    if (oids.containsKey(oid)) {
      result = oids[oid]!;
    }

    return result;
  }
}
