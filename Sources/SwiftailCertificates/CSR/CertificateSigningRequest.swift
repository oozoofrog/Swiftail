import CryptoKit

/// ACME finalize에 보내는 PKCS#10 CSR(RFC 2986).
///
/// Go `feature/acme`의 `certRequest`(→ `x509.CreateCertificateRequest`)가 만드는 것과 같은 모양이다(노트 3.6):
///
/// ```
/// CertificationRequest ::= SEQUENCE {
///   certificationRequestInfo SEQUENCE {
///     version       INTEGER 0,
///     subject       SEQUENCE { SET { SEQUENCE { OID commonName, PrintableString 이름 } } },
///     subjectPKInfo SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID secp256r1 }, BIT STRING 04‖X‖Y },
///     attributes    [0] { SEQUENCE { OID extensionRequest,
///                     SET { SEQUENCE { SEQUENCE { OID subjectAltName,
///                       OCTET STRING { SEQUENCE { [2] 이름 } } } } } } }
///   },
///   signatureAlgorithm SEQUENCE { OID ecdsa-with-SHA256 },
///   signature          BIT STRING (DER ECDSA-Sig-Value)
/// }
/// ```
///
/// `certificationRequestInfo`의 바이트가 Go와 같아야 하는 조건(노트 7장 2, 계약 7절 시험 7): 같은 공개 키,
/// 같은 속성(extensionRequest의 SAN 하나), 같은 CN 태그(`PrintableString`. Go는 ASCII 이름을 이 태그로 쓴다),
/// 같은 DER 규칙. 이 타입은 넷을 모두 Go와 같게 정한다. SAN 확장의 `critical`은 기본값 거짓이라 적지 않는다
/// (DER는 기본값을 생략한다. X.690 11.5, Go `pkix.Extension`의 `optional`).
struct CertificateSigningRequest: Sendable, Equatable {
    /// 서명의 입력인 `certificationRequestInfo`의 DER(RFC 2986 4.2).
    let certificationRequestInfo: [UInt8]
    /// CSR 전체의 DER. finalize의 `csr`는 이것의 base64url이다(RFC 8555 7.4).
    let der: [UInt8]

    /// - Parameters:
    ///   - domain: 주체 CN과 SAN `dNSName`에 넣을 이름.
    ///   - key: 인증서 키. 계정 키와 다른, 이 주문을 위해 새로 만든 키다(RFC 8555 11.1, 계약 동작 C7).
    init(domain: CertificateDomain, signedWith key: P256.Signing.PrivateKey) throws(SigningFailure) {
        let info = Self.certificationRequestInfo(domain: domain, publicKey: key.publicKey)
        certificationRequestInfo = info.encoded
        let signature: [UInt8]
        do {
            // CryptoKit이 SHA-256을 적용하고, `derRepresentation`이 ECDSA-Sig-Value(SEQUENCE { r, s })다(RFC 3279 2.2.3).
            signature = Array(try key.signature(for: certificationRequestInfo).derRepresentation)
        } catch {
            throw SigningFailure()
        }
        der = DERValue.sequence([
            info,
            // ecdsa-with-SHA256의 AlgorithmIdentifier는 매개변수를 생략한다(RFC 5758 3.2).
            .sequence([.objectIdentifier(.ecdsaWithSHA256)]),
            .bitString(signature),
        ]).encoded
    }

    /// 서명하기 전의 `certificationRequestInfo`(RFC 2986 4.1).
    static func certificationRequestInfo(domain: CertificateDomain, publicKey: P256.Signing.PublicKey) -> DERValue {
        // 이름 검사를 통과한 이름은 소문자·숫자·`-`·`.`뿐이므로 두 문자열 형의 문자 집합에 늘 든다.
        let commonName = PrintableString(domain)
        let dnsName = IA5String(domain)
        let subjectAltName = DERValue.sequence([
            .objectIdentifier(.subjectAltName),
            // extnValue는 GeneralNames의 DER를 담은 OCTET STRING이다(RFC 5280 4.1·4.2.1.6). dNSName은 [2] IMPLICIT IA5String.
            .octetString(DERValue.sequence([.implicitlyTagged(number: 2, .ia5String(dnsName))]).encoded),
        ])
        return .sequence([
            .integer(magnitude: []),  // version v1(0)
            // Name ::= RDNSequence. CN 하나짜리 RDN 하나(RFC 5280 4.1.2.4).
            .sequence([.setOf([.sequence([.objectIdentifier(.commonName), .printableString(commonName)])])]),
            subjectPublicKeyInfo(publicKey),
            // attributes [0] IMPLICIT SET OF Attribute. extensionRequest의 값은 Extensions 하나다(RFC 2985 5.4.2).
            .implicitlyTagged(number: 0, .setOf([
                .sequence([.objectIdentifier(.extensionRequest), .setOf([.sequence([subjectAltName])])]),
            ])),
        ])
    }

    /// P-256 공개 키의 SubjectPublicKeyInfo(RFC 5480 2절): 알고리즘 id-ecPublicKey와 곡선 secp256r1, 그리고
    /// 비압축 점 `04 ‖ X ‖ Y`를 담은 BIT STRING. CryptoKit의 `derRepresentation`과 같은 바이트다(시험이 고정한다).
    private static func subjectPublicKeyInfo(_ publicKey: P256.Signing.PublicKey) -> DERValue {
        .sequence([
            .sequence([.objectIdentifier(.ecPublicKey), .objectIdentifier(.secp256r1)]),
            .bitString(Array(publicKey.x963Representation)),
        ])
    }
}

extension PrintableString {
    /// 이름 검사를 통과한 이름의 문자(`a-z`·`0-9`·`-`·`.`)는 모두 PrintableString에 든다.
    init(_ domain: CertificateDomain) {
        value = domain.name
    }
}

extension IA5String {
    /// 이름 검사를 통과한 이름은 ASCII뿐이다.
    init(_ domain: CertificateDomain) {
        value = domain.name
    }
}
