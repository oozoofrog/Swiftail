import CryptoKit

/// A PKCS#10 CSR sent to ACME finalize (RFC 2986).
///
/// Matches the structure produced by `certRequest` (→ `x509.CreateCertificateRequest`) in Go's `feature/acme` (notes §3.6).
///
/// ```
/// CertificationRequest ::= SEQUENCE {
///   certificationRequestInfo SEQUENCE {
///     version       INTEGER 0,
///     subject       SEQUENCE { SET { SEQUENCE { OID commonName, PrintableString name } } },
///     subjectPKInfo SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID secp256r1 }, BIT STRING 04‖X‖Y },
///     attributes    [0] { SEQUENCE { OID extensionRequest,
///                     SET { SEQUENCE { SEQUENCE { OID subjectAltName,
///                       OCTET STRING { SEQUENCE { [2] name } } } } } } }
///   },
///   signatureAlgorithm SEQUENCE { OID ecdsa-with-SHA256 },
///   signature          BIT STRING (DER ECDSA-Sig-Value)
/// }
/// ```
///
/// The bytes of `certificationRequestInfo` must match Go under these conditions (notes chapter 7 item 2, contract §7 test 7): the same public key,
/// attributes (one SAN in extensionRequest), CN tag (`PrintableString`, which Go uses for ASCII names),
/// and DER rules. This type matches Go in all four. Omit the SAN extension's `critical` field because it defaults to false
/// (DER omits defaults, X.690 11.5, `optional` in Go's `pkix.Extension`).
struct CertificateSigningRequest: Sendable, Equatable {
    /// The DER of `certificationRequestInfo`, the signature input (RFC 2986 4.2).
    let certificationRequestInfo: [UInt8]
    /// The DER of the entire CSR. The finalize `csr` field is this data encoded as base64url (RFC 8555 7.4).
    let der: [UInt8]

    /// - Parameters:
    ///   - domain: The name to put in the subject CN and SAN `dNSName`.
    ///   - key: A certificate key generated for this order and distinct from the account key (RFC 8555 11.1, contract behavior C7).
    init(domain: CertificateDomain, signedWith key: P256.Signing.PrivateKey) throws(SigningFailure) {
        let info = Self.certificationRequestInfo(domain: domain, publicKey: key.publicKey)
        certificationRequestInfo = info.encoded
        let signature: [UInt8]
        do {
            // CryptoKit applies SHA-256, and `derRepresentation` is ECDSA-Sig-Value (SEQUENCE { r, s }) (RFC 3279 2.2.3).
            signature = Array(try key.signature(for: certificationRequestInfo).derRepresentation)
        } catch {
            throw SigningFailure()
        }
        der = DERValue.sequence([
            info,
            // The ecdsa-with-SHA256 AlgorithmIdentifier omits parameters (RFC 5758 3.2).
            .sequence([.objectIdentifier(.ecdsaWithSHA256)]),
            .bitString(signature),
        ]).encoded
    }

    /// The `certificationRequestInfo` before signing (RFC 2986 4.1).
    static func certificationRequestInfo(domain: CertificateDomain, publicKey: P256.Signing.PublicKey) -> DERValue {
        // Validated names use only lowercase letters, digits, hyphens, and periods, so they always fit both string types.
        let commonName = PrintableString(domain)
        let dnsName = IA5String(domain)
        let subjectAltName = DERValue.sequence([
            .objectIdentifier(.subjectAltName),
            // extnValue is an OCTET STRING containing the DER of GeneralNames (RFC 5280 4.1 and 4.2.1.6). dNSName is [2] IMPLICIT IA5String.
            .octetString(DERValue.sequence([.implicitlyTagged(number: 2, .ia5String(dnsName))]).encoded),
        ])
        return .sequence([
            .integer(magnitude: []),  // version v1(0)
            // Name ::= RDNSequence. One RDN containing one CN (RFC 5280 4.1.2.4).
            .sequence([.setOf([.sequence([.objectIdentifier(.commonName), .printableString(commonName)])])]),
            subjectPublicKeyInfo(publicKey),
            // attributes [0] IMPLICIT SET OF Attribute. The value of extensionRequest is one Extensions (RFC 2985 5.4.2).
            .implicitlyTagged(number: 0, .setOf([
                .sequence([.objectIdentifier(.extensionRequest), .setOf([.sequence([subjectAltName])])]),
            ])),
        ])
    }

    /// SubjectPublicKeyInfo for a P-256 public key (RFC 5480 §2) contains the id-ecPublicKey algorithm, the secp256r1 curve, and
    /// a BIT STRING holding the uncompressed point `04 ‖ X ‖ Y`. Its bytes match CryptoKit's `derRepresentation` (enforced by the test).
    private static func subjectPublicKeyInfo(_ publicKey: P256.Signing.PublicKey) -> DERValue {
        .sequence([
            .sequence([.objectIdentifier(.ecPublicKey), .objectIdentifier(.secp256r1)]),
            .bitString(Array(publicKey.x963Representation)),
        ])
    }
}

extension PrintableString {
    /// Every character in a validated name (`a-z`, `0-9`, `-`, and `.`) is in PrintableString.
    init(_ domain: CertificateDomain) {
        value = domain.name
    }
}

extension IA5String {
    /// A validated name contains only ASCII.
    init(_ domain: CertificateDomain) {
        value = domain.name
    }
}
