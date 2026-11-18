// Test-only generator for minimal X.509 v3 certificates (RFC 5280 4.1) on demand for chain verification fixtures (contract behaviors X3 and S3).
// The library does not write X.509. Security handles parsing and verification.
//
// `DERValue` in `Encoding/DER.swift` has only the forms needed for CSR and cannot create OIDs externally. It lacks basicConstraints,
// keyUsage, extKeyUsage, and key identifier OIDs, BOOLEAN, UTCTime, and explicit tags. This small writer concatenates tag, length, and content
// directly. It uses the DER length rules (X.690 10.1).

import CryptoKit
import Foundation

@testable import SwiftailCertificates

/// One test certificate authority, with its key and certificate.
struct TestCertificateAuthority {
    let key: P256.Signing.PrivateKey
    let commonName: String
    /// This authority's certificate (DER).
    let certificate: [UInt8]

    /// A self-signed root.
    static func root(_ commonName: String, from notBefore: Date, to notAfter: Date) -> Self {
        let key = P256.Signing.PrivateKey()
        let der = X509.certificate(
            subject: commonName, subjectKey: key.publicKey, issuer: commonName, issuerKey: key,
            notBefore: notBefore, notAfter: notAfter, extensions: X509.caExtensions(key.publicKey, issuerKey: key.publicKey)
        )
        return Self(key: key, commonName: commonName, certificate: der)
    }

    /// An intermediate authority signed by this authority.
    func intermediate(_ commonName: String, from notBefore: Date, to notAfter: Date) -> Self {
        let child = P256.Signing.PrivateKey()
        let der = X509.certificate(
            subject: commonName, subjectKey: child.publicKey, issuer: self.commonName, issuerKey: key,
            notBefore: notBefore, notAfter: notAfter, extensions: X509.caExtensions(child.publicKey, issuerKey: key.publicKey)
        )
        return Self(key: child, commonName: commonName, certificate: der)
    }

    /// A TLS server leaf signed by this authority (one SAN `dNSName` and EKU serverAuth).
    func leaf(_ dnsName: String, publicKey: P256.Signing.PublicKey, from notBefore: Date, to notAfter: Date) -> [UInt8] {
        X509.certificate(
            subject: dnsName, subjectKey: publicKey, issuer: commonName, issuerKey: key,
            notBefore: notBefore, notAfter: notAfter,
            extensions: X509.leafExtensions(dnsName, publicKey: publicKey, issuerKey: key.publicKey)
        )
    }
}

/// The PEM chain, leaf first.
func pemChain(_ certificates: [[UInt8]]) -> [UInt8] {
    Array(certificates.map { PEM.encode(PEMBlock(label: .certificate, der: $0)) }.joined().utf8)
}

/// Assembles X.509 v3.
private enum X509 {
    static func certificate(
        subject: String, subjectKey: P256.Signing.PublicKey, issuer: String, issuerKey: P256.Signing.PrivateKey,
        notBefore: Date, notAfter: Date, extensions: [[UInt8]]
    ) -> [UInt8] {
        let tbs = sequence(
            explicit(0, integer([2])),                                   // version v3
            integer(Array(SHA256.hash(data: Array((subject + issuer).utf8) + subjectKey.rawRepresentation).prefix(16))),
            ecdsaWithSHA256,
            name(issuer),
            sequence(time(notBefore), time(notAfter)),
            name(subject),
            Array(subjectKey.derRepresentation),                         // SubjectPublicKeyInfo
            explicit(3, sequence(extensions))
        )
        // Signature randomness is fine for test fixtures. Security performs verification.
        let signature = (try? issuerKey.signature(for: tbs))?.derRepresentation ?? Data()
        return sequence(tbs, ecdsaWithSHA256, bitString(Array(signature)))
    }

    static func caExtensions(_ subjectKey: P256.Signing.PublicKey, issuerKey: P256.Signing.PublicKey) -> [[UInt8]] {
        [
            // basicConstraints: cA TRUE(critical)
            ext(oid(2, 5, 29, 19), critical: true, sequence(tlv(0x01, [0xFF]))),
            // keyUsage: keyCertSign | cRLSign(critical)
            ext(oid(2, 5, 29, 15), critical: true, tlv(0x03, [0x01, 0x06])),
            ext(oid(2, 5, 29, 14), critical: false, tlv(0x04, keyIdentifier(subjectKey))),
            authorityKeyIdentifier(issuerKey),
        ]
    }

    static func leafExtensions(
        _ dnsName: String, publicKey: P256.Signing.PublicKey, issuerKey: P256.Signing.PublicKey
    ) -> [[UInt8]] {
        [
            // keyUsage: digitalSignature(critical)
            ext(oid(2, 5, 29, 15), critical: true, tlv(0x03, [0x07, 0x80])),
            // extKeyUsage: id-kp-serverAuth 1.3.6.1.5.5.7.3.1. Apple's SSL policy requires it.
            ext(oid(2, 5, 29, 37), critical: false, sequence(oid(1, 3, 6, 1, 5, 5, 7, 3, 1))),
            // subjectAltName: dNSName [2] IMPLICIT IA5String
            ext(oid(2, 5, 29, 17), critical: false, sequence(tlv(0x82, Array(dnsName.utf8)))),
            ext(oid(2, 5, 29, 14), critical: false, tlv(0x04, keyIdentifier(publicKey))),
            authorityKeyIdentifier(issuerKey),
        ]
    }

    // MARK: - Components

    static let ecdsaWithSHA256 = sequence(oid(1, 2, 840, 10045, 4, 3, 2))

    /// `Name` with one CN (UTF8String).
    static func name(_ commonName: String) -> [UInt8] {
        sequence(tlv(0x31, sequence(oid(2, 5, 4, 3), tlv(0x0C, Array(commonName.utf8)))))
    }

    /// RFC 5280 4.1.2.5: UTCTime through 2049, then GeneralizedTime.
    static func time(_ date: Date) -> [UInt8] {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let year = parts.year ?? 0
        let rest = [parts.month, parts.day, parts.hour, parts.minute, parts.second]
            .map { String(format: "%02d", $0 ?? 0) }.joined()
        return year < 2050
            ? tlv(0x17, Array((String(format: "%02d", year % 100) + rest + "Z").utf8))
            : tlv(0x18, Array((String(format: "%04d", year) + rest + "Z").utf8))
    }

    /// RFC 5280 4.2.1.2 method (1): SHA-1 of the public key BIT STRING.
    static func keyIdentifier(_ key: P256.Signing.PublicKey) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: key.x963Representation))
    }

    static func authorityKeyIdentifier(_ issuerKey: P256.Signing.PublicKey) -> [UInt8] {
        ext(oid(2, 5, 29, 35), critical: false, sequence(tlv(0x80, keyIdentifier(issuerKey))))
    }

    static func ext(_ identifier: [UInt8], critical: Bool, _ value: [UInt8]) -> [UInt8] {
        critical
            ? sequence(identifier, tlv(0x01, [0xFF]), tlv(0x04, value))
            : sequence(identifier, tlv(0x04, value))
    }

    static func sequence(_ elements: [UInt8]...) -> [UInt8] { sequence(elements) }
    static func sequence(_ elements: [[UInt8]]) -> [UInt8] { tlv(0x30, elements.flatMap { $0 }) }
    static func explicit(_ number: UInt8, _ value: [UInt8]) -> [UInt8] { tlv(0xA0 | number, value) }
    static func bitString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + bytes) }

    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        let trimmed = Array(magnitude.drop(while: { $0 == 0 }))
        guard let first = trimmed.first else { return tlv(0x02, [0x00]) }
        return tlv(0x02, first & 0x80 == 0 ? trimmed : [0x00] + trimmed)
    }

    static func oid(_ first: UInt64, _ second: UInt64, _ rest: UInt64...) -> [UInt8] {
        tlv(0x06, ([first * 40 + second] + rest).flatMap(base128))
    }

    static func base128(_ value: UInt64) -> [UInt8] {
        var bytes = [UInt8(value & 0x7F)]
        var rest = value >> 7
        while rest > 0 {
            bytes.insert(UInt8(rest & 0x7F) | 0x80, at: 0)
            rest >>= 7
        }
        return bytes
    }

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var length: [UInt8] = []
        if content.count < 0x80 {
            length = [UInt8(content.count)]
        } else {
            var rest = content.count
            while rest > 0 {
                length.insert(UInt8(truncatingIfNeeded: rest), at: 0)
                rest >>= 8
            }
            length.insert(0x80 | UInt8(length.count), at: 0)
        }
        return [tag] + length + content
    }
}
