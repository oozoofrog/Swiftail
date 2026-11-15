// 시험 전용: 사슬 검증(계약 동작 X3·S3)의 자료가 될 최소한의 X.509 v3 인증서(RFC 5280 4.1)를 그 자리에서 만든다.
// 라이브러리에는 X.509 쓰기가 없다(해석·검증은 Security가 한다).
//
// `Encoding/DER.swift`의 `DERValue`는 CSR에 필요한 형만 있고 OID를 밖에서 만들 수 없으므로(basicConstraints·
// keyUsage·extKeyUsage·키 식별자의 OID, BOOLEAN, UTCTime, 명시적 태그가 없다) 여기서는 태그·길이·내용을 직접 잇는
// 작은 쓰기를 둔다. 길이 규칙은 DER(X.690 10.1)와 같다.

import CryptoKit
import Foundation

@testable import SwiftailCertificates

/// 시험용 인증 기관 하나: 키와 그 인증서.
struct TestCertificateAuthority {
    let key: P256.Signing.PrivateKey
    let commonName: String
    /// 이 기관의 인증서(DER).
    let certificate: [UInt8]

    /// 자기 서명 루트.
    static func root(_ commonName: String, from notBefore: Date, to notAfter: Date) -> Self {
        let key = P256.Signing.PrivateKey()
        let der = X509.certificate(
            subject: commonName, subjectKey: key.publicKey, issuer: commonName, issuerKey: key,
            notBefore: notBefore, notAfter: notAfter, extensions: X509.caExtensions(key.publicKey, issuerKey: key.publicKey)
        )
        return Self(key: key, commonName: commonName, certificate: der)
    }

    /// 이 기관이 서명한 중간 기관.
    func intermediate(_ commonName: String, from notBefore: Date, to notAfter: Date) -> Self {
        let child = P256.Signing.PrivateKey()
        let der = X509.certificate(
            subject: commonName, subjectKey: child.publicKey, issuer: self.commonName, issuerKey: key,
            notBefore: notBefore, notAfter: notAfter, extensions: X509.caExtensions(child.publicKey, issuerKey: key.publicKey)
        )
        return Self(key: child, commonName: commonName, certificate: der)
    }

    /// 이 기관이 서명한 TLS 서버 leaf(SAN `dNSName` 하나, EKU serverAuth).
    func leaf(_ dnsName: String, publicKey: P256.Signing.PublicKey, from notBefore: Date, to notAfter: Date) -> [UInt8] {
        X509.certificate(
            subject: dnsName, subjectKey: publicKey, issuer: commonName, issuerKey: key,
            notBefore: notBefore, notAfter: notAfter,
            extensions: X509.leafExtensions(dnsName, publicKey: publicKey, issuerKey: key.publicKey)
        )
    }
}

/// PEM 사슬(leaf 먼저).
func pemChain(_ certificates: [[UInt8]]) -> [UInt8] {
    Array(certificates.map { PEM.encode(PEMBlock(label: .certificate, der: $0)) }.joined().utf8)
}

/// X.509 v3의 조립.
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
        // 시험 자료라 서명의 무작위성은 상관없다(검증하는 것은 Security다).
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
            // extKeyUsage: id-kp-serverAuth 1.3.6.1.5.5.7.3.1. Apple의 SSL 정책이 요구한다.
            ext(oid(2, 5, 29, 37), critical: false, sequence(oid(1, 3, 6, 1, 5, 5, 7, 3, 1))),
            // subjectAltName: dNSName [2] IMPLICIT IA5String
            ext(oid(2, 5, 29, 17), critical: false, sequence(tlv(0x82, Array(dnsName.utf8)))),
            ext(oid(2, 5, 29, 14), critical: false, tlv(0x04, keyIdentifier(publicKey))),
            authorityKeyIdentifier(issuerKey),
        ]
    }

    // MARK: - 부품

    static let ecdsaWithSHA256 = sequence(oid(1, 2, 840, 10045, 4, 3, 2))

    /// `Name`: CN 하나(UTF8String).
    static func name(_ commonName: String) -> [UInt8] {
        sequence(tlv(0x31, sequence(oid(2, 5, 4, 3), tlv(0x0C, Array(commonName.utf8)))))
    }

    /// RFC 5280 4.1.2.5: 2049년까지는 UTCTime, 그 뒤는 GeneralizedTime.
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

    /// RFC 5280 4.2.1.2 방법 (1): 공개 키 BIT STRING의 SHA-1.
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
