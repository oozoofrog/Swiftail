// Key file reading (contract behaviors C4 and S3 ③): PKCS#8 (`PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`, written by Go).

import CryptoKit
import Testing

@testable import SwiftailCertificates

@Suite("Key PEM")
struct PrivateKeyPEMTests {
    private static let limit = 64 * 1024

    @Test("PKCS#8 PEM written by CryptoKit")
    func pkcs8() throws {
        let key = P256.Signing.PrivateKey()
        let read = try P256.Signing.PrivateKey(pemFile: Array(key.pemRepresentation.utf8), maximumByteCount: Self.limit)
        #expect(read.rawRepresentation == key.rawRepresentation)
    }

    /// SEC1 `ECPrivateKey` written by Go `x509.MarshalECPrivateKey` (RFC 5915 §3):
    /// `SEQUENCE { INTEGER 1, OCTET STRING d, [0] EXPLICIT OID secp256r1, [1] EXPLICIT BIT STRING 04‖X‖Y }`.
    /// An EXPLICIT tag is a constructed context tag containing one inner value, so its bytes match `[n] IMPLICIT SEQUENCE { inner value }`.
    private static func sec1(_ key: P256.Signing.PrivateKey) -> [UInt8] {
        DERValue.sequence([
            .integer(magnitude: [1]),
            .octetString(Array(key.rawRepresentation)),
            .implicitlyTagged(number: 0, .sequence([.objectIdentifier(.secp256r1)])),
            .implicitlyTagged(number: 1, .sequence([.bitString(Array(key.publicKey.x963Representation))])),
        ]).encoded
    }

    @Test("SEC1 PEM written by Go")
    func sec1() throws {
        let key = P256.Signing.PrivateKey()
        let pem = PEM.encode(PEMBlock(label: .ecPrivateKey, der: Self.sec1(key)))
        // First verify the test-generated SEC1 with CryptoKit's PEM reader, the path verified with Go's SEC1 file in note §4.6.
        #expect(try P256.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation == key.rawRepresentation)
        let read = try P256.Signing.PrivateKey(pemFile: Array(pem.utf8), maximumByteCount: Self.limit)
        #expect(read.rawRepresentation == key.rawRepresentation)
    }

    @Test("Anything other than a single block returns wrongBlockCount")
    func blockCount() {
        let pem = P256.Signing.PrivateKey().pemRepresentation
        #expect(throws: PEMError.wrongBlockCount) { try P256.Signing.PrivateKey(pemFile: Array((pem + "\n" + pem).utf8), maximumByteCount: Self.limit) }
        #expect(throws: PEMError.wrongBlockCount) { try P256.Signing.PrivateKey(pemFile: [], maximumByteCount: Self.limit) }
    }

    @Test("Non-key label and unknown label (Go's old RSA account key)")
    func label() {
        let certificate = PEM.encode(PEMBlock(label: .certificate, der: Array(P256.Signing.PrivateKey().derRepresentation)))
        #expect(throws: PEMError.unexpectedLabel) { try P256.Signing.PrivateKey(pemFile: Array(certificate.utf8), maximumByteCount: Self.limit) }
        let rsa = "-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----\n"
        #expect(throws: PEMError.unexpectedLabel) { try P256.Signing.PrivateKey(pemFile: Array(rsa.utf8), maximumByteCount: Self.limit) }
    }

    @Test("Non-P-256 key, malformed DER, trailing garbage, and size overflow")
    func rejected() {
        let p384 = P384.Signing.PrivateKey().pemRepresentation
        #expect(throws: PEMError.malformed) { try P256.Signing.PrivateKey(pemFile: Array(p384.utf8), maximumByteCount: Self.limit) }
        let broken = PEM.encode(PEMBlock(label: .privateKey, der: [0x30, 0x03, 0x02, 0x01, 0x00]))
        #expect(throws: PEMError.malformed) { try P256.Signing.PrivateKey(pemFile: Array(broken.utf8), maximumByteCount: Self.limit) }
        let pem = P256.Signing.PrivateKey().pemRepresentation
        #expect(throws: PEMError.malformed) { try P256.Signing.PrivateKey(pemFile: Array((pem + "\ntrailing").utf8), maximumByteCount: Self.limit) }
        #expect(throws: PEMError.tooLarge) { try P256.Signing.PrivateKey(pemFile: Array(pem.utf8), maximumByteCount: 100) }
    }
}
