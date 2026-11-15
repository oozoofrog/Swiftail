// 키 파일 읽기(계약 동작 C4·S3 ③): PKCS#8(`PRIVATE KEY`)과 SEC1(`EC PRIVATE KEY`, Go가 쓴다).

import CryptoKit
import Testing

@testable import SwiftailCertificates

@Suite("키 PEM")
struct PrivateKeyPEMTests {
    private static let limit = 64 * 1024

    @Test("CryptoKit이 쓴 PKCS#8 PEM")
    func pkcs8() throws {
        let key = P256.Signing.PrivateKey()
        let read = try P256.Signing.PrivateKey(pemFile: Array(key.pemRepresentation.utf8), maximumByteCount: Self.limit)
        #expect(read.rawRepresentation == key.rawRepresentation)
    }

    /// Go `x509.MarshalECPrivateKey`가 쓰는 SEC1 `ECPrivateKey`(RFC 5915 3절):
    /// `SEQUENCE { INTEGER 1, OCTET STRING d, [0] EXPLICIT OID secp256r1, [1] EXPLICIT BIT STRING 04‖X‖Y }`.
    /// EXPLICIT 태그는 "안 값 하나를 담은 문맥 구성형"이라 바이트가 `[n] IMPLICIT SEQUENCE { 안 값 }`과 같다.
    private static func sec1(_ key: P256.Signing.PrivateKey) -> [UInt8] {
        DERValue.sequence([
            .integer(magnitude: [1]),
            .octetString(Array(key.rawRepresentation)),
            .implicitlyTagged(number: 0, .sequence([.objectIdentifier(.secp256r1)])),
            .implicitlyTagged(number: 1, .sequence([.bitString(Array(key.publicKey.x963Representation))])),
        ]).encoded
    }

    @Test("Go가 쓰는 SEC1 PEM")
    func sec1() throws {
        let key = P256.Signing.PrivateKey()
        let pem = PEM.encode(PEMBlock(label: .ecPrivateKey, der: Self.sec1(key)))
        // 시험이 만든 SEC1이 맞는지 CryptoKit의 PEM 읽기로 먼저 확인한다(노트 4.6에서 Go의 SEC1 파일로 확인된 길).
        #expect(try P256.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation == key.rawRepresentation)
        let read = try P256.Signing.PrivateKey(pemFile: Array(pem.utf8), maximumByteCount: Self.limit)
        #expect(read.rawRepresentation == key.rawRepresentation)
    }

    @Test("한 블록이 아니면 wrongBlockCount")
    func blockCount() {
        let pem = P256.Signing.PrivateKey().pemRepresentation
        #expect(throws: PEMError.wrongBlockCount) { try P256.Signing.PrivateKey(pemFile: Array((pem + "\n" + pem).utf8), maximumByteCount: Self.limit) }
        #expect(throws: PEMError.wrongBlockCount) { try P256.Signing.PrivateKey(pemFile: [], maximumByteCount: Self.limit) }
    }

    @Test("키가 아닌 라벨, 모르는 라벨(Go의 옛 RSA 계정 키)")
    func label() {
        let certificate = PEM.encode(PEMBlock(label: .certificate, der: Array(P256.Signing.PrivateKey().derRepresentation)))
        #expect(throws: PEMError.unexpectedLabel) { try P256.Signing.PrivateKey(pemFile: Array(certificate.utf8), maximumByteCount: Self.limit) }
        let rsa = "-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----\n"
        #expect(throws: PEMError.unexpectedLabel) { try P256.Signing.PrivateKey(pemFile: Array(rsa.utf8), maximumByteCount: Self.limit) }
    }

    @Test("P-256이 아닌 키, 깨진 DER, 뒤의 쓰레기, 크기 초과")
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
