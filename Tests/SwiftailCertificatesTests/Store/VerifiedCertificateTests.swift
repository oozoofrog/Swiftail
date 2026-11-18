// 계약 7절 단위 시험 9(받은 사슬의 검사): 동작 X3·S3 ⑤·S6, C8의 신뢰 앵커.

import CryptoKit
import Foundation
import Security
import Testing

@testable import SwiftailCertificates

/// 시험의 시각과 인증 기관. 시각은 고정이다(검증 시각을 `SecTrustSetVerifyDate`로 넘긴다).
struct TestPKI {
    static let day: TimeInterval = 24 * 3600
    /// 2026-11-15T00:00:00Z.
    static let now = Date(timeIntervalSince1970: 1_794_700_800)
    static let domainName = "rd-mac-1a2b3c4d.tail0001.ts.net"
    /// 2026-11-01T00:00:00Z부터 90일. 2/3 지점은 2026-12-31T00:00:00Z.
    static let leafStart = Date(timeIntervalSince1970: 1_793_491_200)
    static let leafEnd = leafStart.addingTimeInterval(90 * day)

    let root = TestCertificateAuthority.root("Swiftail Test Root", from: now - 365 * day, to: now + 3650 * day)
    let intermediate: TestCertificateAuthority
    let key = P256.Signing.PrivateKey()
    let domain: CertificateDomain

    init() throws {
        domain = try #require(CertificateDomain(Self.domainName))
        intermediate = root.intermediate("Swiftail Test Intermediate", from: Self.now - 365 * Self.day, to: Self.now + 1825 * Self.day)
    }

    var anchors: CertificateTrustAnchors { .only([root.certificate]) }

    func leaf(
        _ name: String = TestPKI.domainName, key: P256.Signing.PublicKey? = nil,
        from start: Date = TestPKI.leafStart, to end: Date = TestPKI.leafEnd
    ) -> [UInt8] {
        intermediate.leaf(name, publicKey: key ?? self.key.publicKey, from: start, to: end)
    }

    func verify(
        _ pem: [UInt8], key: P256.Signing.PrivateKey? = nil, at now: Date = TestPKI.now,
        anchors: CertificateTrustAnchors? = nil
    ) throws(CertificateVerificationError) -> VerifiedCertificate {
        try VerifiedCertificate(
            pemChain: pem, maximumByteCount: 256 * 1024, privateKey: key ?? self.key,
            domain: domain, at: now, anchors: anchors ?? self.anchors
        )
    }
}

@Suite("받은 사슬의 검사")
struct VerifiedCertificateTests {
    let pki: TestPKI

    init() throws {
        pki = try TestPKI()
    }

    @Test("leaf와 중간 인증서: 통과하고 기간은 leaf의 것")
    func validChain() throws {
        let leaf = pki.leaf()
        let verified = try pki.verify(pemChain([leaf, pki.intermediate.certificate]))
        #expect(verified.chain == [leaf, pki.intermediate.certificate])
        #expect(verified.receivedChain == verified.chain)
        #expect(verified.lifetime == CertificateLifetime(domain: pki.domain, notBefore: TestPKI.leafStart, notAfter: TestPKI.leafEnd))
        #expect(verified.privateKey.rawRepresentation == pki.key.rawRepresentation)
    }

    @Test("루트를 함께 보낸 사슬: 검증 뒤 chain에서 빠지고 receivedChain에는 남는다(동작 S6)")
    func rootIncluded() throws {
        let received = [pki.leaf(), pki.intermediate.certificate, pki.root.certificate]
        let verified = try pki.verify(pemChain(received))
        #expect(verified.receivedChain == received)
        #expect(verified.chain == Array(received.prefix(2)))
    }

    /// 고치기 전에는 주체와 발급자가 같은 인증서를 모두 뗐다. 키를 바꿀 때 쓰는 자기 발급 중간 인증서(이름은 루트와 같고
    /// 키가 다르다)가 빠져 상대가 사슬을 잇지 못했다.
    @Test("자기 발급 중간 인증서는 chain에 남고, 평가가 고른 신뢰 앵커만 빠진다")
    func selfIssuedIntermediateIsKept() throws {
        let selfIssued = pki.root.intermediate(
            pki.root.commonName, from: TestPKI.now - 365 * TestPKI.day, to: TestPKI.now + 1825 * TestPKI.day)
        let leaf = selfIssued.leaf(
            TestPKI.domainName, publicKey: pki.key.publicKey, from: TestPKI.leafStart, to: TestPKI.leafEnd)
        let received = [leaf, selfIssued.certificate, pki.root.certificate]
        let verified = try pki.verify(pemChain(received))
        #expect(verified.chain == [leaf, selfIssued.certificate])
        // 루트를 보내지 않은 사슬에서는 아무것도 빠지지 않는다.
        #expect(try pki.verify(pemChain([leaf, selfIssued.certificate])).chain == [leaf, selfIssued.certificate])
    }

    @Test("PRIVATE KEY 블록이 낀 응답은 전체를 버린다(RFC 8555 11.4)")
    func privateKeyBlock() {
        let keyBlock = Array(pki.key.pemRepresentation.utf8)
        let input = pemChain([pki.leaf()]) + keyBlock + pemChain([pki.intermediate.certificate])
        #expect(throws: CertificateVerificationError.malformedChain(.unexpectedLabel)) { try pki.verify(input) }
    }

    @Test("블록 뒤나 사이의 쓰레기 바이트")
    func trailingGarbage() {
        let leaf = pemChain([pki.leaf()])
        let intermediate = pemChain([pki.intermediate.certificate])
        #expect(throws: CertificateVerificationError.malformedChain(.malformed)) {
            try pki.verify(leaf + Array("garbage\n".utf8) + intermediate)
        }
        #expect(throws: CertificateVerificationError.malformedChain(.malformed)) {
            try pki.verify(leaf + intermediate + Array("x".utf8))
        }
    }

    @Test("해석되지 않는 블록")
    func unparsableBlock() {
        let broken = Array("-----BEGIN CERTIFICATE-----\nnot*base64\n-----END CERTIFICATE-----\n".utf8)
        #expect(throws: CertificateVerificationError.malformedChain(.malformed)) { try pki.verify(broken) }
        let truncated = Array(String(decoding: pemChain([pki.leaf()]), as: UTF8.self).dropLast(26).utf8)
        #expect(throws: CertificateVerificationError.malformedChain(.malformed)) { try pki.verify(truncated) }
    }

    @Test("X.509가 아닌 DER")
    func notX509() {
        let input = Array(PEM.encode(PEMBlock(label: .certificate, der: [0x30, 0x03, 0x02, 0x01, 0x01])).utf8)
        #expect(throws: CertificateVerificationError.unparsableCertificate) { try pki.verify(input) }
    }

    @Test("6장, 0장")
    func chainLength() throws {
        let five = [pki.leaf()] + Array(repeating: pki.intermediate.certificate, count: 4)
        _ = try pki.verify(pemChain(five))
        #expect(throws: CertificateVerificationError.malformedChain(.wrongBlockCount)) {
            try pki.verify(pemChain(five + [pki.root.certificate]))
        }
        #expect(throws: CertificateVerificationError.malformedChain(.wrongBlockCount)) { try pki.verify(Array("\n".utf8)) }
    }

    @Test("다른 키의 leaf(동작 X3 ③)")
    func otherKey() {
        let other = pki.leaf(key: P256.Signing.PrivateKey().publicKey)
        #expect(throws: CertificateVerificationError.keyMismatch) {
            try pki.verify(pemChain([other, pki.intermediate.certificate]))
        }
    }

    @Test("다른 이름의 leaf")
    func otherName() {
        let other = pki.leaf("rd-mac-5e6f7a8b.tail0001.ts.net")
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecHostNameMismatch))) {
            try pki.verify(pemChain([other, pki.intermediate.certificate]))
        }
    }

    @Test("만료된 leaf, 아직 유효하지 않은 leaf")
    func outsideValidity() {
        let chain = pemChain([pki.leaf(), pki.intermediate.certificate])
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecCertificateExpired))) {
            try pki.verify(chain, at: TestPKI.leafEnd + 1)
        }
        // Security는 아직 유효하지 않은 leaf에도 `errSecCertificateExpired`를 낸다(macOS 27에서 본 값).
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecCertificateExpired))) {
            try pki.verify(chain, at: TestPKI.leafStart - 1)
        }
    }

    @Test("모르는 루트: 다른 루트만 앵커로 주면 받지 않는다")
    func unknownRoot() {
        let stranger = TestCertificateAuthority.root("Stranger Root", from: TestPKI.now - TestPKI.day, to: TestPKI.now + TestPKI.day)
        let chain = pemChain([pki.leaf(), pki.intermediate.certificate, pki.root.certificate])
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecNotTrusted))) {
            try pki.verify(chain, anchors: .only([stranger.certificate]))
        }
    }

    @Test("시스템 루트만으로는 시험 기관을 믿지 않는다(운영 앵커)")
    func systemAnchors() {
        let chain = pemChain([pki.leaf(), pki.intermediate.certificate, pki.root.certificate])
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecNotTrusted))) {
            try pki.verify(chain, anchors: .system)
        }
    }

    @Test("중간 인증서가 빠진 사슬은 네트워크에서 채우지 않고 실패한다")
    func missingIntermediate() {
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecCreateChainFailed))) {
            try pki.verify(pemChain([pki.leaf()]))
        }
    }

    @Test("수명이 1시간보다 짧은 leaf(동작 X3 ⑤)")
    func shortLifetime() throws {
        let start = TestPKI.now - 60
        #expect(throws: CertificateVerificationError.lifetimeTooShort) {
            try pki.verify(pemChain([pki.leaf(from: start, to: start + 3599), pki.intermediate.certificate]))
        }
        _ = try pki.verify(pemChain([pki.leaf(from: start, to: start + 3600), pki.intermediate.certificate]))
    }

    @Test("description과 dump에 키와 이름이 없다(동작 K1)")
    func redaction() throws {
        let verified = try pki.verify(pemChain([pki.leaf(), pki.intermediate.certificate]))
        var dumped = ""
        dump(verified, to: &dumped)
        for text in [verified.description, dumped, String(reflecting: verified)] {
            #expect(!text.contains(TestPKI.domainName))
            #expect(!text.contains(pki.key.rawRepresentation.base64EncodedString()))
            #expect(!text.contains("PRIVATE"))
            #expect(text.contains("notAfter"))
        }
    }

    @Test("인증서의 문자열 표현과 덤프에서 tailnet 도메인을 가린다(동작 K2)")
    func tailnetCertificateRedactsDomain() throws {
        let verified = try pki.verify(pemChain([pki.leaf(), pki.intermediate.certificate]))
        let certificate = TailnetCertificate(verified)
        #expect(certificate.domain == TestPKI.domainName)

        var dumped = ""
        dump(certificate, to: &dumped)
        #expect(!String(describing: certificate).contains(TestPKI.domainName))
        #expect(!String(reflecting: certificate).contains(TestPKI.domainName))
        #expect(!dumped.contains(TestPKI.domainName))
    }
}
