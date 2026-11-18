// Contract §7 unit test 9 (received chain verification): behaviors X3, S3 ⑤, and S6, and the C8 trust anchors.

import CryptoKit
import Foundation
import Security
import Testing

@testable import SwiftailCertificates

/// Test time and certificate authority. The time is fixed and passed to `SecTrustSetVerifyDate` as the verification date.
struct TestPKI {
    static let day: TimeInterval = 24 * 3600
    /// 2026-11-15T00:00:00Z.
    static let now = Date(timeIntervalSince1970: 1_794_700_800)
    static let domainName = "rd-mac-1a2b3c4d.tail0001.ts.net"
    /// 90 days from 2026-11-01T00:00:00Z. The 2/3 point is 2026-12-31T00:00:00Z.
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

@Suite("Received chain verification")
struct VerifiedCertificateTests {
    let pki: TestPKI

    init() throws {
        pki = try TestPKI()
    }

    @Test("A leaf and intermediate pass, and the validity period comes from the leaf")
    func validChain() throws {
        let leaf = pki.leaf()
        let verified = try pki.verify(pemChain([leaf, pki.intermediate.certificate]))
        #expect(verified.chain == [leaf, pki.intermediate.certificate])
        #expect(verified.receivedChain == verified.chain)
        #expect(verified.lifetime == CertificateLifetime(domain: pki.domain, notBefore: TestPKI.leafStart, notAfter: TestPKI.leafEnd))
        #expect(verified.privateKey.rawRepresentation == pki.key.rawRepresentation)
    }

    @Test("A root sent with the chain is omitted from chain after verification and remains in receivedChain (behavior S6)")
    func rootIncluded() throws {
        let received = [pki.leaf(), pki.intermediate.certificate, pki.root.certificate]
        let verified = try pki.verify(pemChain(received))
        #expect(verified.receivedChain == received)
        #expect(verified.chain == Array(received.prefix(2)))
    }

    /// Before the fix, all certificates with identical subjects and issuers were removed. The self-issued intermediate used for key rotation (same name as the root
    /// and a different key) was removed, so the peer could not build the chain.
    @Test("Keeps the self-issued intermediate in chain and removes only the trust anchor selected by evaluation")
    func selfIssuedIntermediateIsKept() throws {
        let selfIssued = pki.root.intermediate(
            pki.root.commonName, from: TestPKI.now - 365 * TestPKI.day, to: TestPKI.now + 1825 * TestPKI.day)
        let leaf = selfIssued.leaf(
            TestPKI.domainName, publicKey: pki.key.publicKey, from: TestPKI.leafStart, to: TestPKI.leafEnd)
        let received = [leaf, selfIssued.certificate, pki.root.certificate]
        let verified = try pki.verify(pemChain(received))
        #expect(verified.chain == [leaf, selfIssued.certificate])
        // A chain sent without a root is kept in full.
        #expect(try pki.verify(pemChain([leaf, selfIssued.certificate])).chain == [leaf, selfIssued.certificate])
    }

    @Test("Rejects the entire response if it contains a PRIVATE KEY block (RFC 8555 11.4)")
    func privateKeyBlock() {
        let keyBlock = Array(pki.key.pemRepresentation.utf8)
        let input = pemChain([pki.leaf()]) + keyBlock + pemChain([pki.intermediate.certificate])
        #expect(throws: CertificateVerificationError.malformedChain(.unexpectedLabel)) { try pki.verify(input) }
    }

    @Test("Garbage bytes after or between blocks")
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

    @Test("Unparseable block")
    func unparsableBlock() {
        let broken = Array("-----BEGIN CERTIFICATE-----\nnot*base64\n-----END CERTIFICATE-----\n".utf8)
        #expect(throws: CertificateVerificationError.malformedChain(.malformed)) { try pki.verify(broken) }
        let truncated = Array(String(decoding: pemChain([pki.leaf()]), as: UTF8.self).dropLast(26).utf8)
        #expect(throws: CertificateVerificationError.malformedChain(.malformed)) { try pki.verify(truncated) }
    }

    @Test("Non-X.509 DER")
    func notX509() {
        let input = Array(PEM.encode(PEMBlock(label: .certificate, der: [0x30, 0x03, 0x02, 0x01, 0x01])).utf8)
        #expect(throws: CertificateVerificationError.unparsableCertificate) { try pki.verify(input) }
    }

    @Test("6 certificates, 0 certificates")
    func chainLength() throws {
        let five = [pki.leaf()] + Array(repeating: pki.intermediate.certificate, count: 4)
        _ = try pki.verify(pemChain(five))
        #expect(throws: CertificateVerificationError.malformedChain(.wrongBlockCount)) {
            try pki.verify(pemChain(five + [pki.root.certificate]))
        }
        #expect(throws: CertificateVerificationError.malformedChain(.wrongBlockCount)) { try pki.verify(Array("\n".utf8)) }
    }

    @Test("Leaf with a different key (behavior X3 ③)")
    func otherKey() {
        let other = pki.leaf(key: P256.Signing.PrivateKey().publicKey)
        #expect(throws: CertificateVerificationError.keyMismatch) {
            try pki.verify(pemChain([other, pki.intermediate.certificate]))
        }
    }

    @Test("Leaf with a different name")
    func otherName() {
        let other = pki.leaf("rd-mac-5e6f7a8b.tail0001.ts.net")
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecHostNameMismatch))) {
            try pki.verify(pemChain([other, pki.intermediate.certificate]))
        }
    }

    @Test("Expired leaf and leaf that is not yet valid")
    func outsideValidity() {
        let chain = pemChain([pki.leaf(), pki.intermediate.certificate])
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecCertificateExpired))) {
            try pki.verify(chain, at: TestPKI.leafEnd + 1)
        }
        // Security also returns `errSecCertificateExpired` for a leaf that is not yet valid, as observed on macOS 27.
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecCertificateExpired))) {
            try pki.verify(chain, at: TestPKI.leafStart - 1)
        }
    }

    @Test("An unknown root is rejected when only a different root is supplied as an anchor")
    func unknownRoot() {
        let stranger = TestCertificateAuthority.root("Stranger Root", from: TestPKI.now - TestPKI.day, to: TestPKI.now + TestPKI.day)
        let chain = pemChain([pki.leaf(), pki.intermediate.certificate, pki.root.certificate])
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecNotTrusted))) {
            try pki.verify(chain, anchors: .only([stranger.certificate]))
        }
    }

    @Test("System roots alone do not trust the test authority (production anchors)")
    func systemAnchors() {
        let chain = pemChain([pki.leaf(), pki.intermediate.certificate, pki.root.certificate])
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecNotTrusted))) {
            try pki.verify(chain, anchors: .system)
        }
    }

    @Test("A chain with a missing intermediate fails without fetching from the network")
    func missingIntermediate() {
        #expect(throws: CertificateVerificationError.untrusted(status: Int(errSecCreateChainFailed))) {
            try pki.verify(pemChain([pki.leaf()]))
        }
    }

    @Test("Leaf with a lifetime shorter than 1 hour (behavior X3 ⑤)")
    func shortLifetime() throws {
        let start = TestPKI.now - 60
        #expect(throws: CertificateVerificationError.lifetimeTooShort) {
            try pki.verify(pemChain([pki.leaf(from: start, to: start + 3599), pki.intermediate.certificate]))
        }
        _ = try pki.verify(pemChain([pki.leaf(from: start, to: start + 3600), pki.intermediate.certificate]))
    }

    @Test("description and dump omit the key and name (behavior K1)")
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

    @Test("Redacts the tailnet domain in the certificate's string representation and dump (behavior K2)")
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

    @Test("Redacts the tailnet domain in the status string representation and dump (behavior K2). The property returns it unchanged")
    func certificateStatusRedactsDomain() {
        let status = CertificateStatus(
            domain: TestPKI.domainName, notAfter: TestPKI.leafEnd, lastFailure: .domainNotAllowed, nextAttempt: TestPKI.now
        )
        #expect(status.domain == TestPKI.domainName)

        var dumped = ""
        dump(status, to: &dumped)
        for text in [String(describing: status), String(reflecting: status), dumped] {
            #expect(!text.contains(TestPKI.domainName))
            #expect(text.contains("domainNotAllowed"))
        }
    }
}
