import Foundation
import Testing

@testable import SwiftailIO

/// Tests DERP certificate pinning and name verification (contract `docs/contracts/SwiftailDERP.md` "M8 ③", behavior V 2·4). Uses fixed certificates without connecting.
@Suite("Server certificate verification")
struct ServerCertificateTests {
    private typealias Fixture = ServerCertificateFixtures

    /// Within the validity period of the certificate fixtures.
    private static let now = Date(timeIntervalSince1970: 1_780_272_000) // 2026-06-01T00:00:00Z

    private static func pinned(
        _ certificates: [[UInt8]], hash: String = Fixture.ipLeafSHA256, serverName: String = "100.64.0.1", at now: Date = now
    ) -> ServerCertificate.Failure? {
        do throws(ServerCertificate.Failure) {
            try ServerCertificate.checkPinned(certificates, sha256Hex: hash, serverName: serverName, at: now)
            return nil
        } catch {
            return error
        }
    }

    private static func named(
        _ certificates: [[UInt8]], name: String = "derp-cert.example.test", anchors: [[UInt8]]? = [Fixture.root]
    ) -> ServerCertificate.Failure? {
        do throws(ServerCertificate.Failure) {
            try ServerCertificate.checkNamed(certificates, name: name, at: now, anchors: anchors)
            return nil
        } catch {
            return error
        }
    }

    private static func isUntrusted(_ failure: ServerCertificate.Failure?) -> Bool {
        if case .untrusted = failure { true } else { false }
    }

    // MARK: Pinning

    @Test("Pinning matches derper's self-signed IP certificate by hash and excludes the meta certificate from the count in every position")
    func pinnedMatches() {
        #expect(Self.pinned([Fixture.ipLeaf]) == nil)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta]) == nil)
        // Go accepts this. If the first certificate (whose key TLS proved) looks like a meta certificate, pinning fails to prove key ownership, so reject it.
        #expect(Self.pinned([Fixture.meta, Fixture.ipLeaf]) == .candidateNotLeaf)
    }

    @Test("Pinning fails for a different hash, the same hash in uppercase, and the hash of the meta certificate the server also presents")
    func pinnedHashMismatch() {
        #expect(Self.pinned([Fixture.otherIPLeaf]) == .hashMismatch)
        #expect(Self.pinned([Fixture.ipLeaf], hash: Fixture.ipLeafSHA256.uppercased()) == .hashMismatch)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta], hash: Fixture.metaSHA256) == .hashMismatch)
        #expect(Self.pinned([Fixture.ipLeaf], hash: "") == .hashMismatch)
    }

    @Test("Pinning fails with two non-meta certificates (including duplicates) or no non-meta certificate")
    func pinnedCount() {
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.otherIPLeaf]) == .multipleCandidates)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta, Fixture.otherIPLeaf]) == .multipleCandidates)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.ipLeaf]) == .multipleCandidates)
        #expect(Self.pinned([Fixture.meta]) == .noCandidate)
        #expect(Self.pinned([]) == .unparsable)
        #expect(Self.pinned([Fixture.ipLeaf, [0x30, 0x03, 0x02, 0x01, 0x00]]) == .unparsable)
    }

    @Test("Pinning fails outside the validity period (expired or not yet valid)")
    func pinnedValidity() {
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Date(timeIntervalSince1970: 1_801_440_000)))) // 2027-02-01
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Date(timeIntervalSince1970: 1_764_547_200)))) // 2025-12-01
    }

    @Test("Pinning requires the certificate to be valid for the name sent in SNI and strips a trailing dot")
    func pinnedHostName() {
        let hash = Fixture.dnsLeafSHA256
        #expect(Self.pinned([Fixture.dnsLeaf], hash: hash, serverName: "derp1a.example.test") == nil)
        #expect(Self.pinned([Fixture.dnsLeaf], hash: hash, serverName: "derp1a.example.test.") == nil)
        #expect(Self.isUntrusted(Self.pinned([Fixture.dnsLeaf], hash: hash, serverName: "derp1b.example.test")))
    }

    /// Go omits SNI for IP literals (`hostnameInSNI`), and pinning skips name verification when the SNI name is empty.
    @Test("Pinning skips name verification when hostName is an IP literal (as Go does)")
    func pinnedIPLiteralSkipsName() {
        #expect(Self.pinned([Fixture.ipLeaf], serverName: "127.0.0.1") == nil)
        #expect(Self.pinned([Fixture.ipLeaf], serverName: "::1") == nil)
    }

    // MARK: Named verification

    @Test("Named verification validates the chain against the test anchor and checks the name against certName, even if a meta certificate is present")
    func namedMatches() {
        #expect(Self.named([Fixture.namedLeaf]) == nil)
        #expect(Self.named([Fixture.namedLeaf, Fixture.meta]) == nil)
    }

    @Test("Named verification fails for a different name, a missing anchor (the system store lacks the test root), or a self-signed certificate")
    func namedRejects() {
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], name: "derp1a.example.test")))
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], anchors: nil)))
        #expect(Self.isUntrusted(Self.named([Fixture.dnsLeaf], name: "derp1a.example.test")))
        #expect(Self.named([]) == .unparsable)
    }

    // MARK: SNI name

    @Test("The SNI name follows Go hostnameInSNI: it is absent for IP literals (including brackets and zones) and has trailing dots stripped")
    func sniHostName() {
        #expect(ServerCertificate.sniHostName("100.64.0.1") == nil)
        #expect(ServerCertificate.sniHostName("fd7a:115c:a1e0::1") == nil)
        #expect(ServerCertificate.sniHostName("[fd7a:115c:a1e0::1]") == nil)
        #expect(ServerCertificate.sniHostName("fe80::1%en0") == nil)
        #expect(ServerCertificate.sniHostName("derp1a.example.test") == "derp1a.example.test")
        #expect(ServerCertificate.sniHostName("derp1a.example.test..") == "derp1a.example.test")
        #expect(ServerCertificate.sniHostName("") == nil)
    }
}
