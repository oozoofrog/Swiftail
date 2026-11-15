import Foundation
import Testing

@testable import SwiftailIO

/// DERP 인증서 고정·이름 판정(계약 `docs/contracts/SwiftailDERP.md` "M8 ③" 동작 V 2·4). 연결 없이 고정 인증서로 본다.
@Suite("서버 인증서 판정")
struct ServerCertificateTests {
    private typealias Fixture = ServerCertificateFixtures

    /// 고정 인증서들의 유효 기간 안.
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

    // MARK: 고정

    @Test("고정: derper의 IP 자체 서명 인증서가 해시로 맞고, meta 인증서는 어느 자리에 있어도 세지 않는다")
    func pinnedMatches() {
        #expect(Self.pinned([Fixture.ipLeaf]) == nil)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta]) == nil)
        // Go는 받는다. 첫 자리(TLS가 키를 증명한 자리)가 meta 모양이면 고정이 키 소유를 증명하지 못하므로 받지 않는다.
        #expect(Self.pinned([Fixture.meta, Fixture.ipLeaf]) == .candidateNotLeaf)
    }

    @Test("고정: 해시가 다르면 실패한다. 대문자로 쓴 같은 해시도, 서버가 함께 낸 meta 인증서의 해시도 맞지 않는다")
    func pinnedHashMismatch() {
        #expect(Self.pinned([Fixture.otherIPLeaf]) == .hashMismatch)
        #expect(Self.pinned([Fixture.ipLeaf], hash: Fixture.ipLeafSHA256.uppercased()) == .hashMismatch)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta], hash: Fixture.metaSHA256) == .hashMismatch)
        #expect(Self.pinned([Fixture.ipLeaf], hash: "") == .hashMismatch)
    }

    @Test("고정: meta가 아닌 인증서가 둘이면(같은 것 둘 포함) 실패하고, 하나도 없으면 실패한다")
    func pinnedCount() {
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.otherIPLeaf]) == .multipleCandidates)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta, Fixture.otherIPLeaf]) == .multipleCandidates)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.ipLeaf]) == .multipleCandidates)
        #expect(Self.pinned([Fixture.meta]) == .noCandidate)
        #expect(Self.pinned([]) == .unparsable)
        #expect(Self.pinned([Fixture.ipLeaf, [0x30, 0x03, 0x02, 0x01, 0x00]]) == .unparsable)
    }

    @Test("고정: 유효 기간 밖(지남, 아직 아님)이면 실패한다")
    func pinnedValidity() {
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Date(timeIntervalSince1970: 1_801_440_000)))) // 2027-02-01
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Date(timeIntervalSince1970: 1_764_547_200)))) // 2025-12-01
    }

    @Test("고정: SNI로 나가는 이름이면 인증서가 그 이름에 유효해야 한다. 끝의 점은 뗀다")
    func pinnedHostName() {
        let hash = Fixture.dnsLeafSHA256
        #expect(Self.pinned([Fixture.dnsLeaf], hash: hash, serverName: "derp1a.example.test") == nil)
        #expect(Self.pinned([Fixture.dnsLeaf], hash: hash, serverName: "derp1a.example.test.") == nil)
        #expect(Self.isUntrusted(Self.pinned([Fixture.dnsLeaf], hash: hash, serverName: "derp1b.example.test")))
    }

    /// Go는 IP 리터럴에 SNI를 보내지 않고(`hostnameInSNI`), 고정 판정은 SNI 이름이 비면 이름을 보지 않는다.
    @Test("고정: hostName이 IP 리터럴이면 이름을 보지 않는다(Go와 같다)")
    func pinnedIPLiteralSkipsName() {
        #expect(Self.pinned([Fixture.ipLeaf], serverName: "127.0.0.1") == nil)
        #expect(Self.pinned([Fixture.ipLeaf], serverName: "::1") == nil)
    }

    // MARK: 이름

    @Test("이름: 시험 앵커로 사슬을 검증하고 certName으로 이름을 본다. meta 인증서가 섞여도 된다")
    func namedMatches() {
        #expect(Self.named([Fixture.namedLeaf]) == nil)
        #expect(Self.named([Fixture.namedLeaf, Fixture.meta]) == nil)
    }

    @Test("이름: 이름이 다르거나, 앵커가 없거나(시스템 저장소에 시험 루트가 없다), 자체 서명이면 실패한다")
    func namedRejects() {
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], name: "derp1a.example.test")))
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], anchors: nil)))
        #expect(Self.isUntrusted(Self.named([Fixture.dnsLeaf], name: "derp1a.example.test")))
        #expect(Self.named([]) == .unparsable)
    }

    // MARK: SNI 이름

    @Test("SNI 이름은 Go hostnameInSNI와 같다: IP 리터럴(괄호·범위 포함)은 없고 끝의 점은 뗀다")
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
