// 계약 7절 단위 시험 8(관리자의 몫)·10·12와 동작 C1~C3·C8~C11, S4, R, K: `CertificateManager`를 노드 없이 가짜 접점과
// 넘기는 시계로 돌린다.

import CryptoKit
import Foundation
import Testing

import Swiftail
@testable import SwiftailCertificates
import SwiftailControl

private typealias H = ManagerHarness

@Suite("인증서 관리자: 조건·저장된 것·발급·갱신", .enabled(if: ManagerScratch.root != nil, "SWIFTAIL_TEST_SCRATCH가 없다"),
       .timeLimit(.minutes(1)))
struct ManagerTests {
    struct ConditionCase: Sendable, CustomTestStringConvertible {
        var testDescription: String
        var facts: CertificateFacts
        var failure: CertificateFailure
    }

    static let conditionCases: [ConditionCase] = [
        // C1의 차례: 앞의 조건이 먼저다.
        .init(testDescription: "실행 전", facts: H.facts(running: false, certDomains: [], magicDNS: false), failure: .nodeNotRunning),
        .init(testDescription: "MagicDNS 꺼짐", facts: H.facts(certDomains: [], magicDNS: false), failure: .magicDNSDisabled),
        .init(testDescription: "HTTPS 꺼짐", facts: H.facts(certDomains: []), failure: .httpsNotEnabled),
        .init(testDescription: "이름이 cert 도메인에 없음", facts: H.facts(certDomains: ["rd-mac-9z8y7x6w.tail0001.ts.net"]),
              failure: .domainNotAllowed),
        .init(testDescription: "이름을 모름", facts: H.facts(fqdn: nil), failure: .domainNotAllowed),
        .init(testDescription: "이름 검사 실패(대문자)",
              facts: H.facts(fqdn: "RD-mac-1a2b3c4d.tail0001.ts.net", certDomains: ["RD-mac-1a2b3c4d.tail0001.ts.net"]),
              failure: .domainNotAllowed),
    ]

    @Test("조건이 맞지 않으면 status에 적고 시간으로 다시 시도하지 않으며, 사실이 바뀌면 깨어나 발급한다",
          arguments: conditionCases)
    func unmetCondition(_ condition: ConditionCase) async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let run = h.start(with: condition.facts)

        try await eventually { await h.status().lastFailure == condition.failure }
        let status = await h.status()
        #expect(status.nextAttempt == nil)
        #expect(status.domain == condition.facts.fqdn)
        #expect(status.notAfter == nil)

        h.clock.advance(by: 30 * H.day)
        try await settle()
        #expect(h.transport.sent.isEmpty)
        #expect(h.dns.calls.isEmpty)
        #expect(h.clock.deadlines.isEmpty, "시간으로 깨어날 기다림이 없어야 한다")
        #expect(await h.status().lastFailure == condition.failure)

        h.transport.append(h.issuance())
        h.send(H.facts())
        try await eventually { await h.status().notAfter != nil }
        #expect(await h.status().lastFailure == nil)
        #expect(h.transport.remaining == 0)

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("저장된 유효한 인증서: 요청 없이 certificates에 나오고 2/3 지점까지 잔다")
    func storedCertificate() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let key = P256.Signing.PrivateKey()
        try h.storeCertificate(key: key, from: TestPKI.now - 10 * H.day, to: TestPKI.now + 80 * H.day)
        let run = h.start()

        var certificates = h.manager.certificates.makeAsyncIterator()
        let certificate = try #require(await certificates.next())
        #expect(certificate.domain == H.name)
        #expect(certificate.privateKey.rawRepresentation == key.rawRepresentation)
        #expect(certificate.notAfter == TestPKI.now + 80 * H.day)

        let renewal = TestPKI.now + 50 * H.day
        try await eventually { h.clock.deadlines == [renewal] }
        let status = await h.status()
        #expect(status == CertificateStatus(domain: H.name, notAfter: TestPKI.now + 80 * H.day, lastFailure: nil, nextAttempt: renewal))
        #expect(h.transport.sent.isEmpty, "저장된 것이 유효하면 ACME 요청이 없다")
        #expect(h.dns.calls.isEmpty)

        run.cancel()
        #expect(await run.value == nil)
    }

    enum StoredProblem: String, CaseIterable, Sendable {
        case expired, otherName, keyMismatch
    }

    @Test("저장된 것이 만료·이름 불일치·키 짝 어긋남이면 새로 발급한다", arguments: StoredProblem.allCases)
    func storedCertificateUnusable(_ problem: StoredProblem) async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        switch problem {
        case .expired:
            try h.storeCertificate(from: TestPKI.now - 100 * H.day, to: TestPKI.now - 10 * H.day)
        case .otherName:
            try h.storeCertificate(name: "rd-mac-9z8y7x6w.tail0001.ts.net", from: TestPKI.now - H.day, to: TestPKI.now + 89 * H.day)
        case .keyMismatch:
            try h.storeCertificate(pairedKey: P256.Signing.PrivateKey(), from: TestPKI.now - H.day, to: TestPKI.now + 89 * H.day)
        }
        h.transport.append(h.issuance())
        let run = h.start()

        var certificates = h.manager.certificates.makeAsyncIterator()
        let certificate = try #require(await certificates.next())
        #expect(certificate.notAfter == TestPKI.now + H.lifetime)
        #expect(certificate.privateKey.rawRepresentation == h.certificateKeys.last?.rawRepresentation)
        #expect(h.transport.remaining == 0)

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("처음 발급: 계정 키를 만들어 저장하고, set-dns에 올바른 이름·값을 올리고, 검증한 사슬을 저장한 뒤 낸다")
    func firstIssuance() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()

        var certificates = h.manager.certificates.makeAsyncIterator()
        let certificate = try #require(await certificates.next())

        // 계정 키: 새로 만들어 0600으로 저장했다. TXT 값은 그 키의 지문으로 만든 것이다(RFC 8555 8.4).
        let accountKeyFile = try h.scratch.contents("acme-account.key.pem")
        let accountKey = try P256.Signing.PrivateKey(pemRepresentation: String(decoding: accountKeyFile, as: UTF8.self))
        #expect(try h.scratch.mode("acme-account.key.pem") == 0o600)
        let value = KeyAuthorization(token: Fake.token(1), accountKey: JWK(accountKey.publicKey)).dns01TXTValue
        #expect(h.dns.calls.map(\.name) == ["_acme-challenge." + H.name])
        #expect(h.dns.calls.map(\.value) == [value])

        // 사슬과 키: 이번 시도의 인증서 키, leaf와 중간 인증서. 파일은 0600이고 키 파일이 그 키다.
        let key = try #require(h.certificateKeys.last)
        #expect(h.certificateKeys.count == 1)
        #expect(certificate.domain == H.name)
        #expect(certificate.privateKey.rawRepresentation == key.rawRepresentation)
        #expect(certificate.chain.count == 2)
        #expect(certificate.chain.last == h.pki.intermediate.certificate)
        #expect(certificate.notBefore == TestPKI.now)
        #expect(certificate.notAfter == TestPKI.now + H.lifetime)
        #expect(try h.scratch.mode(H.name + ".crt") == 0o600)
        #expect(try h.scratch.mode(H.name + ".key") == 0o600)
        let keyFile = try h.scratch.contents(H.name + ".key")
        #expect(try P256.Signing.PrivateKey(pemRepresentation: String(decoding: keyFile, as: UTF8.self)).rawRepresentation
                == key.rawRepresentation)

        let renewal = TestPKI.now + 60 * H.day
        try await eventually { h.clock.deadlines == [renewal] }
        #expect(await h.status() == CertificateStatus(domain: H.name, notAfter: TestPKI.now + H.lifetime, lastFailure: nil,
                                                     nextAttempt: renewal))
        #expect(h.transport.remaining == 0)

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("갱신: 2/3 지점에서 새 키로 다시 발급하고 계정 URL을 다시 쓴다. 느린 소비자는 가장 새것 하나만 받는다")
    func renewal() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()

        let renewal = TestPKI.now + 60 * H.day
        try await eventually { h.clock.deadlines == [renewal] }
        // 두 번째 시도는 아는 계정 URL로 곧바로 주문한다(newAccount가 대본에 없다).
        h.transport.append(h.issuance(firstAttempt: false))
        h.clock.advance(to: renewal)
        try await eventually { await h.status().notAfter == renewal + H.lifetime }
        try await eventually { h.clock.deadlines == [renewal + 60 * H.day] }

        run.cancel()
        #expect(await run.value == nil)
        let received = await drain(h.manager.certificates)
        #expect(received.map(\.notAfter) == [renewal + H.lifetime], "받아 가지 않은 것은 가장 새것 하나만 남는다")
        #expect(h.certificateKeys.count == 2)
        #expect(received.first?.privateKey.rawRepresentation == h.certificateKeys.last?.rawRepresentation)
        #expect(h.transport.sent.filter { $0.request.url == Fake.newAccountURL }.count == 1)
        #expect(h.transport.remaining == 0)
    }

    @Test("발급 중에 이름이 바뀌면 그 시도는 끝까지 가고, 다음 판정이 새 이름으로 발급한다(옛 파일은 남는다)")
    func nameChangesDuringIssuance() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let newName = "rd-mac-9z8y7x6w.tail0001.ts.net"
        h.dns.hold()
        h.transport.append(h.issuance())
        let run = h.start()

        try await eventually { h.dns.calls.count == 1 }
        h.transport.append(h.issuance(firstAttempt: false, orderName: newName, leafName: newName))
        h.send(H.facts(fqdn: newName, certDomains: [newName]))
        try await settle()
        h.dns.release()

        try await eventually { await h.status().domain == newName && h.transport.remaining == 0 }
        try await eventually { h.clock.deadlines.count == 1 }
        #expect(h.dns.calls.map(\.name) == ["_acme-challenge." + H.name, "_acme-challenge." + newName])
        #expect(h.scratch.exists(H.name + ".crt"), "옛 이름의 파일은 지우지 않는다(동작 S4)")
        #expect(h.scratch.exists(newName + ".crt"))

        run.cancel()
        #expect(await run.value == nil)
        #expect(await drain(h.manager.certificates).map(\.domain) == [newName])
    }

    @Test("발급 중에 이름이 바뀌어 set-dns가 이름을 거절해도, 바뀐 사실로 곧 다시 판정해 새 이름으로 발급한다")
    func rejectedNameAfterChange() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let newName = "rd-mac-9z8y7x6w.tail0001.ts.net"
        h.dns.hold()
        h.dns.fail(with: .invalidConfiguration("이름"))
        h.transport.append((Steps.accountFound + [
            Steps.newOrder(Body.order("pending")), .post(Fake.authorizationURL(1), 200, Body.authorization("pending")),
        ]).map { ScriptedTransport.Entry(exchange: $0) })
        let run = h.start()

        try await eventually { h.dns.calls.count == 1 }
        h.transport.append(h.issuance(firstAttempt: false, orderName: newName, leafName: newName))
        h.send(H.facts(fqdn: newName, certDomains: [newName]))
        try await settle()
        h.dns.fail(with: nil)
        h.dns.release()

        try await eventually { await h.status().notAfter != nil }
        #expect(await h.status().domain == newName)
        #expect(await h.status().lastFailure == nil)

        run.cancel()
        #expect(await run.value == nil)
    }
}
