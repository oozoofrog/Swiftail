// 계약 동작 R4·X5·C4·C8·K, H16: 발급 실패의 기록과 다음 시도, `retryNow()`, 계정 키, 취소, 비밀.

import CryptoKit
import Foundation
import Security
import Testing

import Swiftail
@testable import SwiftailCertificates
import SwiftailControl

private typealias H = ManagerHarness

@Suite("인증서 관리자: 실패·다시 시도·취소·비밀", .enabled(if: ManagerScratch.root != nil, "SWIFTAIL_TEST_SCRATCH가 없다"),
       .timeLimit(.minutes(1)))
struct ManagerFailureTests {
    struct FailureCase: Sendable, CustomTestStringConvertible {
        var testDescription: String
        /// set-dns가 던질 오류.
        var dnsError: ControlError?
        /// 대본을 만든다.
        var script: @Sendable (ManagerHarness) -> [ScriptedTransport.Entry]
        var expected: @Sendable (CertificateFailure) -> Bool
        /// 다음 시도까지의 간격. nil이면 조건을 기다린다.
        var delay: TimeInterval?
    }

    /// newOrder에서 set-dns 직전까지(authorization을 읽는다).
    private static func untilTXT(_ h: ManagerHarness) -> [ScriptedTransport.Entry] {
        (Steps.accountFound + [Steps.newOrder(Body.order("pending")), .post(Fake.authorizationURL(1), 200, Body.authorization("pending"))])
            .map { ScriptedTransport.Entry(exchange: $0) }
    }

    static let failureCases: [FailureCase] = [
        .init(testDescription: "set-dns 403", dnsError: .http(status: 403), script: untilTXT,
              expected: { $0 == .controlRejected(status: 403) }, delay: 30),
        .init(testDescription: "set-dns 연결 실패", dnsError: .connection("기한"), script: untilTXT,
              expected: { if case .network = $0 { true } else { false } }, delay: 30),
        .init(testDescription: "set-dns 이름 거절", dnsError: .invalidConfiguration("이름"), script: untilTXT,
              expected: { $0 == .domainNotAllowed }, delay: nil),
        .init(testDescription: "ACME 400 badCSR", script: { $0.failingOrder(.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badCSR")))) },
              expected: { $0 == .acme(status: 400, type: Fake.problem("badCSR")) }, delay: 15 * 60),
        .init(testDescription: "ACME 503", script: { $0.failingOrder(.post(Fake.newOrderURL, 503, [])) },
              expected: { $0 == .acme(status: 503, type: "") }, delay: 30),
        .init(testDescription: "ACME rateLimited와 Retry-After 2시간",
              script: { $0.failingOrder(.post(Fake.newOrderURL, 429, Body.problem(Fake.problem("rateLimited"), status: 429))
                  .header("Retry-After", "7200")) },
              expected: { $0 == .rateLimited(retryAfter: TestPKI.now + 7200) }, delay: 7200),
        .init(testDescription: "authorization invalid",
              script: { _ in (Steps.accountFound + [
                  Steps.newOrder(Body.order("pending")),
                  .post(Fake.authorizationURL(1), 200, Body.authorization("invalid", challenges: [
                      Body.challenge(1, status: "invalid", errorType: Fake.problem("dns")),
                  ])),
              ]).map { ScriptedTransport.Entry(exchange: $0) } },
              expected: { if case .validationFailed = $0 { true } else { false } }, delay: 15 * 60),
        .init(testDescription: "다른 키의 leaf", script: { $0.issuance(leafKey: P256.Signing.PrivateKey().publicKey) },
              expected: { $0 == .invalidCertificate }, delay: 6 * 3600),
        .init(testDescription: "다른 이름의 leaf", script: { $0.issuance(leafName: "rd-mac-9z8y7x6w.tail0001.ts.net") },
              expected: { $0 == .invalidCertificate }, delay: 6 * 3600),
    ]

    @Test("실패는 status에 적고, 표의 간격으로 다음 시도를 정하고, 저장하지도 내지도 않는다", arguments: failureCases)
    func failure(_ failure: FailureCase) async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.dns.fail(with: failure.dnsError)
        h.transport.append(failure.script(h))
        let run = h.start()

        try await eventually { await h.status().lastFailure.map(failure.expected) == true }
        try await eventually { h.transport.remaining == 0 }
        let next = failure.delay.map { TestPKI.now + $0 }
        try await eventually { await h.status().nextAttempt == next && h.clock.deadlines == (next.map { [$0] } ?? []) }
        #expect(await h.status().notAfter == nil)
        #expect(!h.scratch.exists(H.name + ".crt"), "실패한 시도는 아무것도 저장하지 않는다")
        #expect(!h.scratch.exists(H.name + ".key"))

        run.cancel()
        #expect(await run.value == nil)
        #expect(await drain(h.manager.certificates).isEmpty, "실패한 시도는 아무것도 내지 않는다")
    }

    @Test("Retry-After 전의 retryNow()는 요청을 보내지 않고, 그 시각이 되면 다시 시도한다")
    func retryNowBeforeRetryAfter() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.failingOrder(.post(Fake.newOrderURL, 429, Body.problem(Fake.problem("rateLimited"), status: 429))
            .header("Retry-After", "7200")))
        let run = h.start()

        let retryAt = TestPKI.now + 7200
        try await eventually { h.clock.deadlines == [retryAt] }
        let sent = h.transport.sent.count
        h.clock.advance(by: 3600)
        await h.manager.retryNow()
        try await settle()
        #expect(h.transport.sent.count == sent, "서버가 정한 시각 전에는 retryNow()도 요청하지 않는다")
        #expect(await h.status().nextAttempt == retryAt)

        h.transport.append(h.issuance(firstAttempt: false))
        h.clock.advance(to: retryAt)
        try await eventually { await h.status().notAfter == retryAt + H.lifetime }
        #expect(h.transport.sent.allSatisfy { $0.time < TestPKI.now + 1 || $0.time >= retryAt })
        #expect(await h.status().lastFailure == nil)

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("물러나는 중의 retryNow()는 곧바로 다시 시도한다")
    func retryNowDuringBackoff() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.dns.fail(with: .connection("끊김"))
        h.transport.append(Self.untilTXT(h))
        let run = h.start()

        try await eventually { await h.status().nextAttempt == TestPKI.now + 30 }
        h.dns.fail(with: nil)
        h.transport.append(h.issuance(firstAttempt: false))
        await h.manager.retryNow()
        try await eventually { await h.status().notAfter != nil }
        #expect(h.clock.now() == TestPKI.now, "시각을 넘기지 않고 다시 시도했다")

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("사용자가 고칠 실패 뒤: 시간으로는 다시 시도하지 않고 retryNow()에 곧바로 다시 본다")
    func retryNowAfterUserFixableFailure() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.dns.fail(with: .invalidConfiguration("이름"))
        h.transport.append(Self.untilTXT(h))
        let run = h.start()

        try await eventually { await h.status().lastFailure == .domainNotAllowed && h.transport.remaining == 0 }
        h.clock.advance(by: 7 * H.day)
        try await settle()
        #expect(h.dns.calls.count == 1)
        #expect(await h.status().nextAttempt == nil)

        h.dns.fail(with: nil)
        h.transport.append(h.issuance(firstAttempt: false))
        await h.manager.retryNow()
        try await eventually { await h.status().notAfter != nil }
        #expect(h.dns.calls.count == 2)

        run.cancel()
        #expect(await run.value == nil)
    }

    enum AccountKeyCase: String, CaseIterable, Sendable {
        case corrupt, rsa

        var bytes: [UInt8] {
            get throws {
                switch self {
                case .corrupt:
                    return Array("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n".utf8)
                case .rsa:
                    // Go의 옛 RSA 계정 키(PKCS#1 `RSA PRIVATE KEY`).
                    let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
                    let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
                    let der = try #require(SecKeyCopyExternalRepresentation(key, nil) as Data?)
                    let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
                    return Array("-----BEGIN RSA PRIVATE KEY-----\n\(body)\n-----END RSA PRIVATE KEY-----\n".utf8)
                }
            }
        }
    }

    @Test("계정 키 파일이 깨졌거나 RSA면 run()이 accountKeyUnreadable로 끝나고 파일은 그대로다", arguments: AccountKeyCase.allCases)
    func unreadableAccountKey(_ keyCase: AccountKeyCase) async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let bytes = try keyCase.bytes
        try h.scratch.put(bytes, "acme-account.key.pem")
        let run = h.start()

        #expect(await run.value == .accountKeyUnreadable)
        #expect(try h.scratch.contents("acme-account.key.pem") == bytes)
        #expect(h.transport.sent.isEmpty)
        #expect(await drain(h.manager.certificates).isEmpty)
    }

    @Test("잠든 중에 취소하면 곧 돌아오고 요청이 더 가지 않는다")
    func cancelWhileSleeping() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()
        try await eventually { h.clock.deadlines.count == 1 }
        let sent = h.transport.sent.count

        run.cancel()
        #expect(await run.value == nil)
        #expect(h.clock.deadlines.isEmpty, "기다림이 취소로 풀렸다")
        h.clock.advance(by: 100 * H.day)
        try await settle()
        #expect(h.transport.sent.count == sent)
    }

    @Test("발급 중에 취소하면 곧 돌아오고 요청이 더 가지 않는다")
    func cancelWhileIssuing() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(Steps.accountFound.map { ScriptedTransport.Entry(exchange: $0) } + [
            ScriptedTransport.Entry(exchange: Steps.newOrder(Body.order("ready")), hangs: true),
            ScriptedTransport.Entry(exchange: Steps.finalizeValid),
        ])
        let run = h.start()
        try await eventually { h.transport.sent.count == 4 }

        run.cancel()
        #expect(await run.value == nil)
        try await settle()
        #expect(h.transport.sent.count == 4)
        #expect(await h.status().lastFailure == nil, "취소는 실패로 적지 않는다")
    }

    @Test("run()은 한 번만, 디렉터리 URL은 https만")
    func invalidConfiguration() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let run = h.start(with: H.facts(running: false))
        try await eventually { await h.status().lastFailure == .nodeNotRunning }
        await #expect(throws: CertificateError.invalidConfiguration("run()은 한 번만 부를 수 있다")) {
            try await h.manager.run()
        }
        run.cancel()
        _ = await run.value

        let (facts, _) = AsyncStream.makeStream(of: CertificateFacts.self)
        for url in ["http://acme.invalid/directory", "file:///directory"] {
            #expect(throws: CertificateError.self) {
                try CertificateManager(
                    facts: facts, setDNS: { _, _ in }, stateDirectory: h.scratch.url, transport: h.transport,
                    configuration: CertificateConfiguration(directoryURL: try #require(URL(string: url)))
                )
            }
        }
    }

    @Test("description·dump·String(reflecting:)에 키 바이트와 계정 URL이 없다")
    func secrets() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()
        var certificates = h.manager.certificates.makeAsyncIterator()
        let certificate = try #require(await certificates.next())
        let accountKeyFile = try h.scratch.contents("acme-account.key.pem")
        let accountKey = try P256.Signing.PrivateKey(pemRepresentation: String(decoding: accountKeyFile, as: UTF8.self))
        let status = await h.status()

        var secrets: [String] = [Fake.accountURL]
        for key in [certificate.privateKey, accountKey] {
            let raw = key.rawRepresentation
            secrets += [
                raw.map { String(format: "%02x", $0) }.joined(), raw.base64EncodedString(), Base64URL.encode(raw),
                key.x963Representation.base64EncodedString(), "\(Array(raw))",
            ]
            secrets += key.pemRepresentation.split(separator: "\n").dropFirst().dropLast().map(String.init)
        }
        for text in Self.renderings(certificate) + Self.renderings(h.manager) + Self.renderings(status) {
            for secret in secrets {
                #expect(!text.contains(secret))
            }
        }
        #expect(certificate.description.contains(H.name))
        #expect(!Self.renderings(h.manager).joined().contains(H.name))

        run.cancel()
        _ = await run.value
    }

    private static func renderings(_ value: Any) -> [String] {
        var dumped = ""
        dump(value, to: &dumped)
        return [String(describing: value), String(reflecting: value), dumped]
    }
}

@Suite("인증서 관리자: 조건과 실패의 분류")
struct ManagerMappingTests {
    @Test("동작 C1·C2: 조건을 차례로 본다")
    func eligibility() throws {
        let domain = try #require(CertificateDomain(H.name))
        #expect(CertificateManager.eligibility(of: H.facts()) == .eligible(domain))
        #expect(CertificateManager.eligibility(of: H.facts(fqdn: H.name + ".", certDomains: [H.name + "."])) == .eligible(domain),
                "끝 점 하나는 떼고 검사한다")
        #expect(CertificateManager.eligibility(of: H.facts(running: false)) == .blocked(.nodeNotRunning))
        #expect(CertificateManager.eligibility(of: H.facts(magicDNS: false)) == .blocked(.magicDNSDisabled))
        #expect(CertificateManager.eligibility(of: H.facts(certDomains: [])) == .blocked(.httpsNotEnabled))
        #expect(CertificateManager.eligibility(of: H.facts(certDomains: ["tail0001.ts.net"])) == .blocked(.domainNotAllowed))
        #expect(CertificateManager.eligibility(of: H.facts(fqdn: "a_b.tail0001.ts.net", certDomains: ["a_b.tail0001.ts.net"]))
                == .blocked(.domainNotAllowed))
    }

    @Test("set-dns의 실패: http → controlRejected, invalidConfiguration → domainNotAllowed, 그 밖 → network")
    func controlErrors() {
        #expect(CertificateManager.failure(for: .http(status: 500)) == .controlRejected(status: 500))
        #expect(CertificateManager.failure(for: .invalidConfiguration("x")) == .domainNotAllowed)
        for error in [ControlError.connection("x"), .storage("x"), .nodeKeyExpired] {
            guard case .network(let message) = CertificateManager.failure(for: error) else {
                Issue.record("network가 아니다")
                continue
            }
            #expect(!message.contains("x"), "연관 문자열은 고정 문구다")
        }
    }

    @Test("동작 R4 표: CertificateFailure → RenewalFailure")
    func renewalFailures() {
        let date = TestPKI.now
        let table: [(CertificateFailure, RenewalFailure, Date?)] = [
            (.magicDNSDisabled, .needsUserAction, nil), (.httpsNotEnabled, .needsUserAction, nil),
            (.domainNotAllowed, .needsUserAction, nil), (.nodeNotRunning, .nodeNotRunning, nil),
            (.network("x"), .unreachable, nil), (.timedOut, .unreachable, nil), (.controlRejected(status: 403), .unreachable, nil),
            (.acme(status: 500, type: ""), .unreachable, nil), (.acme(status: 599, type: ""), .unreachable, nil),
            (.acme(status: 400, type: ""), .rejected, nil), (.acme(status: 600, type: ""), .rejected, nil),
            (.validationFailed(type: ""), .rejected, nil), (.orderFailed(type: ""), .rejected, nil),
            (.unexpectedResponse, .rejected, nil), (.rateLimited(retryAfter: date), .rateLimited, date),
            (.rateLimited(retryAfter: nil), .rateLimited, nil), (.invalidCertificate, .invalidCertificate, nil),
        ]
        for (failure, expected, retryAfter) in table {
            let mapped = CertificateManager.renewalFailure(for: failure)
            #expect(mapped.0 == expected, "\(failure)")
            #expect(mapped.retryAfter == retryAfter, "\(failure)")
        }
    }
}
