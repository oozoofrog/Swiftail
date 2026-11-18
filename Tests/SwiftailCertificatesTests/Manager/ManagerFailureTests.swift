// Contract behaviors R4, X5, C4, C8, and K, and H16: recording issuance failures, the next attempt, `retryNow()`, the account key, cancellation, and secrets.

import CryptoKit
import Foundation
import Security
import Testing

import Swiftail
@testable import SwiftailCertificates
import SwiftailControl

private typealias H = ManagerHarness

@Suite("Certificate manager: failures, retries, cancellation, and secrets", .enabled(if: ManagerScratch.root != nil, "SWIFTAIL_TEST_SCRATCH is missing"),
       .timeLimit(.minutes(1)))
struct ManagerFailureTests {
    struct FailureCase: Sendable, CustomTestStringConvertible {
        var testDescription: String
        /// The error set-dns throws.
        var dnsError: ControlError?
        /// Builds the script.
        var script: @Sendable (ManagerHarness) -> [ScriptedTransport.Entry]
        var expected: @Sendable (CertificateFailure) -> Bool
        /// The interval until the next attempt. A nil value waits for the condition.
        var delay: TimeInterval?
    }

    /// From newOrder up to set-dns, reading the authorization along the way.
    private static func untilTXT(_ h: ManagerHarness) -> [ScriptedTransport.Entry] {
        (Steps.accountFound + [Steps.newOrder(Body.order("pending")), .post(Fake.authorizationURL(1), 200, Body.authorization("pending"))])
            .map { ScriptedTransport.Entry(exchange: $0) }
    }

    static let failureCases: [FailureCase] = [
        .init(testDescription: "set-dns 403", dnsError: .http(status: 403), script: untilTXT,
              expected: { $0 == .controlRejected(status: 403) }, delay: 30),
        .init(testDescription: "set-dns connection failure", dnsError: .connection("deadline"), script: untilTXT,
              expected: { if case .network = $0 { true } else { false } }, delay: 30),
        .init(testDescription: "set-dns name rejection", dnsError: .invalidConfiguration("name"), script: untilTXT,
              expected: { $0 == .domainNotAllowed }, delay: nil),
        .init(testDescription: "ACME 400 badCSR", script: { $0.failingOrder(.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badCSR")))) },
              expected: { $0 == .acme(status: 400, type: Fake.problem("badCSR")) }, delay: 15 * 60),
        .init(testDescription: "ACME 503", script: { $0.failingOrder(.post(Fake.newOrderURL, 503, [])) },
              expected: { $0 == .acme(status: 503, type: "") }, delay: 30),
        .init(testDescription: "ACME rateLimited with Retry-After of 2 hours",
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
        .init(testDescription: "Leaf with a different key", script: { $0.issuance(leafKey: P256.Signing.PrivateKey().publicKey) },
              expected: { $0 == .invalidCertificate }, delay: 6 * 3600),
        .init(testDescription: "Leaf with a different name", script: { $0.issuance(leafName: "rd-mac-9z8y7x6w.tail0001.ts.net") },
              expected: { $0 == .invalidCertificate }, delay: 6 * 3600),
    ]

    @Test("Records a failure in status, schedules the next attempt at the interval from the table, and stores and emits nothing", arguments: failureCases)
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
        #expect(!h.scratch.exists(H.name + ".crt"), "A failed attempt stores nothing")
        #expect(!h.scratch.exists(H.name + ".key"))

        run.cancel()
        #expect(await run.value == nil)
        #expect(await drain(h.manager.certificates).isEmpty, "A failed attempt emits nothing")
    }

    @Test("retryNow() before Retry-After sends no request and retries when that time arrives")
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
        #expect(h.transport.sent.count == sent, "Even retryNow() sends no request before the server's time")
        #expect(await h.status().nextAttempt == retryAt)

        h.transport.append(h.issuance(firstAttempt: false))
        h.clock.advance(to: retryAt)
        try await eventually { await h.status().notAfter == retryAt + H.lifetime }
        #expect(h.transport.sent.allSatisfy { $0.time < TestPKI.now + 1 || $0.time >= retryAt })
        #expect(await h.status().lastFailure == nil)

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("retryNow() retries immediately during backoff")
    func retryNowDuringBackoff() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.dns.fail(with: .connection("disconnected"))
        h.transport.append(Self.untilTXT(h))
        let run = h.start()

        try await eventually { await h.status().nextAttempt == TestPKI.now + 30 }
        h.dns.fail(with: nil)
        h.transport.append(h.issuance(firstAttempt: false))
        await h.manager.retryNow()
        try await eventually { await h.status().notAfter != nil }
        #expect(h.clock.now() == TestPKI.now, "Retried without advancing time")

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("After a failure the user must fix, waits without retrying on a timer and re-evaluates immediately on retryNow()")
    func retryNowAfterUserFixableFailure() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.dns.fail(with: .invalidConfiguration("name"))
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
                    // Go's old RSA account key (PKCS#1 `RSA PRIVATE KEY`).
                    let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
                    let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
                    let der = try #require(SecKeyCopyExternalRepresentation(key, nil) as Data?)
                    let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
                    return Array("-----BEGIN RSA PRIVATE KEY-----\n\(body)\n-----END RSA PRIVATE KEY-----\n".utf8)
                }
            }
        }
    }

    @Test("A corrupt or RSA account key file makes run() end with accountKeyUnreadable and preserves the file", arguments: AccountKeyCase.allCases)
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

    @Test("Canceling while asleep returns promptly and sends no more requests")
    func cancelWhileSleeping() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()
        try await eventually { h.clock.deadlines.count == 1 }
        let sent = h.transport.sent.count

        run.cancel()
        #expect(await run.value == nil)
        #expect(h.clock.deadlines.isEmpty, "Cancellation released the wait")
        h.clock.advance(by: 100 * H.day)
        try await settle()
        #expect(h.transport.sent.count == sent)
    }

    @Test("Canceling during issuance returns promptly and sends no more requests")
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
        #expect(await h.status().lastFailure == nil, "Cancellation is not recorded as a failure")
    }

    @Test("run() can be called once, and the directory URL requires https")
    func invalidConfiguration() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let run = h.start(with: H.facts(running: false))
        try await eventually { await h.status().lastFailure == .nodeNotRunning }
        await #expect(throws: CertificateError.invalidConfiguration("run() can only be called once")) {
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

    @Test("Configured trustAnchors verify with the supplied root and complete issuance. Without them, a chain the system does not trust is not stored")
    func configuredTrustAnchors() async throws {
        let trusted = try ManagerHarness(anchors: .configuration)
        defer { trusted.scratch.remove() }
        trusted.transport.append(trusted.issuance())
        let trustedRun = trusted.start()
        try await eventually { await trusted.status().notAfter != nil }
        #expect(await trusted.status().lastFailure == nil)
        trustedRun.cancel()
        _ = await trustedRun.value

        let system = try ManagerHarness(anchors: .none)
        defer { system.scratch.remove() }
        system.transport.append(system.issuance())
        let systemRun = system.start()
        try await eventually { await system.status().lastFailure == .invalidCertificate }
        #expect(await system.status().notAfter == nil)
        #expect(throws: (any Error).self) { try system.scratch.contents(H.name + ".crt") }
        systemRun.cancel()
        _ = await systemRun.value
    }

    @Test("Empty trustAnchors are rejected")
    func emptyTrustAnchors() throws {
        let scratch = try ManagerScratch()
        defer { scratch.remove() }
        let (facts, _) = AsyncStream.makeStream(of: CertificateFacts.self)
        #expect(throws: CertificateError.self) {
            try CertificateManager(
                facts: facts, setDNS: { _, _ in }, stateDirectory: scratch.url, transport: ScriptedTransport(clock: TestClock(TestPKI.now)),
                configuration: CertificateConfiguration(directoryURL: try #require(URL(string: Fake.directoryURL)), trustAnchors: [])
            )
        }
    }

    @Test("description, dump, and String(reflecting:) omit key bytes and the account URL")
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
        #expect(certificate.domain == H.name)
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

@Suite("Certificate manager: classification of conditions and failures")
struct ManagerMappingTests {
    @Test("Behaviors C1 and C2 check conditions in order")
    func eligibility() throws {
        let domain = try #require(CertificateDomain(H.name))
        #expect(CertificateManager.eligibility(of: H.facts()) == .eligible(domain))
        #expect(CertificateManager.eligibility(of: H.facts(fqdn: H.name + ".", certDomains: [H.name + "."])) == .eligible(domain),
                "Removes one trailing dot before validation")
        #expect(CertificateManager.eligibility(of: H.facts(running: false)) == .blocked(.nodeNotRunning))
        #expect(CertificateManager.eligibility(of: H.facts(magicDNS: false)) == .blocked(.magicDNSDisabled))
        #expect(CertificateManager.eligibility(of: H.facts(certDomains: [])) == .blocked(.httpsNotEnabled))
        #expect(CertificateManager.eligibility(of: H.facts(certDomains: ["tail0001.ts.net"])) == .blocked(.domainNotAllowed))
        #expect(CertificateManager.eligibility(of: H.facts(fqdn: "a_b.tail0001.ts.net", certDomains: ["a_b.tail0001.ts.net"]))
                == .blocked(.domainNotAllowed))
    }

    @Test("set-dns failures: http → controlRejected, invalidConfiguration → domainNotAllowed, and all others → network")
    func controlErrors() {
        #expect(CertificateManager.failure(for: .http(status: 500)) == .controlRejected(status: 500))
        #expect(CertificateManager.failure(for: .invalidConfiguration("x")) == .domainNotAllowed)
        for error in [ControlError.connection("x"), .storage("x"), .nodeKeyExpired] {
            guard case .network(let message) = CertificateManager.failure(for: error) else {
                Issue.record("Expected network")
                continue
            }
            #expect(!message.contains("x"), "The associated string is fixed")
        }
    }

    @Test("Behavior R4 table: CertificateFailure → RenewalFailure")
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
