// Contract §7 unit tests 8 (the manager's part), 10, and 12, and behaviors C1–C3, C8–C11, S4, R, and K. Runs `CertificateManager` without a node, using fake interfaces and
// a manually advanced clock.

import CryptoKit
import Foundation
import Testing

import Swiftail
@testable import SwiftailCertificates
import SwiftailControl

private typealias H = ManagerHarness

@Suite("Certificate manager: conditions, stored certificate, issuance, and renewal", .enabled(if: ManagerScratch.root != nil, "SWIFTAIL_TEST_SCRATCH is missing"),
       .timeLimit(.minutes(1)))
struct ManagerTests {
    struct ConditionCase: Sendable, CustomTestStringConvertible {
        var testDescription: String
        var facts: CertificateFacts
        var failure: CertificateFailure
    }

    static let conditionCases: [ConditionCase] = [
        // C1 order: earlier conditions take precedence.
        .init(testDescription: "Before running", facts: H.facts(running: false, certDomains: [], magicDNS: false), failure: .nodeNotRunning),
        .init(testDescription: "MagicDNS disabled", facts: H.facts(certDomains: [], magicDNS: false), failure: .magicDNSDisabled),
        .init(testDescription: "HTTPS disabled", facts: H.facts(certDomains: []), failure: .httpsNotEnabled),
        .init(testDescription: "Name absent from cert domains", facts: H.facts(certDomains: ["rd-mac-9z8y7x6w.tail0001.ts.net"]),
              failure: .domainNotAllowed),
        .init(testDescription: "Unknown name", facts: H.facts(fqdn: nil), failure: .domainNotAllowed),
        .init(testDescription: "Name validation failure (uppercase)",
              facts: H.facts(fqdn: "RD-mac-1a2b3c4d.tail0001.ts.net", certDomains: ["RD-mac-1a2b3c4d.tail0001.ts.net"]),
              failure: .domainNotAllowed),
    ]

    @Test("Records unmet conditions in status, does not retry on a timer, and wakes to issue when the facts change",
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
        #expect(h.clock.deadlines.isEmpty, "No wait should be scheduled to wake on a timer")
        #expect(await h.status().lastFailure == condition.failure)

        h.transport.append(h.issuance())
        h.send(H.facts())
        try await eventually { await h.status().notAfter != nil }
        #expect(await h.status().lastFailure == nil)
        #expect(h.transport.remaining == 0)

        run.cancel()
        #expect(await run.value == nil)
    }

    @Test("A valid stored certificate appears in certificates without a request and sleeps until the 2/3 point")
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
        #expect(h.transport.sent.isEmpty, "A valid stored certificate requires no ACME request")
        #expect(h.dns.calls.isEmpty)

        run.cancel()
        #expect(await run.value == nil)
    }

    enum StoredProblem: String, CaseIterable, Sendable {
        case expired, otherName, keyMismatch
    }

    @Test("Issues a new certificate if the stored certificate is expired, has a different name, or does not match the key", arguments: StoredProblem.allCases)
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

    @Test("First issuance creates and stores the account key, publishes the correct name and value with set-dns, then stores and emits the verified chain")
    func firstIssuance() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()

        var certificates = h.manager.certificates.makeAsyncIterator()
        let certificate = try #require(await certificates.next())

        // A new account key was generated and stored with mode 0600. The TXT value uses that key's thumbprint (RFC 8555 8.4).
        let accountKeyFile = try h.scratch.contents("acme-account.key.pem")
        let accountKey = try P256.Signing.PrivateKey(pemRepresentation: String(decoding: accountKeyFile, as: UTF8.self))
        #expect(try h.scratch.mode("acme-account.key.pem") == 0o600)
        let value = KeyAuthorization(token: Fake.token(1), accountKey: JWK(accountKey.publicKey)).dns01TXTValue
        #expect(h.dns.calls.map(\.name) == ["_acme-challenge." + H.name])
        #expect(h.dns.calls.map(\.value) == [value])

        // The chain and key use this attempt's certificate key, leaf, and intermediate. The files have mode 0600, and the key file contains that key.
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

    @Test("Renewal issues with a new key at the 2/3 point and reuses the account URL. A slow consumer receives only the newest certificate")
    func renewal() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        h.transport.append(h.issuance())
        let run = h.start()

        let renewal = TestPKI.now + 60 * H.day
        try await eventually { h.clock.deadlines == [renewal] }
        // The second attempt orders directly with the known account URL (the script has no newAccount).
        h.transport.append(h.issuance(firstAttempt: false))
        h.clock.advance(to: renewal)
        try await eventually { await h.status().notAfter == renewal + H.lifetime }
        try await eventually { h.clock.deadlines == [renewal + 60 * H.day] }

        run.cancel()
        #expect(await run.value == nil)
        let received = await drain(h.manager.certificates)
        #expect(received.map(\.notAfter) == [renewal + H.lifetime], "Only the newest unconsumed certificate remains")
        #expect(h.certificateKeys.count == 2)
        #expect(received.first?.privateKey.rawRepresentation == h.certificateKeys.last?.rawRepresentation)
        #expect(h.transport.sent.filter { $0.request.url == Fake.newAccountURL }.count == 1)
        #expect(h.transport.remaining == 0)
    }

    @Test("A name change during issuance lets that attempt finish. The next evaluation issues for the new name and leaves the old files")
    func nameChangesDuringIssuance() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let newName = "rd-mac-9z8y7x6w.tail0001.ts.net"
        h.dns.hold()
        h.transport.append(h.issuance())
        // Check every emitted certificate. The issuance that finished under the old name must be stored without being emitted.
        let emitted = Task { () -> [String] in
            var domains: [String] = []
            for await certificate in h.manager.certificates { domains.append(certificate.domain) }
            return domains
        }
        let run = h.start()

        try await eventually { h.dns.calls.count == 1 }
        h.transport.append(h.issuance(firstAttempt: false, orderName: newName, leafName: newName))
        h.send(H.facts(fqdn: newName, certDomains: [newName]))
        try await settle()
        h.dns.release()

        try await eventually { await h.status().domain == newName && h.transport.remaining == 0 }
        try await eventually { h.clock.deadlines.count == 1 }
        #expect(h.dns.calls.map(\.name) == ["_acme-challenge." + H.name, "_acme-challenge." + newName])
        #expect(h.scratch.exists(H.name + ".crt"), "Files for the old name are preserved (behavior S4)")
        #expect(h.scratch.exists(newName + ".crt"))

        run.cancel()
        #expect(await run.value == nil)
        #expect(await emitted.value == [newName])
    }

    @Test("If a name change during issuance causes set-dns to reject the name, re-evaluates the changed facts immediately and issues for the new name")
    func rejectedNameAfterChange() async throws {
        let h = try ManagerHarness()
        defer { h.scratch.remove() }
        let newName = "rd-mac-9z8y7x6w.tail0001.ts.net"
        h.dns.hold()
        h.dns.fail(with: .invalidConfiguration("name"))
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
