import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("Independent ACME issuance scenarios")
struct CertificateIssuanceScenarios {
    @Test
    func newAccountThenReuseAccountURL() async throws {
        let scenario = CertificateScenario()
        let first = try await scenario.run()
        let issued = try await verified(first, in: scenario, key: scenario.certificateKey)
        #expect(issued.chain.count == 2)
        #expect(issued.lifetime.notBefore == scenario.clock.now.addingTimeInterval(-60))
        #expect(issued.lifetime.notAfter == scenario.clock.now.addingTimeInterval(86400 * 30))
        let records = await scenario.server.records
        let accountRequests = records.filter { $0.endpoint == .account }
        #expect(accountRequests.map(\.status) == [400, 201])
        #expect(try JSONSerialization.jsonObject(with: #require(accountRequests.first?.payload)) as? [String: Bool]
            == ["onlyReturnExisting": true])
        #expect(try JSONSerialization.jsonObject(with: #require(accountRequests.last?.payload)) as? [String: Bool]
            == ["termsOfServiceAgreed": true])
        #expect(records.contains { $0.endpoint == .certificate && $0.payload?.isEmpty == true })
        #expect(scenario.dns.records.keys.sorted() == ["_acme-challenge." + FakeACMEServer.domain])
        let values = scenario.dns.lookup("_acme-challenge." + FakeACMEServer.domain)
        #expect(values.count == 1)
        #expect(values.allSatisfy { $0.count == 43 && FakeACMECrypto.decode($0)?.count == 32 })
        guard case let .issued(_, accountURL) = first else { Issue.record("First issuance failed"); return }
        let nextKey = P256.Signing.PrivateKey()
        let second = try await scenario.run(accountURL: accountURL, certificateKey: nextKey)
        _ = try await verified(second, in: scenario, key: nextKey)
        #expect(await scenario.server.accountCount == 1)
        #expect(await scenario.server.orderCount == 2)
        #expect(await scenario.server.records.filter { $0.endpoint == .account }.count == accountRequests.count)
        #expect(scenario.clock.now.timeIntervalSince(ScenarioClock.epoch) <= 300)
        let firstCSR = try #require(await scenario.server.submittedCSRs.first)
        let parsed = try FakeACMECrypto.CSR(firstCSR)
        #expect(parsed.names == [FakeACMEServer.domain])
        #expect(parsed.publicKey.x963Representation == scenario.certificateKey.publicKey.x963Representation)
        #expect(parsed.publicKey.x963Representation != scenario.accountKey.publicKey.x963Representation)
    }

    @Test
    func existingKeyFindsSameAccount() async throws {
        let scenario = CertificateScenario()
        let first = try await scenario.run()
        _ = try await verified(first, in: scenario, key: scenario.certificateKey)
        let before = await scenario.server.records.count
        let nextKey = P256.Signing.PrivateKey()
        let second = try await scenario.run(certificateKey: nextKey)
        _ = try await verified(second, in: scenario, key: nextKey)
        let requests = await scenario.server.records.dropFirst(before).filter { $0.endpoint == .account }
        #expect(requests.map(\.status) == [200])
        #expect(await scenario.server.accountCount == 1)
    }

    enum AuthorizationCase: String, Sendable, CaseIterable {
        case valid, twoOneValid, twoPending, processingChallenge, validChallenge, deactivated, expired, revoked, invalid
        case missingDNS01, wrongName, wrongType, wildcard, nine, none, unknownAuthorization, unknownChallenge, invalidChallenge
        case invalidToken, longToken, emptyToken
    }

    @Test(arguments: AuthorizationCase.allCases)
    func authorizationStates(_ kind: AuthorizationCase) async throws {
        var config = FakeACMEServer.Configuration()
        let expected: CertificateFailure?
        switch kind {
        case .valid: config.authorizationStates = ["valid"]; expected = nil
        case .twoOneValid: config.authorizationStates = ["pending", "valid"]; expected = nil
        case .twoPending: config.authorizationStates = ["pending", "pending"]; expected = nil
        case .processingChallenge: config.challengeStatus = "processing"; expected = nil
        case .validChallenge:
            config.challengeStatus = "valid"
            expected = nil
        case .deactivated, .expired, .revoked:
            config.authorizationStates = [kind.rawValue]; expected = .orderFailed(type: "")
        case .invalid: config.authorizationStates = ["invalid"]; config.challengeStatus = "invalid"
            expected = .validationFailed(type: FakeACMEServer.errorPrefix + "dns")
        case .invalidChallenge: config.challengeStatus = "invalid"
            expected = .validationFailed(type: FakeACMEServer.errorPrefix + "dns")
        case .missingDNS01: config.challengeType = "http-01"; expected = .unexpectedResponse
        case .wrongName: config.authorizationName = "other.tail0001.ts.net"; expected = .unexpectedResponse
        case .wrongType: config.authorizationType = "ip"; expected = .unexpectedResponse
        case .wildcard: config.wildcard = true; expected = .unexpectedResponse
        case .nine: config.authorizationStates = Array(repeating: "pending", count: 9); expected = .unexpectedResponse
        case .none: config.authorizationStates = []; expected = .unexpectedResponse
        case .unknownAuthorization: config.authorizationStates = ["future"]; expected = .unexpectedResponse
        case .unknownChallenge: config.challengeStatus = "future"; expected = .unexpectedResponse
        case .invalidToken: config.token = "invalid="; expected = .unexpectedResponse
        case .longToken: config.token = String(repeating: "A", count: 513); expected = .unexpectedResponse
        case .emptyToken: config.token = ""; expected = .unexpectedResponse
        }
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        if let expected { expectFailure(result, expected) }
        else { _ = try await verified(result, in: scenario, key: scenario.certificateKey) }
        let records = await scenario.server.records
        if [.valid, .validChallenge, .processingChallenge].contains(kind) {
            #expect(records.allSatisfy { $0.endpoint != .challenge })
        }
        if kind == .twoOneValid {
            #expect(records.filter { $0.endpoint == .authorization }.count == 2)
            #expect(records.filter { $0.endpoint == .challenge }.count == 1)
        }
        if kind == .twoPending {
            #expect(records.filter { $0.endpoint == .authorization }.count == 2)
            #expect(records.filter { $0.endpoint == .challenge }.count == 2)
            #expect(scenario.dns.lookup("_acme-challenge." + FakeACMEServer.domain).count == 2)
        }
        for request in records where request.endpoint == .challenge {
            let payload = try #require(request.payload)
            let object = try #require(JSONSerialization.jsonObject(with: payload) as? [String: String])
            #expect(object.isEmpty)
        }
        if expected != nil {
            #expect(records.allSatisfy { $0.endpoint != .finalize && $0.endpoint != .certificate })
            #expect(records.allSatisfy { $0.endpoint != .challenge })
            #expect(scenario.dns.records.isEmpty)
        }
        if kind == .nine || kind == .none {
            #expect(records.allSatisfy { $0.endpoint != .authorization })
        }
    }

    enum OrderCase: String, Sendable, CaseIterable {
        case ready, validThenPending, processingThenPending, repeatedValid, repeatedProcessing, initiallyInvalid, unknown
        case wrongIdentifiers, validBeforeCSR, processingBeforeCSR
    }

    @Test(arguments: OrderCase.allCases)
    func initialOrderStates(_ kind: OrderCase) async throws {
        var config = FakeACMEServer.Configuration()
        var expected: CertificateFailure?
        switch kind {
        case .ready: config.initialOrderStatuses = ["ready"]
        case .validThenPending: config.initialOrderStatuses = ["valid", "pending"]
        case .processingThenPending: config.initialOrderStatuses = ["processing", "pending"]
        case .repeatedValid: config.initialOrderStatuses = ["valid"]; expected = .orderFailed(type: "")
        case .repeatedProcessing: config.initialOrderStatuses = ["processing"]; expected = .orderFailed(type: "")
        case .initiallyInvalid:
            config.initialOrderStatuses = ["invalid"]; expected = .orderFailed(type: FakeACMEServer.errorPrefix + "badCSR")
        case .unknown: config.initialOrderStatuses = ["future"]; expected = .unexpectedResponse
        case .wrongIdentifiers: config.responseIdentifier = "other.tail0001.ts.net"; expected = .unexpectedResponse
        case .validBeforeCSR: config.pollStatuses = ["valid"]
        case .processingBeforeCSR: config.pollStatuses = ["processing"]
        }
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        if let expected { expectFailure(result, expected) }
        else { _ = try await verified(result, in: scenario, key: scenario.certificateKey) }
        let records = await scenario.server.records
        if kind == .ready { #expect(records.allSatisfy { $0.endpoint != .authorization && $0.endpoint != .challenge }) }
        if [.validThenPending, .processingThenPending, .repeatedValid, .repeatedProcessing, .validBeforeCSR, .processingBeforeCSR].contains(kind) {
            #expect(await scenario.server.orderCount == 2)
            #expect(records.allSatisfy { $0.url != FakeACMEServer.base + "/order/1/certificate" })
        }
    }

    enum FinalizeCase: String, Sendable, CaseIterable {
        case valid, processing, invalid, invalidWithoutError, ready, pending, unknown, orderNotReady
        case repeatedReady, repeatedPending, invalidOrderAfterFinalize, invalidOrderWithoutError
    }

    @Test(arguments: FinalizeCase.allCases)
    func finalizeStates(_ kind: FinalizeCase) async throws {
        var config = FakeACMEServer.Configuration()
        var expected: CertificateFailure?
        switch kind {
        case .valid: config.finalizeStatuses = ["valid"]
        case .processing: config.processingPolls = 4
        case .invalid: config.finalizeStatuses = ["invalid"]; expected = .orderFailed(type: FakeACMEServer.errorPrefix + "badCSR")
        case .invalidWithoutError:
            config.finalizeStatuses = ["invalid"]; config.orderErrorType = nil; expected = .orderFailed(type: "")
        case .ready: config.finalizeStatuses = ["ready", "valid"]
        case .pending: config.finalizeStatuses = ["pending", "valid"]
        case .unknown: config.finalizeStatuses = ["future"]; expected = .unexpectedResponse
        case .orderNotReady: config.orderNotReadyCount = 1
        case .repeatedReady: config.finalizeStatuses = ["ready", "ready"]; expected = .unexpectedResponse
        case .repeatedPending: config.finalizeStatuses = ["pending", "pending"]; expected = .unexpectedResponse
        case .invalidOrderAfterFinalize:
            config.pollStatuses = ["ready", "invalid"]; expected = .orderFailed(type: FakeACMEServer.errorPrefix + "badCSR")
        case .invalidOrderWithoutError:
            config.pollStatuses = ["ready", "invalid"]; config.orderErrorType = nil; expected = .orderFailed(type: "")
        }
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        if let expected { expectFailure(result, expected) }
        else { _ = try await verified(result, in: scenario, key: scenario.certificateKey) }
        let records = await scenario.server.records
        let finalizations = records.filter { $0.endpoint == .finalize }
        if [.ready, .pending, .orderNotReady, .repeatedReady, .repeatedPending].contains(kind) {
            #expect(finalizations.count == 2)
            // Check whether the CSR body is preserved, disregarding the bytes of the new signature.
            #expect(finalizations.first?.payload == finalizations.last?.payload)
        }
        if expected != nil { #expect(records.allSatisfy { $0.endpoint != .certificate }) }
    }

    @Test(arguments: [1, 3, 4])
    func badNonceRetryBudget(_ count: Int) async throws {
        var config = FakeACMEServer.Configuration()
        config.badNonce = [.newOrder: count, .finalize: count]
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        if count <= 3 { _ = try await verified(result, in: scenario, key: scenario.certificateKey) }
        else { expectFailure(result, .acme(status: 400, type: FakeACMEServer.errorPrefix + "badNonce")) }
        let records = await scenario.server.records
        let orderRequests = records.filter { $0.endpoint == .newOrder }
        #expect(orderRequests.count == min(count + 1, 4))
        if count <= 3 { #expect(records.filter { $0.endpoint == .finalize }.count == count + 1) }
        for index in records.indices where index > 0 && records[index - 1].status == 400 &&
            [.newOrder, .finalize].contains(records[index - 1].endpoint) {
            #expect(records[index].method == .post)
            #expect(records[index].protected?.nonce == records[index - 1].responseNonce)
            #expect(records[index].payload == records[index - 1].payload)
        }
    }

    @Test
    func badNonceBudgetIsPerRequest() async throws {
        var config = FakeACMEServer.Configuration()
        config.badNonce = [.account: 1, .newOrder: 3, .authorization: 3, .challenge: 3, .order: 3, .finalize: 3, .certificate: 3]
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        _ = try await verified(result, in: scenario, key: scenario.certificateKey)
        let records = await scenario.server.records
        for endpoint in [FakeACMEServer.Endpoint.newOrder, .authorization, .challenge, .order, .finalize, .certificate] {
            #expect(records.filter { $0.endpoint == endpoint && $0.status == 400 }.count == 3)
        }
        for index in records.indices where index > 0 && records[index - 1].status == 400 &&
            records[index - 1].endpoint != .account {
            #expect(records[index].protected?.nonce == records[index - 1].responseNonce)
        }
    }

    enum RetryCase: String, Sendable, CaseIterable {
        case seconds, date, past, invalid, absent, beyondDeadline, beyondSevenDays, zero

        var header: String? {
            switch self {
            case .seconds: "37"
            case .date: httpDate(ScenarioClock.epoch.addingTimeInterval(42))
            case .past: httpDate(ScenarioClock.epoch.addingTimeInterval(-10))
            case .invalid: "not-a-date"
            case .absent: nil
            case .beyondDeadline: "301"
            case .beyondSevenDays: "9999999"
            case .zero: "0"
            }
        }

        var delay: TimeInterval? {
            switch self {
            case .seconds: 37
            case .date: 42
            case .beyondDeadline: 301
            case .beyondSevenDays: 7 * 86400
            default: nil
            }
        }
    }

    @Test(arguments: RetryCase.allCases)
    func rateLimitedPreservesRetryAfter(_ kind: RetryCase) async throws {
        var config = FakeACMEServer.Configuration()
        config.responseFault = .init(status: 429, type: FakeACMEServer.errorPrefix + "rateLimited", retryAfter: kind.header)
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        let until = kind.delay.map { ScenarioClock.epoch.addingTimeInterval($0) }
        let reportedDate: Date?
        switch kind {
        case .past: reportedDate = ScenarioClock.epoch.addingTimeInterval(-10)
        case .zero: reportedDate = ScenarioClock.epoch
        default: reportedDate = until
        }
        expectFailure(result, .rateLimited(retryAfter: reportedDate), retry: until)
        #expect(scenario.clock.now == ScenarioClock.epoch)
        #expect(await scenario.server.records.last?.endpoint == .newOrder)
    }

    @Test(arguments: RetryCase.allCases)
    func processingHonorsRetryAfter(_ kind: RetryCase) async throws {
        var config = FakeACMEServer.Configuration()
        config.initialOrderStatuses = ["ready"]
        config.retryAfter = kind.header
        config.processingPolls = 2
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        let records = await scenario.server.records
        let finalizedAt = try #require(records.first { $0.endpoint == .finalize }?.time)
        if let delay = kind.delay, delay > 300 {
            expectFailure(result, .timedOut, retry: finalizedAt.addingTimeInterval(delay))
            #expect(records.last?.endpoint == .finalize)
            #expect(scenario.clock.now == ScenarioClock.epoch)
        } else {
            _ = try await verified(result, in: scenario, key: scenario.certificateKey)
            let firstPoll = try #require(records.first { $0.endpoint == .order })
            let minimumDelay = max(kind.delay ?? 0, 1)
            #expect(firstPoll.time.timeIntervalSince(finalizedAt) >= minimumDelay)
            let polls = records.filter { $0.endpoint == .order }
            #expect(polls.count == 3)
            for index in 1..<polls.count {
                let expectedDelay: TimeInterval = kind == .date ? 1 : minimumDelay
                #expect(polls[index].time.timeIntervalSince(polls[index - 1].time) >= expectedDelay)
            }
        }
        #expect(scenario.clock.now.timeIntervalSince(ScenarioClock.epoch) <= 300)
    }

    @Test(arguments: [true, false])
    func endlessOrderStopsAtFiveMinutes(_ processing: Bool) async throws {
        var config = FakeACMEServer.Configuration()
        config.processingPolls = processing ? 1000 : 0
        config.pendingPolls = processing ? 0 : 1000
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        expectFailure(result, .timedOut)
        #expect(scenario.clock.now.timeIntervalSince(ScenarioClock.epoch) <= 300)
        let records = await scenario.server.records
        #expect(records.allSatisfy { $0.time.timeIntervalSince(ScenarioClock.epoch) <= 300 })
        #expect(records.count < 320)
        #expect(records.allSatisfy { $0.endpoint != .certificate })
    }

    @Test
    func retryAfterStopsEveryEndpointIncludingCertificate() async throws {
        var config = FakeACMEServer.Configuration()
        config.finalizeStatuses = ["valid"]
        config.retryAfter = "23"
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        _ = try await verified(result, in: scenario, key: scenario.certificateKey)
        let records = await scenario.server.records
        let finalizeIndex = try #require(records.firstIndex { $0.endpoint == .finalize })
        #expect(records[finalizeIndex + 1].time >= records[finalizeIndex].time.addingTimeInterval(23))
        #expect(records[finalizeIndex + 1].endpoint == .certificate)
    }

    @Test
    func retryAfterAppliesAcrossAllResourceURLs() async throws {
        var config = FakeACMEServer.Configuration()
        config.retryAfterByEndpoint = [
            .directory: "11", .account: "7", .newOrder: "9", .authorization: "8",
            .challenge: "6", .order: "3", .finalize: "5",
        ]
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        _ = try await verified(result, in: scenario, key: scenario.certificateKey)
        let records = await scenario.server.records
        for index in 0..<(records.count - 1) {
            if let endpoint = records[index].endpoint, let value = config.retryAfterByEndpoint[endpoint], let delay = Double(value) {
                #expect(records[index + 1].time >= records[index].time.addingTimeInterval(delay))
            }
        }
        #expect(scenario.clock.now.timeIntervalSince(ScenarioClock.epoch) <= 300)
    }

    @Test(arguments: [true, false])
    func publishFailureAndWrongTXT(_ publishFails: Bool) async throws {
        let scenario = CertificateScenario()
        let failure = CertificateFailure.controlRejected(status: 403)
        let result = try await issueCertificate(
            with: scenario.flow(), transport: scenario.server, now: { scenario.clock.now },
            sleep: { (until: Date) async throws(CancellationError) in try await scenario.clock.sleep(until: until) },
            publishTXT: { name, value in
                #expect(name == "_acme-challenge." + FakeACMEServer.domain)
                #expect(value.count == 43 && FakeACMECrypto.decode(value)?.count == 32)
                if publishFails { return failure }
                scenario.dns.publish(name, String(repeating: "A", count: 43))
                return nil
            }
        )
        expectFailure(result, publishFails ? failure : .validationFailed(type: FakeACMEServer.errorPrefix + "dns"))
        let records = await scenario.server.records
        #expect(records.filter { $0.endpoint == .challenge }.count == (publishFails ? 0 : 1))
        #expect(records.allSatisfy { $0.endpoint != .finalize && $0.endpoint != .certificate })
        if !publishFails { #expect(records.filter { $0.endpoint == .authorization }.count == 2) }
    }

    @Test
    func wrongTXTWithoutChallengeProblemStillFailsValidation() async throws {
        var config = FakeACMEServer.Configuration()
        config.challengeErrorType = nil
        let scenario = CertificateScenario(config)
        let result = try await issueCertificate(
            with: scenario.flow(), transport: scenario.server, now: { scenario.clock.now },
            sleep: { (until: Date) async throws(CancellationError) in try await scenario.clock.sleep(until: until) }, publishTXT: { _, _ in nil }
        )
        expectFailure(result, .validationFailed(type: ""))
    }

    @Test
    func cancellingDuringWaitStopsRequests() async throws {
        var config = FakeACMEServer.Configuration()
        config.initialOrderStatuses = ["ready"]
        config.retryAfter = "30"
        let scenario = CertificateScenario(config)
        let gate = ScenarioSleepGate()
        let flow = try scenario.flow()
        let task = Task {
            try await issueCertificate(
                with: flow, transport: scenario.server, now: { scenario.clock.now },
                sleep: { (_: Date) async throws(CancellationError) in try await gate.wait() },
                publishTXT: { name, value in scenario.dns.publish(name, value); return nil }
            )
        }
        var iterator = gate.entered.makeAsyncIterator()
        _ = await iterator.next()
        let count = await scenario.server.records.count
        task.cancel()
        await gate.resume()
        do { _ = try await task.value; Issue.record("Canceled issuance returned a result") }
        catch is CancellationError { }
        #expect(await scenario.server.records.count == count)
        #expect(await scenario.server.records.last?.endpoint == .finalize)
    }

    @Test
    func completedFlowAndResultDoNotReflectPrivateKeys() async throws {
        let scenario = CertificateScenario()
        var flow = try scenario.flow()
        var step = flow.start(at: scenario.clock.now)
        var result: ACMEIssuanceResult?
        for _ in 0..<100 {
            switch step {
            case .send(let request): step = flow.receive(try await scenario.server.send(request), at: scenario.clock.now)
            case .wait(let until): scenario.clock.advance(to: until); step = flow.resume(at: scenario.clock.now)
            case .publishTXT(let name, let value): scenario.dns.publish(name, value); step = flow.txtPublished(at: scenario.clock.now)
            case .finished(let issued): result = issued
            }
            if result != nil { break }
        }
        let finished = try #require(result)
        _ = try await verified(finished, in: scenario, key: scenario.certificateKey)
        var dumped = ""
        dump(flow, to: &dumped)
        dump(finished, to: &dumped)
        let reflection = String(reflecting: flow) + String(reflecting: finished) + dumped
        let keys = [scenario.accountKey, scenario.certificateKey]
        let redacted = keys.allSatisfy { key in
            let representations = [key.rawRepresentation, key.x963Representation, key.derRepresentation]
            let secrets = representations.flatMap { bytes in
                [String(describing: Array(bytes)), bytes.base64EncodedString(),
                 bytes.map { String(format: "%02x", $0) }.joined(), FakeACMECrypto.base64URL(bytes)]
            } + [key.pemRepresentation]
            return secrets.allSatisfy { !reflection.contains($0) }
        }
        // Do not pass keys or reflection strings as arguments to failure diagnostics.
        #expect(redacted)
    }
}

func expectFailure(_ result: ACMEIssuanceResult, _ expected: CertificateFailure, retry: Date? = nil) {
    guard case let .failed(failure, retryNotBefore, _) = result else { Issue.record("Issuance succeeded when it should have failed"); return }
    #expect(failure == expected)
    #expect(retryNotBefore == retry)
}

/// Connects the issuance step that returns the chain bytes to the storage boundary that verifies the chain.
private func verified(
    _ result: ACMEIssuanceResult, in scenario: CertificateScenario, key: P256.Signing.PrivateKey?
) async throws -> VerifiedCertificate {
    guard case let .issued(pem, _) = result else { throw ScenarioError.issuanceFailed }
    guard let key else { throw ScenarioError.missingKey }
    let domain = try #require(CertificateDomain(FakeACMEServer.domain))
    return try VerifiedCertificate(
        pemChain: pem, maximumByteCount: 256 * 1024, privateKey: key, domain: domain,
        at: scenario.clock.now, anchors: .only([await scenario.server.rootCertificate])
    )
}

private enum ScenarioError: Error { case issuanceFailed, missingKey }

private func httpDate(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = .gmt
    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
    return formatter.string(from: date)
}

private actor ScenarioSleepGate {
    nonisolated let entered: AsyncStream<Void>
    private let signal: AsyncStream<Void>.Continuation
    private var waiter: CheckedContinuation<Void, Never>?

    init() {
        let pair = AsyncStream<Void>.makeStream()
        entered = pair.stream
        signal = pair.continuation
    }

    func wait() async throws(CancellationError) {
        await withCheckedContinuation { continuation in
            waiter = continuation
            signal.yield(())
        }
        if Task.isCancelled { throw CancellationError() }
    }

    func resume() { waiter?.resume(); waiter = nil; signal.finish() }
}
