import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("Independent ACME response and chain boundaries")
struct CertificateBoundaryScenarios {
    enum ProblemCase: String, Sendable, CaseIterable {
        case nonJSON, noType, blank, privateURI, longType, unicodeType, fakeBadNonce, serverError, subproblems, redirect
    }

    @Test(arguments: ProblemCase.allCases)
    func problemDocuments(_ kind: ProblemCase) async throws {
        var fault = FakeACMEServer.ResponseFault()
        var expectedType = ""
        switch kind {
        case .nonJSON: fault.rawBody = Array("upstream failure".utf8)
        case .noType: fault.type = nil
        case .blank: expectedType = "about:blank"; fault.type = expectedType
        case .privateURI: expectedType = "https://acme.invalid/problems/policy"; fault.type = expectedType
        case .longType:
            fault.type = "https://acme.invalid/" + String(repeating: "a", count: 300)
            expectedType = String(try #require(fault.type).prefix(256))
        case .unicodeType:
            fault.type = "https://acme.invalid/" + String(repeating: "가", count: 100)
            expectedType = "https://acme.invalid/" + String(repeating: "가", count: 78)
        case .fakeBadNonce: expectedType = "https://acme.invalid/problems/badNonce"; fault.type = expectedType
        case .serverError: fault.status = 503; fault.type = nil; fault.retryAfter = "90"
        case .subproblems: expectedType = FakeACMEServer.errorPrefix + "rejectedIdentifier"; fault.type = expectedType
        case .redirect: fault.status = 302; fault.type = nil
        }
        var config = FakeACMEServer.Configuration()
        config.responseFault = fault
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        expectFailure(
            result, .acme(status: fault.status, type: expectedType),
            retry: kind == .serverError ? ScenarioClock.epoch.addingTimeInterval(90) : nil
        )
        #expect(await scenario.server.records.last?.endpoint == .newOrder)
        #expect(await scenario.server.records.filter { $0.endpoint == .newOrder }.count == 1)
        let reflected = String(reflecting: result)
        #expect(!reflected.contains("test identifier omitted from diagnostics"))
        #expect(!reflected.contains("subproblems"))
    }

    enum BoundaryCase: String, Sendable, CaseIterable {
        case httpURL, longURL, largeJSON, nonJSONSuccess, missingNonce, invalidNonce, missingEveryNonce, invalidEveryNonce
        case badAccountStatus
        case exactURLLimit, encodedURL, differentHost
    }

    @Test(arguments: BoundaryCase.allCases)
    func responseBoundaries(_ kind: BoundaryCase) async throws {
        var config = FakeACMEServer.Configuration()
        var succeeds = false
        switch kind {
        case .httpURL: config.directoryOrderURL = "http://acme.invalid/new-order"
        case .longURL: config.directoryOrderURL = FakeACMEServer.base + "/" + String(repeating: "a", count: 2049)
        case .largeJSON:
            config.responseFault = .init(endpoint: .directory, status: 200, rawBody: Array(repeating: 32, count: 64 * 1024 + 1))
        case .nonJSONSuccess:
            config.responseFault = .init(endpoint: .directory, status: 200, rawBody: Array("not-json".utf8))
        case .missingNonce: config.nonceMode = .missingExceptNonce; succeeds = true
        case .invalidNonce: config.nonceMode = .invalidExceptNonce; succeeds = true
        case .missingEveryNonce: config.nonceMode = .missing
        case .invalidEveryNonce: config.nonceMode = .invalid
        case .badAccountStatus: config.accountStatus = "deactivated"
        case .exactURLLimit:
            let prefix = FakeACMEServer.base + "/"
            config.directoryOrderURL = prefix + String(repeating: "a", count: 2048 - prefix.utf8.count)
            succeeds = true
        case .encodedURL:
            config.directoryOrderURL = FakeACMEServer.base + "/new%2forder?literal=a%2Bb&other=%26"
            succeeds = true
        case .differentHost:
            // Sends no requests to URLs with an origin different from the directory (contract X1. Initially accepted, then disallowed after review).
            config.directoryOrderURL = "https://other-acme.invalid/new-order"
        }
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        let records = await scenario.server.records
        if succeeds {
            guard case .issued = result else { Issue.record("Issuance that needed to obtain another valid nonce failed"); return }
            if kind == .missingNonce || kind == .invalidNonce {
                #expect(records.filter { $0.endpoint == .nonce }.count > 3)
            }
            #expect(records.filter { $0.method == .post }.allSatisfy { $0.status < 400 || $0.endpoint == .account })
        } else {
            expectFailure(result, .unexpectedResponse)
            #expect(records.allSatisfy { $0.endpoint != .finalize && $0.endpoint != .certificate })
        }
        if kind == .httpURL || kind == .longURL { #expect(records.count == 1) }
        if kind == .missingEveryNonce || kind == .invalidEveryNonce {
            #expect(records.filter { $0.endpoint == .nonce }.count == 1)
            #expect(records.allSatisfy { $0.method != .post })
        }
    }

    @Test(arguments: FakeACMEServer.ChainFault.allCases)
    func receivedCertificateChains(_ kind: FakeACMEServer.ChainFault) async throws {
        var config = FakeACMEServer.Configuration()
        config.chainFault = kind
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        if kind == .tooLarge { expectFailure(result, .unexpectedResponse); return }
        guard case let .issued(pem, _) = result else { Issue.record("Issuance failed before receiving the chain bytes"); return }
        let domain = try #require(CertificateDomain(FakeACMEServer.domain))
        let root = await scenario.server.rootCertificate
        do {
            let verified = try VerifiedCertificate(
                pemChain: pem, maximumByteCount: 256 * 1024, privateKey: scenario.certificateKey,
                domain: domain, at: scenario.clock.now, anchors: .only([root])
            )
            #expect(kind == .none || kind == .includeRoot)
            #expect(verified.chain.count == 2)
            #expect(verified.receivedChain.count == (kind == .includeRoot ? 3 : 2))
            #expect(!verified.chain.contains(root))
            if kind == .includeRoot { #expect(verified.receivedChain.contains(root)) }
        } catch {
            #expect(kind != .none && kind != .includeRoot)
            // Every CertificateVerificationError case maps to the manager's invalidCertificate boundary.
            switch (kind, error) {
            case (.wrongKey, .keyMismatch), (.wrongName, .untrusted), (.expired, .untrusted), (.unknownRoot, .untrusted),
                 (.privateKey, .malformedChain), (.garbageAfter, .malformedChain), (.garbageBetween, .malformedChain),
                 (.malformed, .unparsableCertificate), (.malformed, .malformedChain), (.sixCertificates, .malformedChain):
                break
            default: Issue.record("The invalid chain was not rejected at the expected verification boundary")
            }
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"] != nil))
    func rootRemainsInStoredChainAfterVerification() async throws {
        var config = FakeACMEServer.Configuration()
        config.chainFault = .includeRoot
        let scenario = CertificateScenario(config)
        let result = try await scenario.run()
        guard case let .issued(pem, _) = result else { Issue.record("Issuance failed"); return }
        let root = await scenario.server.rootCertificate
        let domain = try #require(CertificateDomain(FakeACMEServer.domain))
        let verified = try VerifiedCertificate(
            pemChain: pem, maximumByteCount: 256 * 1024, privateKey: scenario.certificateKey,
            domain: domain, at: scenario.clock.now, anchors: .only([root])
        )
        let scratch = try #require(ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"])
        let directory = URL(fileURLWithPath: scratch, isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = CertificateStore(stateDirectory: directory)
        try store.save(verified)
        let saved = try store.certificate(for: domain, at: scenario.clock.now, anchors: .only([root]))
        let restored = try #require(saved)
        #expect(restored.receivedChain == verified.receivedChain)
        #expect(restored.receivedChain.contains(root))
        #expect(!restored.chain.contains(root))
        #expect(restored.chain.count == 2)
    }
}
