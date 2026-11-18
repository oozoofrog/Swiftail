import CryptoKit
import Foundation
import Synchronization

@testable import SwiftailCertificates

/// Advances issuance deadlines and request times together without real waits.
final class ScenarioClock: Sendable {
    static let epoch = Date(timeIntervalSince1970: 1_800_000_000)
    private let state = Mutex(ScenarioClock.epoch)

    var now: Date { state.withLock { $0 } }
    func advance(to date: Date) { state.withLock { $0 = max($0, date) } }

    func sleep(until: Date) async throws(CancellationError) {
        guard !Task.isCancelled else { throw CancellationError() }
        advance(to: until)
    }
}

/// Allows multiple TXT values. The two authorizations use different tokens.
final class ScenarioDNS: Sendable {
    private let state = Mutex<[String: [String]]>([:])

    func lookup(_ name: String) -> [String] { state.withLock { $0[name] ?? [] } }
    func publish(_ name: String, _ value: String) { state.withLock { $0[name, default: []].append(value) } }
    var records: [String: [String]] { state.withLock { $0 } }
}

struct CertificateScenario: Sendable {
    let clock = ScenarioClock()
    let dns = ScenarioDNS()
    let accountKey = P256.Signing.PrivateKey()
    let certificateKey = P256.Signing.PrivateKey()
    let server: FakeACMEServer

    init(_ configuration: FakeACMEServer.Configuration = .init()) {
        let clock = self.clock
        let dns = self.dns
        server = FakeACMEServer(configuration: configuration, now: { clock.now }, lookupTXT: { dns.lookup($0) })
    }

    func flow(accountURL: String? = nil, certificateKey: P256.Signing.PrivateKey? = nil) throws -> ACMEOrderFlow {
        guard let domain = CertificateDomain(FakeACMEServer.domain) else { throw FakeACMECrypto.Invalid.encoding }
        return ACMEOrderFlow(
            directoryURL: FakeACMEServer.directoryURL, domain: domain,
            accountKey: accountKey, accountURL: accountURL, certificateKey: certificateKey ?? self.certificateKey
        )
    }

    func run(accountURL: String? = nil, certificateKey: P256.Signing.PrivateKey? = nil) async throws -> ACMEIssuanceResult {
        try await issueCertificate(
            with: flow(accountURL: accountURL, certificateKey: certificateKey), transport: server,
            now: { clock.now }, sleep: { (until: Date) async throws(CancellationError) in try await clock.sleep(until: until) },
            publishTXT: { name, value in dns.publish(name, value); return nil }
        )
    }
}
