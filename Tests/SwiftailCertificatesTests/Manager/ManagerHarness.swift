// A `CertificateManager` test harness that supplies a fake facts stream, set-dns, scripted transport, and manually advanced clock to the internal initializer without a node.
//
// Tests advance the clock (`TestClock.advance`). Only short waits that coordinate the order of concurrent work (`eventually`) use real time.
// Creates files only under `SWIFTAIL_TEST_SCRATCH`.

import CryptoKit
import Foundation
import Synchronization
import Testing

import Swiftail
@testable import SwiftailCertificates
import SwiftailControl

/// A wall clock advanced by the test. `sleep(until:)` returns when the test advances to that time or cancels the wait.
final class TestClock: Sendable {
    private struct Sleeper {
        let id: UInt64
        let deadline: Date
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct State {
        var now: Date
        var nextID: UInt64 = 0
        var sleepers: [Sleeper] = []
        var cancelled: Set<UInt64> = []
    }

    private let state: Mutex<State>

    init(_ start: Date) {
        state = Mutex(State(now: start))
    }

    func now() -> Date { state.withLock { $0.now } }

    /// Pending wake times, earliest first.
    var deadlines: [Date] { state.withLock { $0.sleepers.map(\.deadline).sorted() } }

    func sleep(until deadline: Date) async throws(CancellationError) {
        let id = state.withLock { state in
            state.nextID += 1
            return state.nextID
        }
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    let outcome = state.withLock { state -> Result<Void, CancellationError>? in
                        if state.cancelled.remove(id) != nil { return .failure(CancellationError()) }
                        if deadline <= state.now { return .success(()) }
                        state.sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                        return nil
                    }
                    if let outcome { continuation.resume(with: outcome) }
                }
            } onCancel: {
                let sleeper = state.withLock { state -> Sleeper? in
                    guard let index = state.sleepers.firstIndex(where: { $0.id == id }) else {
                        state.cancelled.insert(id)
                        return nil
                    }
                    return state.sleepers.remove(at: index)
                }
                sleeper?.continuation.resume(throwing: CancellationError())
            }
        } catch {
            throw CancellationError()
        }
    }

    /// Advances time and wakes waits whose deadlines have arrived.
    func advance(to date: Date) {
        let due = state.withLock { state -> [Sleeper] in
            state.now = max(state.now, date)
            let now = state.now
            let due = state.sleepers.filter { $0.deadline <= now }
            state.sleepers.removeAll { $0.deadline <= now }
            return due
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    func advance(by interval: TimeInterval) {
        advance(to: now().addingTimeInterval(interval))
    }
}

/// A scripted transport that responds to requests in order. An unexpected method or URL is recorded as a test failure.
final class ScriptedTransport: ACMETransport {
    /// One script entry.
    struct Entry: Sendable {
        var exchange: Exchange
        /// Builds the body at response time. For certificate download, creates the leaf with the current time and certificate key.
        var body: (@Sendable () -> [UInt8])?
        /// Holds the request without responding until canceled.
        var hangs = false
    }

    struct Sent: Sendable {
        var request: ACMEHTTPRequest
        var time: Date
    }

    private struct State {
        var queue: [Entry] = []
        var sent: [Sent] = []
        var nonce = 0
    }

    private let state = Mutex(State())
    private let clock: TestClock

    init(clock: TestClock) {
        self.clock = clock
    }

    func append(_ entries: [Entry]) {
        state.withLock { $0.queue += entries }
    }

    var sent: [Sent] { state.withLock { $0.sent } }
    var remaining: Int { state.withLock { $0.queue.count } }

    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse {
        let time = clock.now()
        let entry = state.withLock { state -> Entry? in
            state.sent.append(Sent(request: request, time: time))
            return state.queue.isEmpty ? nil : state.queue.removeFirst()
        }
        guard let entry else {
            Issue.record("Request missing from the script: \(request.method) \(request.url)")
            throw .network
        }
        #expect(request.method == entry.exchange.method && request.url == entry.exchange.url,
                "Expected \(entry.exchange.method) \(entry.exchange.url), received \(request.method) \(request.url)")
        if entry.hangs {
            try? await Task.sleep(for: .seconds(3600))
            throw .network
        }
        var headers = entry.exchange.headers
        if case .fresh = entry.exchange.nonce {
            let nonce = state.withLock { state in
                state.nonce += 1
                return "nonce-\(state.nonce)"
            }
            headers.append(.init(name: "Replay-Nonce", value: nonce))
        }
        return ACMEHTTPResponse(status: entry.exchange.status, headers: headers, body: entry.body?() ?? entry.exchange.body)
    }
}

/// A fake set-dns that records requests and throws a preset failure.
final class FakeDNS: Sendable {
    private struct State {
        var calls: [(name: String, value: String)] = []
        var failure: ControlError?
        /// When true, waits for `release()` before responding.
        var isHeld = false
        var heldWaiter: CheckedContinuation<Void, Never>?
    }

    private let state = Mutex(State())

    var calls: [(name: String, value: String)] { state.withLock { $0.calls } }

    func fail(with error: ControlError?) { state.withLock { $0.failure = error } }
    func hold() { state.withLock { $0.isHeld = true } }

    func release() {
        let waiter = state.withLock { state -> CheckedContinuation<Void, Never>? in
            state.isHeld = false
            defer { state.heldWaiter = nil }
            return state.heldWaiter
        }
        waiter?.resume()
    }

    func setDNS(name: String, value: String) async throws(ControlError) {
        let failure = state.withLock { state in
            state.calls.append((name, value))
            return state.failure
        }
        await withCheckedContinuation { continuation in
            let held = state.withLock { state -> Bool in
                guard state.isHeld else { return false }
                state.heldWaiter = continuation
                return true
            }
            if !held { continuation.resume() }
        }
        if let failure { throw failure }
    }
}

/// A state directory for one test. Creates it under `SWIFTAIL_TEST_SCRATCH` and removes it when done.
struct ManagerScratch {
    static let root = ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"]

    let url: URL

    init() throws {
        let root = URL(fileURLWithPath: try #require(Self.root), isDirectory: true)
        url = root.appending(path: "manager-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    func remove() { try? FileManager.default.removeItem(at: url) }

    func file(_ name: String) -> URL {
        url.appending(path: "certs", directoryHint: .isDirectory).appending(path: name, directoryHint: .notDirectory)
    }

    func exists(_ name: String) -> Bool { FileManager.default.fileExists(atPath: file(name).path) }

    func contents(_ name: String) throws -> [UInt8] { Array(try Data(contentsOf: file(name))) }

    func mode(_ name: String) throws -> Int {
        try #require(try FileManager.default.attributesOfItem(atPath: file(name).path)[.posixPermissions] as? Int)
    }

    /// Writes a file directly, such as a stored certificate or a corrupt account key, without going through the manager.
    func put(_ bytes: [UInt8], _ name: String) throws {
        let certs = url.appending(path: "certs", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: certs, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data(bytes).write(to: file(name))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(name).path)
    }
}

/// One manager and its interfaces.
struct ManagerHarness {
    static let name = TestPKI.domainName
    static let day: TimeInterval = 24 * 3600
    /// The lifetime of an issued certificate. The 2/3 point is issuance time + 60 days.
    static let lifetime: TimeInterval = 90 * day

    let pki: TestPKI
    let scratch: ManagerScratch
    let clock = TestClock(TestPKI.now)
    let transport: ScriptedTransport
    let dns = FakeDNS()
    let manager: CertificateManager
    private let factsContinuation: AsyncStream<CertificateFacts>.Continuation
    /// Certificate keys generated by the manager, in order.
    private let keys = KeyLog()

    /// Where to supply the test root.
    enum AnchorSource {
        /// The `anchors` parameter of the internal initializer, used by most tests.
        case parameter
        /// `trustAnchors` in the public configuration, the path for apps using staging.
        case configuration
        /// Supplies no anchor. Verification uses the system trust store, so the test root's chain fails.
        case none
    }

    init(anchors source: AnchorSource = .parameter) throws {
        pki = try TestPKI()
        scratch = try ManagerScratch()
        transport = ScriptedTransport(clock: clock)
        let (facts, continuation) = AsyncStream.makeStream(of: CertificateFacts.self, bufferingPolicy: .bufferingNewest(1))
        factsContinuation = continuation
        let clock = clock
        let dns = dns
        let keys = keys
        var roots: [[UInt8]]?
        if source == .configuration, case let .only(certificates) = pki.anchors { roots = certificates }
        manager = try CertificateManager(
            facts: facts,
            setDNS: { name, value throws(ControlError) in try await dns.setDNS(name: name, value: value) },
            stateDirectory: scratch.url,
            transport: transport,
            configuration: CertificateConfiguration(directoryURL: try #require(URL(string: Fake.directoryURL)), trustAnchors: roots),
            anchors: source == .parameter ? pki.anchors : nil,
            now: { clock.now() },
            sleep: { until throws(CancellationError) in try await clock.sleep(until: until) },
            makeCertificateKey: { keys.make() }
        )
    }

    var certificateKeys: [P256.Signing.PrivateKey] { keys.all }

    static func facts(
        running: Bool = true, fqdn: String? = name, certDomains: [String] = [name], magicDNS: Bool = true
    ) -> CertificateFacts {
        CertificateFacts(isRunning: running, fqdn: fqdn, certDomains: certDomains, isMagicDNSEnabled: magicDNS)
    }

    func send(_ facts: CertificateFacts) {
        factsContinuation.yield(facts)
    }

    /// Runs `run()`. Returns a Task that yields the final result.
    func start(with facts: CertificateFacts = ManagerHarness.facts()) -> Task<CertificateError?, Never> {
        send(facts)
        let manager = manager
        return Task {
            do throws(CertificateError) {
                try await manager.run()
                return nil
            } catch {
                return error
            }
        }
    }

    func status() async -> CertificateStatus { await manager.status }

    // MARK: - Scripts

    /// A script for one issuance attempt. With `firstAttempt`, looks up the account. Otherwise orders directly with the known account URL.
    ///
    /// The download body builds a leaf with the last certificate key the manager generated at that time (90 days from issuance). `leafName` and `leafKey` can
    /// produce a leaf for another name or key.
    func issuance(
        firstAttempt: Bool = true, orderName: String = ManagerHarness.name, leafName: String = ManagerHarness.name,
        leafKey: P256.Signing.PublicKey? = nil
    ) -> [ScriptedTransport.Entry] {
        let account: [Exchange] = firstAttempt
            ? Steps.accountFound
            : [.get(Fake.directoryURL, 200, Body.directory()), .head()]
        let identifiers = [["type": "dns", "value": orderName]]
        let ordering = account + [
            Steps.newOrder(Body.order("pending", identifiers: identifiers)),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", identifier: identifiers[0])),
            .post(Fake.challengeURL(1), 200, Body.json(Body.challenge(1, status: "processing"))),
            Steps.readOrder(Body.order("ready", identifiers: identifiers)),
            .post(Fake.finalizeURL, 200, Body.order("valid", identifiers: identifiers, certificate: Fake.certificateURL)),
        ]
        let pki = pki
        let clock = clock
        let keys = keys
        let download = ScriptedTransport.Entry(exchange: Steps.download, body: {
            let issuedAt = clock.now()
            let key = leafKey ?? keys.all.last?.publicKey ?? P256.Signing.PrivateKey().publicKey
            let leaf = pki.intermediate.leaf(leafName, publicKey: key, from: issuedAt, to: issuedAt + Self.lifetime)
            return pemChain([leaf, pki.intermediate.certificate])
        })
        return ordering.map { ScriptedTransport.Entry(exchange: $0) } + [download]
    }

    /// A failure script in which newOrder receives this response after account lookup.
    func failingOrder(_ exchange: Exchange, firstAttempt: Bool = true) -> [ScriptedTransport.Entry] {
        let account: [Exchange] = firstAttempt
            ? Steps.accountFound
            : [.get(Fake.directoryURL, 200, Body.directory()), .head()]
        return (account + [exchange]).map { ScriptedTransport.Entry(exchange: $0) }
    }

    /// Places a stored certificate file without going through the manager.
    func storeCertificate(
        name: String = ManagerHarness.name, key: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
        pairedKey: P256.Signing.PrivateKey? = nil, from start: Date, to end: Date
    ) throws {
        let leaf = pki.intermediate.leaf(name, publicKey: key.publicKey, from: start, to: end)
        try scratch.put(pemChain([leaf, pki.intermediate.certificate]), Self.name + ".crt")
        try scratch.put(Array((pairedKey ?? key).pemRepresentation.utf8), Self.name + ".key")
    }
}

/// The record of certificate keys generated by the manager.
final class KeyLog: Sendable {
    private let keys = Mutex<[P256.Signing.PrivateKey]>([])

    var all: [P256.Signing.PrivateKey] { keys.withLock { $0 } }

    func make() -> P256.Signing.PrivateKey {
        let key = P256.Signing.PrivateKey()
        keys.withLock { $0.append(key) }
        return key
    }
}

/// Briefly waits for the condition to become true. This gives other Tasks a turn without advancing the clock.
func eventually(
    _ message: String = "The condition was not met",
    sourceLocation: SourceLocation = #_sourceLocation,
    _ condition: () async -> Bool
) async throws {
    for _ in 0..<2500 {
        if await condition() { return }
        try await Task.sleep(for: .milliseconds(2))
    }
    Issue.record(Comment(rawValue: message), sourceLocation: sourceLocation)
    throw CancellationError()
}

/// Gives the manager a little longer to run before checking that something did not happen.
func settle() async throws {
    for _ in 0..<20 {
        await Task.yield()
    }
    try await Task.sleep(for: .milliseconds(30))
}

/// Drains the stream. The stream must have ended, after `run()` returns.
func drain(_ stream: AsyncStream<TailnetCertificate>) async -> [TailnetCertificate] {
    var collected: [TailnetCertificate] = []
    for await certificate in stream { collected.append(certificate) }
    return collected
}
