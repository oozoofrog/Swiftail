// `CertificateManager` 시험의 틀: 노드 없이 내부 init에 가짜 접점(사실의 흐름, set-dns, 대본 전송)과 넘기는 시계를 준다.
//
// 시각은 시험이 넘긴다(`TestClock.advance`). 실제로 흐르는 것은 동시성의 차례를 맞추는 짧은 기다림(`eventually`)뿐이다.
// 파일은 `SWIFTAIL_TEST_SCRATCH` 아래에만 만든다.

import CryptoKit
import Foundation
import Synchronization
import Testing

import Swiftail
@testable import SwiftailCertificates
import SwiftailControl

/// 시험이 넘기는 벽시계. `sleep(until:)`은 시험이 그 시각을 넘길 때까지(또는 취소될 때까지) 돌아오지 않는다.
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

    /// 기다리는 시각들(이른 것부터).
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

    /// 시각을 넘기고, 그 시각이 된 기다림을 깨운다.
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

/// 대본 전송: 요청이 오면 차례로 응답한다. 기대한 메서드·URL이 아니면 시험 실패로 적는다.
final class ScriptedTransport: ACMETransport {
    /// 대본 한 줄.
    struct Entry: Sendable {
        var exchange: Exchange
        /// 응답할 때 본문을 만든다(인증서 내려받기: 그때의 시각과 인증서 키로 leaf를 만든다).
        var body: (@Sendable () -> [UInt8])?
        /// 응답하지 않고 취소될 때까지 붙잡는다.
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
            Issue.record("대본에 없는 요청: \(request.method) \(request.url)")
            throw .network
        }
        #expect(request.method == entry.exchange.method && request.url == entry.exchange.url,
                "기대한 요청은 \(entry.exchange.method) \(entry.exchange.url), 받은 것은 \(request.method) \(request.url)")
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

/// 가짜 set-dns: 받은 요청을 적고, 정해 둔 실패를 던진다.
final class FakeDNS: Sendable {
    private struct State {
        var calls: [(name: String, value: String)] = []
        var failure: ControlError?
        /// 참이면 `release()`까지 답하지 않는다.
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

/// 시험마다 하나씩 쓰는 상태 디렉터리. `SWIFTAIL_TEST_SCRATCH` 아래에 만들고 끝나면 지운다.
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

    /// 관리자를 거치지 않고 파일을 쓴다(저장된 인증서, 깨진 계정 키).
    func put(_ bytes: [UInt8], _ name: String) throws {
        let certs = url.appending(path: "certs", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: certs, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data(bytes).write(to: file(name))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(name).path)
    }
}

/// 관리자 하나와 그 접점.
struct ManagerHarness {
    static let name = TestPKI.domainName
    static let day: TimeInterval = 24 * 3600
    /// 발급하는 인증서의 수명. 2/3 지점은 발급 시각 + 60일이다.
    static let lifetime: TimeInterval = 90 * day

    let pki: TestPKI
    let scratch: ManagerScratch
    let clock = TestClock(TestPKI.now)
    let transport: ScriptedTransport
    let dns = FakeDNS()
    let manager: CertificateManager
    private let factsContinuation: AsyncStream<CertificateFacts>.Continuation
    /// 관리자가 만든 인증서 키(차례대로).
    private let keys = KeyLog()

    /// 시험 루트를 어디로 주는가.
    enum AnchorSource {
        /// 내부 초기화의 `anchors` 인자(대부분의 시험).
        case parameter
        /// 공개 설정의 `trustAnchors`(앱이 스테이징을 쓸 때의 길).
        case configuration
        /// 주지 않는다. 시스템 신뢰 저장소로 검증하므로 시험 루트의 사슬은 통과하지 못한다.
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

    /// `run()`을 돌린다. 끝난 결과를 돌려주는 Task다.
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

    // MARK: - 대본

    /// 발급 한 번의 대본. `firstAttempt`면 계정을 찾고, 아니면 아는 계정 URL로 곧바로 주문한다.
    ///
    /// 내려받기의 본문은 그때 관리자가 만든 마지막 인증서 키로 leaf를 만든다(발급 시각부터 90일). `leafName`·`leafKey`로
    /// 다른 이름·다른 키의 leaf를 낼 수 있다.
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

    /// 계정을 찾은 뒤 newOrder가 이 응답을 받는 대본(실패의 대본).
    func failingOrder(_ exchange: Exchange, firstAttempt: Bool = true) -> [ScriptedTransport.Entry] {
        let account: [Exchange] = firstAttempt
            ? Steps.accountFound
            : [.get(Fake.directoryURL, 200, Body.directory()), .head()]
        return (account + [exchange]).map { ScriptedTransport.Entry(exchange: $0) }
    }

    /// 저장된 인증서 파일을 둔다(관리자를 거치지 않고).
    func storeCertificate(
        name: String = ManagerHarness.name, key: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
        pairedKey: P256.Signing.PrivateKey? = nil, from start: Date, to end: Date
    ) throws {
        let leaf = pki.intermediate.leaf(name, publicKey: key.publicKey, from: start, to: end)
        try scratch.put(pemChain([leaf, pki.intermediate.certificate]), Self.name + ".crt")
        try scratch.put(Array((pairedKey ?? key).pemRepresentation.utf8), Self.name + ".key")
    }
}

/// 관리자가 만든 인증서 키의 기록.
final class KeyLog: Sendable {
    private let keys = Mutex<[P256.Signing.PrivateKey]>([])

    var all: [P256.Signing.PrivateKey] { keys.withLock { $0 } }

    func make() -> P256.Signing.PrivateKey {
        let key = P256.Signing.PrivateKey()
        keys.withLock { $0.append(key) }
        return key
    }
}

/// 조건이 설 때까지 짧게 기다린다. 시각을 넘기는 것이 아니라 다른 Task의 차례를 기다린다.
func eventually(
    _ message: String = "조건이 서지 않았다",
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

/// 관리자가 잠시 더 돌 틈을 준다(일어나지 않아야 할 일을 확인하기 전).
func settle() async throws {
    for _ in 0..<20 {
        await Task.yield()
    }
    try await Task.sleep(for: .milliseconds(30))
}

/// 흐름에 남은 것을 모두 꺼낸다. 흐름이 끝나 있어야 한다(`run()`이 돌아온 뒤).
func drain(_ stream: AsyncStream<TailnetCertificate>) async -> [TailnetCertificate] {
    var collected: [TailnetCertificate] = []
    for await certificate in stream { collected.append(certificate) }
    return collected
}
