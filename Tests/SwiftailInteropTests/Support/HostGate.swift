// M7 관문 (가)의 하네스: `tailnet` 도구(testcontrol + DERP + STUN + pebble), Go 피어 둘, `.inProcess` Swift 노드 하나.
// 기존 관문의 `withGate`와 같은 방식으로 도구와 노드를 격리하고 회수한다(상태 디렉터리는 TMPDIR 아래).

import CryptoKit
import Foundation
import Network
import Security
import Swiftail
import SwiftailBase
import SwiftailControl
import SwiftailLoopback
import Synchronization
import Testing

@testable import SwiftailCertificates

/// 관문의 한 실행. 도구·노드는 시험마다 새로 띄운다.
struct HostGate: Sendable {
    let tool: GoTailnet
    let node: TailnetNode
    let local: GatePeer
    let peerA: GatePeer
    let peerB: GatePeer
    let directoryURL: URL
    let rootPEM: String
    let rootDER: [UInt8]
    let facts: FactsRelay
    let setDNS: SetDNSRecorder
    /// 기존 관문의 주입 도우미(`Gate.inject(_:marker:)`)를 다시 쓰려고 쥔다.
    let gate: Gate
    static let fqdn = "rd-mac-1a2b3c4d.tail0001.test"

    /// pebble에 붙은 관리자. 노드의 `package` 접점을 그대로 넘기되, 사실은 중계를 거친다(관리자를 다시 띄우려면 흐름이
    /// 새로 필요하다. 노드의 흐름은 구독자 하나이고 첫 관리자가 멈추면 끝난다).
    func makeManager(transport: CountingTransport, clock: TestClock? = nil) throws -> CertificateManager {
        let node = self.node
        let recorder = setDNS
        let setDNS: CertificateManager.SetDNS = { name, value throws(ControlError) in
            try await recorder.record(name: name, value: value) { () async throws(ControlError) in
                try await node.setDNS(name: name, value: value)
            }
        }
        let configuration = CertificateConfiguration(directoryURL: directoryURL)
        if let clock {
            return try CertificateManager(facts: facts.subscribe(), setDNS: setDNS, stateDirectory: node.stateDirectory,
                                          transport: transport, configuration: configuration, anchors: .only([rootDER]),
                                          now: { clock.now() }, sleep: { date throws(CancellationError) in try await clock.sleep(until: date) })
        }
        return try CertificateManager(facts: facts.subscribe(), setDNS: setDNS, stateDirectory: node.stateDirectory,
                                      transport: transport, configuration: configuration, anchors: .only([rootDER]))
    }

    func makeTransport() -> CountingTransport {
        CountingTransport(URLSessionACMETransport(trustAnchors: [rootDER]))
    }

    var certificatesDirectory: URL { node.stateDirectory.appending(path: "certs") }

    /// 저장된 인증서가 있으면 지운다(계정 키는 남긴다). 같은 계정으로 새로 발급하게 한다.
    func removeStoredCertificate() throws {
        for suffix in ["crt", "key"] {
            let file = certificatesDirectory.appending(path: "\(Self.fqdn).\(suffix)")
            if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
        }
    }

    /// Go 피어가 tailnet으로 보내는 HTTP 요청. `peerHTTP`는 도구가 뒤에서 처리하므로 기다리지 않고 보낸다.
    func startHTTP(_ peer: String, path: String, method: String = "GET", range: String? = nil, body: UInt64? = nil,
                   scheme: String = "https", port: UInt16? = nil, timeout: Int = 60) async throws -> Int {
        let authority = port.map { "\(Self.fqdn):\($0)" } ?? Self.fqdn
        return try await tool.send(.init(cmd: "peerHTTP", name: peer, send: body, seed: body.map { _ in 1 },
            timeoutSec: timeout, url: "\(scheme)://\(authority)\(path)", method: method, range: range,
            rootPEM: scheme == "https" ? rootPEM : nil))
    }

    func http(_ peer: String, path: String, method: String = "GET", range: String? = nil, body: UInt64? = nil,
              scheme: String = "https", port: UInt16? = nil, timeout: Int = 60) async throws -> GoTailnet.Event {
        let id = try await startHTTP(peer, path: path, method: method, range: range, body: body, scheme: scheme, port: port, timeout: timeout)
        return try await tool.response(to: id, expecting: "peerHTTP", timeout: .seconds(timeout + 10))
    }

    /// Go 피어 `name`의 `LocalClient().WhoIs(address)`.
    func goWhoIs(from name: String = "go-peer-a", _ address: SwiftailBase.IPAddress) async throws -> GoTailnet.Event {
        try await tool.command(.init(cmd: "peerWhoIs", name: name, to: address.description), expecting: "peerWhoIs")
    }

    /// Swift 노드의 netmap에서 피어를 뺀다(`PeersRemoved`). 도구의 `removePeer`는 testcontrol의 목록을 지우지 않는다.
    /// 이 주입 뒤로 이 노드의 자동 맵은 억제된다(README `injectMapResponse`). 시험의 마지막 단계에서만 쓴다.
    func removeFromNetmap(_ peer: GatePeer, marker: UInt8) async throws {
        try await gate.inject(MapInjection(PeersRemoved: [try peer.mapNode.ID]), marker: marker)
    }
}

/// 노드의 `certificateFacts`(구독자 하나)를 받아 관리자마다 새 흐름으로 나눈다. 새 구독은 마지막 사실부터 받는다.
final class FactsRelay: Sendable {
    private struct State {
        var latest: CertificateFacts?
        var sinks: [UUID: AsyncStream<CertificateFacts>.Continuation] = [:]
        var task: Task<Void, Never>?
    }

    private let state = Mutex(State())

    static func start(_ node: TailnetNode) -> FactsRelay {
        let relay = FactsRelay()
        let task = Task {
            for await facts in node.certificateFacts { relay.publish(facts) }
            relay.finish()
        }
        relay.state.withLock { $0.task = task }
        return relay
    }

    var latest: CertificateFacts? { state.withLock { $0.latest } }

    func subscribe() -> AsyncStream<CertificateFacts> {
        let (stream, sink) = AsyncStream.makeStream(of: CertificateFacts.self, bufferingPolicy: .bufferingNewest(1))
        let id = UUID()
        state.withLock { state in
            if let latest = state.latest { sink.yield(latest) }
            state.sinks[id] = sink
        }
        sink.onTermination = { [weak self] _ in self?.state.withLock { _ = $0.sinks.removeValue(forKey: id) } }
        return stream
    }

    private func publish(_ facts: CertificateFacts) {
        let sinks = state.withLock { state in
            state.latest = facts
            return Array(state.sinks.values)
        }
        for sink in sinks { sink.yield(facts) }
    }

    private func finish() {
        let sinks = state.withLock { Array($0.sinks.values) }
        for sink in sinks { sink.finish() }
    }

    func close() {
        let task = state.withLock { $0.task }
        task?.cancel()
    }
}

/// 운영 전송을 감싸 요청을 센다. "요청 없음"(항목 4·7)과 `badNonce` 재시도(항목 5)를 본다.
final class CountingTransport: ACMETransport {
    struct Exchange: Sendable {
        let method: ACMEHTTPRequest.Method
        let status: Int?
        let problemType: String?
    }

    private let inner: any ACMETransport
    private let log = Mutex<[Exchange]>([])

    init(_ inner: any ACMETransport) { self.inner = inner }

    var exchanges: [Exchange] { log.withLock { $0 } }
    var count: Int { log.withLock { $0.count } }
    var badNonceCount: Int { exchanges.filter { $0.problemType == "urn:ietf:params:acme:error:badNonce" }.count }

    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse {
        do {
            let response = try await inner.send(request)
            var problem: String?
            if !(200..<300).contains(response.status),
               let object = try? JSONSerialization.jsonObject(with: Data(response.body)) as? [String: Any] {
                problem = object["type"] as? String
            }
            log.withLock { $0.append(Exchange(method: request.method, status: response.status, problemType: problem)) }
            return response
        } catch {
            log.withLock { $0.append(Exchange(method: request.method, status: nil, problemType: nil)) }
            throw error
        }
    }
}

/// 관리자가 올린 TXT와 `set-dns` 왕복 시간(항목 2).
final class SetDNSRecorder: Sendable {
    struct Call: Sendable {
        let name: String
        let value: String
        let seconds: Double
        let failure: String?
    }

    private let calls = Mutex<[Call]>([])
    var all: [Call] { calls.withLock { $0 } }

    func record(name: String, value: String, _ body: () async throws(ControlError) -> Void) async throws(ControlError) {
        let started = ContinuousClock.now
        do {
            try await body()
            let seconds = started.duration(to: .now).netstackSeconds
            calls.withLock { $0.append(Call(name: name, value: value, seconds: seconds, failure: nil)) }
        } catch {
            let seconds = started.duration(to: .now).netstackSeconds
            calls.withLock { $0.append(Call(name: name, value: value, seconds: seconds, failure: "\(error)")) }
            throw error
        }
    }
}

/// 벽시계에 시험이 정한 만큼을 더한 시계(항목 6). 기다림은 짧게 나눠 자므로 시계를 옮기면 곧 깬다.
final class TestClock: Sendable {
    private let offset = Mutex<TimeInterval>(0)

    func now() -> Date { Date().addingTimeInterval(offset.withLock { $0 }) }

    func advance(by interval: TimeInterval) { offset.withLock { $0 += interval } }

    func sleep(until date: Date) async throws(CancellationError) {
        while true {
            let remaining = date.timeIntervalSince(now())
            guard remaining > 0 else { return }
            do { try await Task.sleep(for: .seconds(min(remaining, 0.2))) } catch { throw CancellationError() }
        }
    }
}

/// tailnet 443(또는 다른 포트)에서 받은 연결마다 `bridge.forward(_:toLoopbackPort:)`를 부른다. 포트는 지금 서버의 것이다
/// (갱신 뒤 새 리스너로 바꾸면 새 연결부터 그쪽으로 간다).
final class BridgeAcceptor: Sendable {
    private let route = Mutex<UInt16>(0)
    private let errors = Mutex<[LoopbackBridgeError]>([])
    private let task = Mutex<Task<Void, Never>?>(nil)
    let listener: TailnetListener

    init(listener: TailnetListener, bridge: LoopbackBridge, port: UInt16) {
        self.listener = listener
        route.withLock { $0 = port }
        let started = Task {
            await withDiscardingTaskGroup { group in
                for await connection in listener {
                    let port = self.route.withLock { $0 }
                    group.addTask {
                        do throws(LoopbackBridgeError) { try await bridge.forward(connection, toLoopbackPort: port) }
                        catch { self.errors.withLock { $0.append(error) } }
                    }
                }
            }
        }
        task.withLock { $0 = started }
    }

    var forwardErrors: [LoopbackBridgeError] { errors.withLock { $0 } }

    func switchTo(port: UInt16) { route.withLock { $0 = port } }

    func close() async {
        await listener.close()
        let running = task.withLock { $0 }
        running?.cancel()
        await running?.value
    }
}

/// PEM 인증서 하나의 DER.
func certificateDER(fromPEM pem: String) throws -> [UInt8] {
    let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
    guard let data = Data(base64Encoded: body) else { throw GateFailure("rootPEM을 해석하지 못함") }
    return Array(data)
}

/// 사슬이 `anchor`로 `domain`의 TLS 서버 인증서로 검증되는가(SSL 서버 정책, 지금 시각).
func chainVerifies(_ chain: [[UInt8]], domain: String, anchor: [UInt8]) throws -> Bool {
    try chainVerifies(chain, domain: domain, anchors: [anchor])
}

/// 사슬이 `anchors`(이것들만)로 `domain`의 TLS 서버 인증서로 검증되는가.
func chainVerifies(_ chain: [[UInt8]], domain: String, anchors: [[UInt8]]) throws -> Bool {
    let certificates = try chain.map { try requireValue(SecCertificateCreateWithData(nil, Data($0) as CFData), "인증서 해석 실패") }
    var trust: SecTrust?
    guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateSSL(true, domain as CFString), &trust) == errSecSuccess,
          let trust else { return false }
    return trustEvaluates(trust, domain: domain, anchors: anchors)
}

/// `trust`를 `domain`의 SSL 서버 정책과 `anchors`만으로 지금 시각에 검증한다. 빠진 중간 인증서를 네트워크에서 받지 않는다.
func trustEvaluates(_ trust: SecTrust, domain: String, anchors: [[UInt8]]) -> Bool {
    let roots = anchors.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
    guard roots.count == anchors.count, !roots.isEmpty,
          SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, domain as CFString)) == errSecSuccess,
          SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
          SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
          SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { return false }
    return SecTrustEvaluateWithError(trust, nil)
}

/// 다리 밖에서 루프백 포트로 직접 건 TLS 연결이 본 것(항목 9).
struct DirectTLSProbe: Sendable {
    var handshake = false
    /// 서버가 보낸 인증서 수(`sec_protocol_metadata_access_peer_certificate_chain`).
    var peerCertificates = 0
    var negotiatedALPN: String?
    var receivedBytes = 0
    var end = ""

    /// 신뢰 판단은 하지 않는다(모두 받는다). 이 탐침은 서버가 표에 없는 연결을 끊는지만 본다.
    static func run(port: UInt16, domain: String) async -> DirectTLSProbe {
        let result = Mutex(DirectTLSProbe())
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(options, domain)
        sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
        let queue = DispatchQueue(label: "test.direct.tls")
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            result.withLock { $0.peerCertificates = 0 }
            sec_protocol_metadata_access_peer_certificate_chain(metadata) { _ in result.withLock { $0.peerCertificates += 1 } }
            complete(true)
        }, queue)
        let connection = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port) ?? .any,
                                      using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
        let ready = await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let once = Mutex<CheckedContinuation<String?, Never>?>(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: once.withLock { $0.take() }?.resume(returning: nil)
                case .failed(let error): once.withLock { $0.take() }?.resume(returning: MinimalHTTPServer.describe(error))
                case .waiting(let error): once.withLock { $0.take() }?.resume(returning: "waiting \(MinimalHTTPServer.describe(error))")
                case .cancelled: once.withLock { $0.take() }?.resume(returning: "cancelled")
                default: break
                }
            }
            connection.start(queue: queue)
            // 서버가 거절한 연결을 닫지 않으면 이 연결은 준비 중에 머문다. 기한 없이 기다리면 관문이 멈춘다.
            queue.asyncAfter(deadline: .now() + 10) { once.withLock { $0.take() }?.resume(returning: "10초 안에 끝나지 않음") }
        }
        if let ready {
            result.withLock { $0.end = "준비 전 끝: \(ready)" }
            connection.cancel()
            return result.withLock { $0 }
        }
        if let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
           let alpn = sec_protocol_metadata_get_negotiated_protocol(metadata.securityProtocolMetadata) {
            let protocolName = String(cString: alpn)
            result.withLock { $0.negotiatedALPN = protocolName }
        }
        result.withLock { $0.handshake = true }
        _ = await MinimalHTTPServer.send(connection, Array("POST /pair HTTP/1.1\r\nHost: \(domain)\r\nContent-Length: 0\r\n\r\n".utf8))
        let deadline = ContinuousClock.now + .seconds(5)
        loop: while ContinuousClock.now < deadline {
            switch await MinimalHTTPServer.receive(connection) {
            case .bytes(let bytes): result.withLock { $0.receivedBytes += bytes.count }
            case .end: result.withLock { $0.end = "eof" }; break loop
            case .failed(let error): result.withLock { $0.end = "error(\(error))" }; break loop
            }
        }
        connection.cancel()
        return result.withLock { $0 }
    }
}

/// 관문 하나: 도구를 띄우고 pebble을 켠 뒤 Go 피어 둘과 Swift 노드(`.inProcess`)를 붙인다. 성공·실패·취소에서 모두 회수한다.
func withHostGate(nonceReject: Int = 0, authzReuse: Int = 0, _ body: (HostGate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m7-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("M7 상태 디렉터리 정리 실패: \(redacted(String(describing: error)))") }
        }
    }
    var run: Task<Void, any Error>?
    var relay: FactsRelay?
    do {
        let state = directory.appending(path: "node")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        let ready = try await tool.start()
        let acme = try await tool.command(.init(cmd: "acmeStart", nonceReject: nonceReject, authzReuse: authzReuse), expecting: "acmeStart")
        let rootPEM = try requireValue(acme.rootPEM, "acmeStart rootPEM 없음")
        let directoryURL = try requireValue(acme.directoryURL.flatMap(URL.init(string:)), "acmeStart directoryURL 없음")
        let peerA = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer"))
        let peerB = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer"))
        let node = try TailnetNode(configuration: .init(stateDirectory: state, hostname: "rd-mac-1a2b3c4d",
                                                      controlURL: try #require(ready.controlURL)), device: .inProcess)
        relay = FactsRelay.start(node)
        run = Task { try await node.run() }
        let addresses = try await running(node)
        let runningAt = ContinuousClock.now
        let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
        let local = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) })
        let localPeer = GatePeer(key: local.nodeKey, addresses: addresses)
        try await netstackWait("Swift netmap의 Go 피어 둘") { await node.status.peerCount >= 2 }
        for name in ["go-peer-a", "go-peer-b"] {
            try await netstackWait("\(name)의 netmap에 Swift 노드") {
                let status = try await tool.command(.init(cmd: "peerStatus", name: name), expecting: "peerStatus")
                return status.peers?.contains { $0.nodeKey == local.nodeKey } == true
            }
        }
        let gate = Gate(tool: tool, node: node, local: localPeer, peer: peerA, witness: peerB, runningAt: runningAt,
                        controlURL: ready.controlURL)
        let host = HostGate(tool: tool, node: node, local: localPeer, peerA: peerA, peerB: peerB, directoryURL: directoryURL,
                            rootPEM: rootPEM, rootDER: try certificateDER(fromPEM: rootPEM), facts: try requireValue(relay),
                            setDNS: SetDNSRecorder(), gate: gate)
        try await body(host)
        relay?.close()
        run?.cancel()
        await tool.stop()
        _ = await run?.result
    } catch {
        relay?.close()
        run?.cancel()
        await tool.stop()
        let result = await run?.result
        var detail = redacted(String(describing: error))
        if case .failure(let failure) = result { detail += "\nTailnetNode.run: \(redacted(String(describing: failure)))" }
        throw GateFailure("\(detail)\n\(await tool.diagnostics())")
    }
}

/// 관리자를 돌리고 첫 인증서를 기다린다. 돌려준 Task는 시험이 취소하고 회수한다.
func runManager(_ manager: CertificateManager, waitingSeconds: Int = 120) async throws
    -> (task: Task<Void, any Error>, certificate: TailnetCertificate, seconds: Double) {
    let started = ContinuousClock.now
    let task = Task { try await manager.run() }
    do {
        let certificate = try await nextEvent(manager.certificates, waitingFor: "첫 인증서", timeout: .seconds(waitingSeconds))
        return (task, certificate, started.duration(to: .now).netstackSeconds)
    } catch {
        let status = await manager.status
        task.cancel()
        _ = await task.result
        throw GateFailure("첫 인증서를 받지 못함: lastFailure \(String(describing: status.lastFailure)), nextAttempt \(String(describing: status.nextAttempt)); \(error)")
    }
}

func stopManager(_ task: Task<Void, any Error>) async {
    task.cancel()
    _ = await task.result
}

/// 관리자의 `status`가 조건을 채울 때까지 기다린다.
func waitForStatus(_ manager: CertificateManager, _ stage: String, seconds: Int = 60,
                   _ predicate: @escaping @Sendable (CertificateStatus) -> Bool) async throws -> CertificateStatus {
    var last: CertificateStatus?
    do {
        try await netstackWait(stage, seconds: seconds) {
            let status = await manager.status
            last = status
            return predicate(status)
        }
    } catch {
        throw GateFailure("\(stage): 마지막 status \(String(describing: last))")
    }
    return try requireValue(last)
}

extension TailnetCertificate {
    var publicKeyBytes: Data { privateKey.publicKey.x963Representation }
}
