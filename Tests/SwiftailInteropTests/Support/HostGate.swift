// Harness for M7 gate (a): the `tailnet` tool (testcontrol + DERP + STUN + pebble), two Go peers, and one `.inProcess` Swift node.
// Isolates and cleans up the tool and nodes like `withGate` in the existing gate (state directories are under TMPDIR).

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

/// One gate run. Starts a fresh tool and nodes for each test.
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
    /// Retains this to reuse the existing gate's injection helper (`Gate.inject(_:marker:)`).
    let gate: Gate
    static let fqdn = "rd-mac-1a2b3c4d.tail0001.test"

    /// A manager connected to pebble. Passes through the node's `package` interface, but it actually goes through a relay (restarting the manager needs
    /// a new stream. The node's stream has one subscriber and ends when the first manager stops).
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

    /// Deletes any stored certificate but keeps the account key, allowing fresh issuance with the same account.
    func removeStoredCertificate() throws {
        for suffix in ["crt", "key"] {
            let file = certificatesDirectory.appending(path: "\(Self.fqdn).\(suffix)")
            if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
        }
    }

    /// An HTTP request sent by a Go peer over the tailnet. The tool handles `peerHTTP` in the background, so send without waiting.
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

    /// The Go peer `name`'s `LocalClient().WhoIs(address)`.
    func goWhoIs(from name: String = "go-peer-a", _ address: SwiftailBase.IPAddress) async throws -> GoTailnet.Event {
        try await tool.command(.init(cmd: "peerWhoIs", name: name, to: address.description), expecting: "peerWhoIs")
    }

    /// Removes a peer from the Swift node's netmap (`PeersRemoved`). The tool's `removePeer` leaves the testcontrol list intact.
    /// This injection suppresses subsequent automatic maps for this node (README `injectMapResponse`). Use it only in the last stage of a test.
    func removeFromNetmap(_ peer: GatePeer, marker: UInt8) async throws {
        try await gate.inject(MapInjection(PeersRemoved: [try peer.mapNode.ID]), marker: marker)
    }
}

/// Consumes the node's single-subscriber `certificateFacts` stream and creates a fresh stream for each manager. A new subscriber starts with the most recent fact.
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

/// Wraps the production transport to count requests. Checks "no requests" (items 4 and 7) and `badNonce` retries (item 5).
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

/// The TXT value published by the manager and the `set-dns` round-trip time (item 2).
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

/// A clock offset from wall time by a test-specified amount (item 6). Waits sleep in short increments, so they wake soon after a clock change.
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

/// Calls `bridge.forward(_:toLoopbackPort:)` for each connection accepted on tailnet port 443 (or another port). Uses the current server's port
/// (switching to a new listener after renewal routes new connections there).
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

/// DER for one PEM certificate.
func certificateDER(fromPEM pem: String) throws -> [UInt8] {
    let body = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
    guard let data = Data(base64Encoded: body) else { throw GateFailure("Could not decode rootPEM") }
    return Array(data)
}

/// Checks whether the chain verifies with `anchor` as a TLS server certificate for `domain` (SSL server policy, current time).
func chainVerifies(_ chain: [[UInt8]], domain: String, anchor: [UInt8]) throws -> Bool {
    try chainVerifies(chain, domain: domain, anchors: [anchor])
}

/// Checks whether the chain verifies with only `anchors` as a TLS server certificate for `domain`.
func chainVerifies(_ chain: [[UInt8]], domain: String, anchors: [[UInt8]]) throws -> Bool {
    let certificates = try chain.map { try requireValue(SecCertificateCreateWithData(nil, Data($0) as CFData), "Could not decode the certificate") }
    var trust: SecTrust?
    guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateSSL(true, domain as CFString), &trust) == errSecSuccess,
          let trust else { return false }
    return trustEvaluates(trust, domain: domain, anchors: anchors)
}

/// Verifies `trust` at the current time with the SSL server policy for `domain` and only `anchors`. Does not fetch missing intermediates over the network.
func trustEvaluates(_ trust: SecTrust, domain: String, anchors: [[UInt8]]) -> Bool {
    let roots = anchors.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
    guard roots.count == anchors.count, !roots.isEmpty,
          SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, domain as CFString)) == errSecSuccess,
          SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
          SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
          SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { return false }
    return SecTrustEvaluateWithError(trust, nil)
}

/// What a direct TLS connection to the loopback port outside the bridge observed (item 9).
struct DirectTLSProbe: Sendable {
    var handshake = false
    /// The number of certificates the server sent (`sec_protocol_metadata_access_peer_certificate_chain`).
    var peerCertificates = 0
    var negotiatedALPN: String?
    var receivedBytes = 0
    var end = ""

    /// Accepts every certificate without evaluating trust. The probe only checks whether the server disconnects a connection missing from the table.
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
            // If the server does not close a rejected connection, this connection stays in setup. Waiting without a deadline would stall the gate.
            queue.asyncAfter(deadline: .now() + 10) { once.withLock { $0.take() }?.resume(returning: "Did not finish within 10 seconds") }
        }
        if let ready {
            result.withLock { $0.end = "Ended before readiness: \(ready)" }
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

/// Runs one gate by starting the tool, enabling pebble, and connecting two Go peers and a Swift node (`.inProcess`). Cleans up on success, failure, or cancellation.
func withHostGate(nonceReject: Int = 0, authzReuse: Int = 0, _ body: (HostGate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m7-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("Could not clean up the M7 state directory: \(redacted(String(describing: error)))") }
        }
    }
    var run: Task<Void, any Error>?
    var relay: FactsRelay?
    do {
        let state = directory.appending(path: "node")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        let ready = try await tool.start()
        let acme = try await tool.command(.init(cmd: "acmeStart", nonceReject: nonceReject, authzReuse: authzReuse), expecting: "acmeStart")
        let rootPEM = try requireValue(acme.rootPEM, "acmeStart returned no rootPEM")
        let directoryURL = try requireValue(acme.directoryURL.flatMap(URL.init(string:)), "acmeStart returned no directoryURL")
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
        try await netstackWait("Two Go peers in the Swift netmap") { await node.status.peerCount >= 2 }
        for name in ["go-peer-a", "go-peer-b"] {
            try await netstackWait("Swift node in the netmap of \(name)") {
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

/// Runs the manager and waits for the first certificate. The test cancels and joins the returned Task.
func runManager(_ manager: CertificateManager, waitingSeconds: Int = 120) async throws
    -> (task: Task<Void, any Error>, certificate: TailnetCertificate, seconds: Double) {
    let started = ContinuousClock.now
    let task = Task { try await manager.run() }
    do {
        let certificate = try await nextEvent(manager.certificates, waitingFor: "first certificate", timeout: .seconds(waitingSeconds))
        return (task, certificate, started.duration(to: .now).netstackSeconds)
    } catch {
        let status = await manager.status
        task.cancel()
        _ = await task.result
        throw GateFailure("Did not receive the first certificate: lastFailure \(String(describing: status.lastFailure)), nextAttempt \(String(describing: status.nextAttempt)). \(error)")
    }
}

func stopManager(_ task: Task<Void, any Error>) async {
    task.cancel()
    _ = await task.result
}

/// Waits until the manager's `status` meets the condition.
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
        throw GateFailure("\(stage): last status \(String(describing: last))")
    }
    return try requireValue(last)
}

extension TailnetCertificate {
    var publicKeyBytes: Data { privateKey.publicKey.x963Representation }
}
