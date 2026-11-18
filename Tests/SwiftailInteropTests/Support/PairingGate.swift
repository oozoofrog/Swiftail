// Harness for pairing gate (a) (docs/contracts/SwiftailPairing.md §7, 9–11) with the `tailnet` tool (testcontrol + DERP + STUN),
// `.inProcess` Swift nodes, and the host state machine attached to a loopback listener. Like the existing gates, it starts a fresh tool and nodes for each test and
// cleans them up on success, failure, or cancellation (the state directory is under TMPDIR). It starts no Go peers.

import Foundation
import Network
import Swiftail
import SwiftailBase
import Synchronization
import Testing

@testable import SwiftailPairing

/// One Swift node in the gate.
final class PairingNode: Sendable {
    let node: TailnetNode
    private let run: Task<Void, any Error>

    init(directory: URL, hostname: String, controlURL: URL, authKey: String?) throws {
        let node = try TailnetNode(
            configuration: .init(stateDirectory: directory, hostname: hostname, controlURL: controlURL, authKey: authKey),
            device: .inProcess)
        run = Task { try await node.run() }
        self.node = node
    }

    /// Stops and joins `run()`. Returns a description if it ended for a reason other than cancellation.
    @discardableResult
    func stop() async -> String? {
        run.cancel()
        if case .failure(let error) = await run.result, !(error is CancellationError) {
            return redacted(String(describing: error))
        }
        return nil
    }
}

/// The pairing gate for one test.
struct PairingGate: Sendable {
    /// The started nodes. Stops them all when the gate ends.
    final class Registry: Sendable {
        let nodes = Mutex<[PairingNode]>([])
    }

    let tool: GoTailnet
    let controlURL: URL
    let root: URL
    let registry: Registry

    func startNode(_ label: String, hostname: String, authKey: String? = nil) throws -> PairingNode {
        let node = try PairingNode(
            directory: root.appending(path: label), hostname: hostname, controlURL: controlURL, authKey: authKey)
        registry.nodes.withLock { $0.append(node) }
        return node
    }

    /// Waits until both nodes are `.running` and see each other in their netmaps.
    func waitUntilPeers(_ first: PairingNode, _ second: PairingNode) async throws {
        try await netstackWait("Both Swift nodes appear in each other's netmaps") {
            for (node, other) in [(first, second), (second, first)] {
                let status = await node.node.status
                guard status.state == .running, let address = await other.node.status.addresses.first,
                      await node.node.whoIs(address) != nil
                else { return false }
            }
            return true
        }
    }

    /// Creates the host and calls `body` while `run()` runs. Cancels and joins `run()` afterward.
    func withHost(
        _ node: PairingNode, port: UInt16 = 4_747, approver: Approver,
        _ body: (PairingHost) async throws -> Void
    ) async throws {
        let host = try await PairingHost(node: node.node, port: port, storeDirectory: root.appending(path: "store")) {
            await approver.decide($0)
        }
        let serving = Task { () async -> PairingError? in
            do throws(PairingError) {
                try await host.run()
                return nil
            } catch {
                return error
            }
        }
        do {
            try await body(host)
        } catch {
            serving.cancel()
            _ = await serving.value
            throw error
        }
        serving.cancel()
        let ending = await serving.value
        #expect(ending == nil, "Canceled run() returns without throwing")
    }
}

/// Starts and cleans up one pairing gate. If given `authKey`, the test control server accepts registration only with that key.
func withPairingGate(authKey: String? = nil, _ body: (PairingGate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m9-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    let registry = PairingGate.Registry()
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("Could not clean up the pairing gate state directory: \(redacted(String(describing: error)))") }
        }
    }
    func stopNodes() async -> [String] {
        var failures: [String] = []
        for node in registry.nodes.withLock({ $0 }) {
            if let failure = await node.stop() { failures.append(failure) }
        }
        return failures
    }
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        if let authKey {
            _ = try await tool.command(.init(cmd: "setAuth", authKey: authKey), expecting: "auth")
        }
        let gate = PairingGate(tool: tool, controlURL: try #require(ready.controlURL), root: directory, registry: registry)
        try await body(gate)
        _ = await stopNodes()
        await tool.stop()
    } catch {
        let failures = await stopNodes()
        await tool.stop()
        var detail = redacted(String(describing: error))
        if !failures.isEmpty { detail += "\nTailnetNode.run: \(failures.joined(separator: "; "))" }
        throw GateFailure("\(detail)\n\(await tool.diagnostics())")
    }
}

/// Acts as the host app's approval screen. Records requests and responds as configured.
final class Approver: Sendable {
    enum Answer: Sendable {
        case approve, deny
        /// Does not respond. Waits for cancellation (the edge cancels this Task when the other side disconnects).
        case wait
    }

    private struct State {
        var answer = Answer.approve
        var requests: [PairingRequest] = []
        var cancelledCount = 0
    }

    private let state = Mutex(State())

    var requests: [PairingRequest] { state.withLock { $0.requests } }
    /// The number of decisions canceled while waiting for a response.
    var cancelledCount: Int { state.withLock { $0.cancelledCount } }

    func set(_ answer: Answer) {
        state.withLock { $0.answer = answer }
    }

    func decide(_ request: PairingRequest) async -> Bool {
        let answer = state.withLock { state in
            state.requests.append(request)
            return state.answer
        }
        switch answer {
        case .approve: return true
        case .deny: return false
        case .wait:
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(1)) }
            state.withLock { $0.cancelledCount += 1 }
            return false
        }
    }
}

/// Collects the SAS that the joiner receives via `awaitingApproval`.
final class ConfirmationCodes: Sendable {
    private let codes = Mutex<[String]>([])
    private let arrivals: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation

    init() {
        (arrivals, continuation) = AsyncStream.makeStream(of: Void.self)
    }

    var all: [String] { codes.withLock { $0 } }

    func record(_ code: String) {
        codes.withLock { $0.append(code) }
        continuation.yield()
    }

    /// Waits for the next SAS.
    func next() async {
        for await _ in arrivals { return }
    }
}

/// The `PairingError` thrown by `body`, or nil if it does not throw. Any other error fails the test.
func pairingFailure<T>(_ body: () async throws -> T) async -> PairingError? {
    do {
        _ = try await body()
        return nil
    } catch let error as PairingError {
        return error
    } catch {
        Issue.record("Unexpected error type in place of PairingError: \(redacted(String(describing: error)))")
        return nil
    }
}

/// A host state machine attached to a loopback (`127.0.0.1`) listener (gate 11). There is no tailnet or node.
///
/// Verifies that the joiner's OS socket path (`NWConnection`) completes the procedure over real TCP. Because both endpoints have loopback addresses,
/// a test-only switch disables the joiner's address range checks. This path bypasses name resolution and the tunnel.
actor LoopbackPairingHost {
    /// The result of running one connection.
    struct Served: Sendable {
        var confirmationCode: String?
        var saved: PairedPeer?
        var ending: PairingHostMachine.Ending?
        /// The number of bytes received from the joiner.
        var receivedByteCount = 0
    }

    static let joinerIdentity = PeerIdentity(
        stableID: "nEXAMPLEJOINER", name: "rd-phone-5e6f7a8b.tail0001.ts.net", computedName: "rd-phone-5e6f7a8b",
        loginName: "alice@example.com")
    static let hostIdentity = PeerIdentity(
        stableID: "nEXAMPLEHOST", name: "rd-mac-1a2b3c4d.tail0001.ts.net", computedName: "rd-mac-1a2b3c4d",
        loginName: "alice@example.com")

    nonisolated let port: UInt16
    private let listener: NWListener
    private let accepted: AsyncStream<NWConnection>
    private var machine = PairingHostMachine()
    private var nextID: PairingHostMachine.SessionID = 0

    private init(listener: NWListener, port: UInt16, accepted: AsyncStream<NWConnection>) {
        self.listener = listener
        self.port = port
        self.accepted = accepted
    }

    static func start() async throws -> LoopbackPairingHost {
        let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        listener.newConnectionHandler = { sink.yield($0) }
        let (ports, ready) = AsyncStream.makeStream(of: UInt16?.self)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.yield(listener.port?.rawValue)
            case .failed, .cancelled: ready.yield(nil)
            default: break
            }
        }
        listener.start(queue: DispatchQueue(label: "test.pairing.listener"))
        var port: UInt16?
        for await value in ports {
            port = value
            break
        }
        guard let port else {
            listener.cancel()
            throw GateFailure("Could not open the loopback listener")
        }
        return LoopbackPairingHost(listener: listener, port: port, accepted: accepted)
    }

    nonisolated func close() {
        listener.cancel()
    }

    /// Opens a new offer. Uses the loopback address in place of the hostname (both sides just need to put the same string into T).
    func openOffer() -> PairingOffer {
        let offer = PairingOffer(
            host: "127.0.0.1", port: port, expires: Date().addingTimeInterval(300), authKey: nil,
            secret: PairingRandom.bytes(32))
        machine.open(offer)
        return offer
    }

    var hasOpenOffer: Bool { machine.hasOpenOffer }

    /// Accepts one more connection and runs the procedure to completion.
    func serveNext(approving: Bool) async throws -> Served {
        var connection: NWConnection?
        for await next in accepted {
            connection = next
            break
        }
        guard let connection else { throw GateFailure("The loopback listener closed") }
        let transport = SocketPairingTransport(connection)
        guard await transport.open(), let ends = transport.endpoints else {
            throw GateFailure("The accepted loopback connection did not become ready")
        }
        let id = nextID
        nextID += 1
        var served = Served()
        var actions = machine.accept(
            id, from: Self.joinerIdentity, endpoints: PairingEndpoints(joiner: ends.remote, host: ends.local),
            nonce: PairingRandom.bytes(32), at: .now)
        while true {
            while !actions.isEmpty {
                switch actions.removeFirst() {
                case .send(let bytes):
                    await transport.send(bytes)
                case .requestDecision(let request):
                    served.confirmationCode = request.confirmationCode
                    actions += machine.decided(
                        id, approved: approving, currentPeer: Self.joinerIdentity, host: Self.hostIdentity, at: Date())
                case .save(let peer):
                    served.saved = peer
                    actions += machine.saved(id, succeeded: true)
                case .finish(let ending):
                    served.ending = ending
                    await transport.close()
                    return served
                }
            }
            if let bytes = await transport.receive() {
                served.receivedByteCount += bytes.count
                actions = machine.receive(bytes, on: id, wallClock: Date(), now: .now)
            } else {
                actions = machine.connectionEnded(id)
            }
        }
    }
}
