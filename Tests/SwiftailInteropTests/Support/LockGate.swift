// Harness for Tailnet Lock gate (a) (docs/contracts/SwiftailTailnetLock.md §7): the `tailnet` tool (testcontrol copy + DERP + STUN),
// a Go peer acting as the signing device, and Swift nodes on in-memory devices. Like `withGate` in the existing gate, starts a fresh tool and nodes per test and
// cleans up on success, failure, or cancellation (the state directory is under TMPDIR).

import Foundation
import SwiftailBase
import SwiftailControl
import Synchronization
import Testing

@testable import Swiftail

/// Collects node events and received packets throughout `run()`.
///
/// Each stream has one subscriber, and canceling a pending read at a deadline ends the stream. Waiters therefore poll this record instead of
/// reading the streams directly.
final class NodeRecorder: Sendable {
    /// One event and the `status` read immediately after receiving it.
    struct Entry: Sendable {
        let event: NodeEvent
        let status: NodeStatus
    }

    private let entries = Mutex<[Entry]>([])
    private let received = Mutex<[ReceivedPacket]>([])

    func append(_ event: NodeEvent, _ status: NodeStatus) { entries.withLock { $0.append(.init(event: event, status: status)) } }
    func append(_ packet: ReceivedPacket) { received.withLock { $0.append(packet) } }

    var events: [Entry] { entries.withLock { $0 } }
    var packetCount: Int { received.withLock { $0.count } }

    /// Checks whether any packet received at or after index `start` matches `predicate`.
    func received(since start: Int, where predicate: (ReceivedPacket) -> Bool) -> Bool {
        received.withLock { $0.dropFirst(start).contains(where: predicate) }
    }

    /// The received `tailnetLockChanged` values in arrival order.
    var lockChanges: [TailnetLockStatus] {
        events.compactMap { if case let .tailnetLockChanged(lock) = $0.event { lock } else { nil } }
    }
}

/// A Swift node in the gate. Its in-memory device exchanges UDP and TCP as packets (the same path as in existing gates 3 and 4).
final class LockNode: Sendable {
    let node: TailnetNode
    let directory: URL
    let recorder: NodeRecorder
    private let run: Task<Void, any Error>
    private let collectors: [Task<Void, Never>]

    init(directory: URL, hostname: String, controlURL: URL, authKey: String?) throws {
        let node = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: hostname,
                                                        controlURL: controlURL, authKey: authKey), device: .memory())
        let recorder = NodeRecorder()
        collectors = [
            Task {
                for await event in node.events { recorder.append(event, await node.status) }
            },
            Task {
                // This gate sends only UDP and TCP. Skip other packets (ICMP, for example) because they cannot be parsed.
                for await bytes in node.inboundPackets { if let packet = try? ReceivedPacket(bytes) { recorder.append(packet) } }
            },
        ]
        run = Task { try await node.run() }
        self.node = node
        self.directory = directory
        self.recorder = recorder
    }

    /// Stops and joins `run()`. Returns a description if it ended for a reason other than cancellation.
    @discardableResult
    func stop() async -> String? {
        run.cancel()
        let result = await run.result
        for collector in collectors { await collector.value }
        if case .failure(let error) = result, !(error is CancellationError) { return redacted(String(describing: error)) }
        return nil
    }

    var status: NodeStatus { get async { await node.status } }

    /// Node keys of peers in the Swift node's filtered netmap.
    var peerKeys: Set<String> { get async { Set(await node.lastNetmap?.peers.map(\.key.description) ?? []) } }

    /// The node's own node key. Nil before the netmap arrives.
    var selfKey: String? { get async { await node.lastNetmap?.selfNode.key.description } }

    var lockFile: URL { directory.appending(path: "tailnet-lock.cbor") }

    func address() async throws -> IPAddress {
        try #require(await status.addresses.first { $0.isIPv4 })
    }
}

/// The lock gate for one test.
struct LockGate: Sendable {
    /// How long to wait when expecting no response. In the working case, the first packet usually arrives within 1 second via loopback DERP (observations go in
    /// each stage's checkpoint). This window comfortably covers the initial WireGuard handshake and retransmission interval (0.5 seconds).
    static let silence: Duration = .seconds(6)
    /// Time limit for the working case.
    static let reachable: Duration = .seconds(25)

    final class Registry: Sendable {
        struct State {
            var nodes: [LockNode] = []
            var names: [String: String] = [:]
            var nextPort: UInt16 = 43_100
        }
        let state = Mutex(State())
    }

    let tool: GoTailnet
    let controlURL: URL
    let root: URL
    let registry: Registry

    // MARK: Tool commands

    func command(_ value: GoTailnet.Command, expecting kind: String) async throws -> GoTailnet.Event {
        try await tool.command(value, expecting: kind)
    }

    func addPeer(_ name: String, authKey: String? = nil) async throws -> GatePeer {
        let peer = try GatePeer(await command(.init(cmd: "addPeer", name: name, authKey: authKey), expecting: "peer"))
        self.name(peer.key, name)
        return peer
    }

    func lockStatus(_ name: String) async throws -> GoTailnet.Event {
        try await command(.init(cmd: "lockStatus", name: name), expecting: "lockStatus")
    }

    func registrations() async throws -> [GoTailnet.LockRegistration] {
        try #require(await command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
    }

    /// The `/machine/tka/` requests received by testcontrol.
    func tkaRequests() async throws -> [GoTailnet.SetDNSRequest] {
        try #require(await command(.init(cmd: "lockRequests"), expecting: "lockRequests").requests)
    }

    /// Number of `/machine/tka/<kind>` requests sent by `nodeKey`.
    func tkaRequestCount(_ kind: String, from nodeKey: String) async throws -> Int {
        try await tkaRequests().count { $0.path == "/machine/tka/\(kind)" && $0.nodeKey == nodeKey }
    }

    /// All node keys in the testcontrol registration list.
    func registeredKeys() async throws -> Set<String> {
        Set(try #require(await command(.init(cmd: "nodes"), expecting: "nodes").nodes).map(\.nodeKey))
    }

    func setBootstrapFault(_ enabled: Bool) async throws {
        _ = try await command(.init(cmd: "setLockBootstrapFault", enabled: enabled), expecting: "lockBootstrapFault")
    }

    // MARK: Names

    /// Uses names instead of keys in reports.
    func name(_ key: String, _ name: String) { registry.state.withLock { $0.names[key] = name } }

    func names(_ keys: Set<String>) -> String {
        let names = registry.state.withLock { state in keys.map { state.names[$0] ?? "unnamed node" } }
        return "[" + names.sorted().joined(separator: ", ") + "]"
    }

    // MARK: Swift nodes

    func startNode(_ label: String, hostname: String = "rd-mac-1a2b3c4d", authKey: String? = nil) throws -> LockNode {
        let node = try LockNode(directory: root.appending(path: label), hostname: hostname,
                                controlURL: controlURL, authKey: authKey)
        registry.state.withLock { $0.nodes.append(node) }
        return node
    }

    /// Waits until the Swift node's `status` satisfies `predicate` and returns that value.
    @discardableResult
    func wait(_ node: LockNode, _ stage: String, seconds: Int = 30,
              _ predicate: @Sendable (NodeStatus) -> Bool) async throws -> NodeStatus {
        var last: NodeStatus?
        do {
            try await netstackWait(stage, seconds: seconds) {
                let status = await node.status
                last = status
                return predicate(status)
            }
        } catch {
            throw GateFailure("\(error) — last status: \(describe(last))")
        }
        return try #require(last)
    }

    /// Checks that `predicate` stays true for `seconds` for a condition that should not change.
    func holds(_ node: LockNode, _ stage: String, seconds: Int = 3,
               _ predicate: @Sendable (NodeStatus) -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(seconds)
        while ContinuousClock.now < deadline {
            let status = await node.status
            guard predicate(status) else { throw GateFailure("\(stage): changed when it should have stayed the same — \(describe(status))") }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    func describe(_ status: NodeStatus?) -> String {
        guard let status else { return "none" }
        let lock = status.tailnetLock
        return "state \(status.state), mode \(lock.mode), issue \(lock.issue.map { "\($0)" } ?? "none"), "
            + "head \(lock.head.map { String($0.prefix(8)) } ?? "none"), signingRequest \(lock.signingRequest == nil ? "absent" : "present"), "
            + "peerCount \(status.peerCount), filteredPeerCount \(lock.filteredPeerCount)"
    }

    // MARK: Comparing decisions

    /// Waits for Go peer `goName` and the Swift node to agree at the same point in time (contract §7, gate (a) 5).
    ///
    /// Compares head text, visible peers (Go's `visiblePeers`, including the signed Go peer itself) with peers in the Swift netmap, and filtered peers (Go's
    /// `filteredPeers`, including the unsigned Go peer itself) with peers Swift filtered (the testcontrol registration list minus the peers Swift kept and Swift itself)
    /// and their count (`filteredPeerCount`). Also compares whether Go filters the Swift node with the Swift node's own lockout (`signingRequest`). The Swift node itself is removed from both Go sets. This server does not supply `UnsignedPeerAPIOnly`.
    /// If `controlHead` is present (server lock is enabled), the head must match it as well.
    func expectAgreement(_ node: LockNode, with goName: String, _ stage: String, seconds: Int = 30) async throws {
        var detail = ""
        do {
            try await netstackWait("\(stage): \(goName) and Swift node decisions", seconds: seconds) {
                let go = try await lockStatus(goName)
                let status = await node.status
                let swiftPeers = await node.peerKeys
                guard let selfKey = await node.selfKey, let goKey = go.nodeKey else { return false }
                let registered = try await registeredKeys()
                // Include the Go peer itself on the visible side if its own signature verifies (`nodeKeySigned`), and on the filtered side otherwise.
                let goSigned = go.nodeKeySigned == true
                let goVisible = Set(go.visiblePeers ?? []).union(goSigned ? [goKey] : []).subtracting([selfKey])
                let goFiltered = Set(go.filteredPeers ?? []).union(goSigned ? [] : [goKey]).subtracting([selfKey])
                // Self lockout: Go filtering Swift matches the Swift node treating itself as locked.
                let goFiltersSwift = go.filteredPeers?.contains(selfKey) == true
                let goSeesSwift = go.visiblePeers?.contains(selfKey) == true
                let swiftLocked = status.tailnetLock.signingRequest != nil
                let swiftFiltered = registered.subtracting(swiftPeers).subtracting([selfKey])
                let controlHead = go.controlHead ?? ""
                detail = "Go visible \(names(goVisible)) / Swift visible \(names(swiftPeers)); "
                    + "Go filtered \(names(goFiltered)) / Swift filtered \(names(swiftFiltered)) (filteredPeerCount \(status.tailnetLock.filteredPeerCount)); "
                    + "Swift locked \(swiftLocked) / Go filters \(goFiltersSwift) and sees \(goSeesSwift); "
                    + "Head matches Go=\(status.tailnetLock.head == go.head) server=\(controlHead.isEmpty ? "server lock disabled" : "\(status.tailnetLock.head == controlHead)")"
                return go.enabled == true && status.tailnetLock.mode == .enforcing
                    && status.tailnetLock.head != nil && status.tailnetLock.head == go.head
                    && (controlHead.isEmpty || controlHead == go.head)
                    && goVisible == swiftPeers && goFiltered == swiftFiltered
                    && swiftFiltered.count == status.tailnetLock.filteredPeerCount
                    && status.peerCount == swiftPeers.count
                    && goFiltersSwift == swiftLocked && goSeesSwift == !swiftLocked
            }
        } catch {
            Issue.record("\(stage): Go and Swift decisions differ — \(detail)")
            throw error
        }
        await tool.checkpoint("\(stage): same decision as \(goName) — \(detail)")
    }

    // MARK: Data plane

    private func nextPort() -> UInt16 {
        registry.state.withLock { state in
            defer { state.nextPort += 1 }
            return state.nextPort
        }
    }

    /// Time for the Swift node to receive a UDP echo from `peer` (port 7), or nil if it does not arrive within `within`.
    func udpEcho(from node: LockNode, to peer: GatePeer, within: Duration) async throws -> Duration? {
        let port = nextPort()
        let payload = Array("tl10-\(port)".utf8)
        let source = try await node.address(), destination = try peer.address()
        let packet = Packets.udp(from: source, port: port, to: destination, payload: payload)
        return try await exchange(node, within: within, send: { await node.node.send(packet) }) {
            $0.proto == 17 && $0.source == destination && $0.sourcePort == 7 && $0.destinationPort == port && $0.payload == payload
        }
    }

    /// Time until `peer`'s TCP port 7 answers the Swift node's SYN with SYN-ACK, or nil if no reply arrives.
    func tcpHandshake(from node: LockNode, to peer: GatePeer, within: Duration) async throws -> Duration? {
        let port = nextPort()
        let source = try await node.address(), destination = try peer.address()
        let syn = Packets.syn(from: source, port: port, to: destination, destinationPort: 7, sequence: UInt32(port) << 16)
        return try await exchange(node, within: within, send: { await node.node.send(syn) }) {
            $0.proto == 6 && $0.source == destination && $0.sourcePort == 7 && $0.destinationPort == port
                && $0.flags & 0x12 == 0x12 && $0.acknowledgement == UInt32(port) << 16 &+ 1
        }
    }

    /// Time until a UDP datagram or TCP SYN from Go peer `goName` reaches the Swift node's device, or nil if it never arrives.
    ///
    /// For an in-memory device, only packets that pass the filter appear in `inboundPackets`. If a packet does not arrive, the Swift node cannot answer it.
    func goSend(_ goName: String, to node: LockNode, proto: String, within: Duration) async throws -> Duration? {
        let port = nextPort()
        let payload = Array("tl10-\(port)".utf8)
        let target = try await node.address().description
        return try await exchange(node, within: within, send: {
            // For TCP, the tool attempts to connect for 2 seconds (Go retransmits SYN during that time). The write result does not guarantee receipt, so ignore it.
            _ = try await command(.init(cmd: "peerSend", name: goName, to: target, port: port, proto: proto, payload: payload.hex),
                                  expecting: "peerSend")
        }) {
            $0.destinationPort == port && (proto == "udp" ? $0.proto == 17 && $0.payload == payload : $0.proto == 6 && $0.flags & 0x12 == 0x02)
        }
    }

    /// Repeats `send` every 0.5 seconds and looks in the record for a packet matching `predicate`.
    private func exchange(_ node: LockNode, within: Duration, send: () async throws -> Void,
                          matching predicate: (ReceivedPacket) -> Bool) async throws -> Duration? {
        let start = ContinuousClock.now, mark = node.recorder.packetCount
        while start.duration(to: .now) < within {
            try await send()
            let resend = ContinuousClock.now + .milliseconds(500)
            while ContinuousClock.now < resend {
                if node.recorder.received(since: mark, where: predicate) { return start.duration(to: .now) }
                try await Task.sleep(for: .milliseconds(25))
            }
        }
        return node.recorder.received(since: mark, where: predicate) ? start.duration(to: .now) : nil
    }

    /// Reachable case: the packet must arrive within `within`. Records the elapsed time.
    func expectReachable(_ stage: String, _ probe: () async throws -> Duration?) async throws {
        guard let elapsed = try await probe() else { throw GateFailure("\(stage): did not arrive within \(Self.reachable)") }
        await tool.checkpoint("\(stage): \(elapsed.formatted(.units(allowed: [.milliseconds])))")
    }

    /// Unreachable case: no packet must arrive during `silence`.
    func expectSilent(_ stage: String, _ probe: () async throws -> Duration?) async throws {
        if let elapsed = try await probe() {
            Issue.record("\(stage): unexpectedly arrived after \(elapsed.formatted(.units(allowed: [.milliseconds])))")
        } else {
            await tool.checkpoint("\(stage): did not arrive during \(Self.silence)")
        }
    }
}

/// Starts and cleans up one lock gate. If `capability` is true, includes `tailnet-lock` in every node's CapMap before the first registration.
func withLockGate(capability: Bool = true, _ body: (LockGate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-tl10-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    let registry = LockGate.Registry()
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("Could not clean up the lock gate state directory: \(redacted(String(describing: error)))") }
        }
    }
    func stopNodes() async -> [String] {
        var failures: [String] = []
        for node in registry.state.withLock({ $0.nodes }) {
            if let failure = await node.stop() { failures.append(failure) }
        }
        return failures
    }
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        if capability {
            _ = try await tool.command(.init(cmd: "setLockCapability", enabled: true), expecting: "lockCapability")
        }
        let gate = LockGate(tool: tool, controlURL: try #require(ready.controlURL), root: directory, registry: registry)
        try await body(gate)
        let failures = await stopNodes()
        await tool.stop()
        if !failures.isEmpty { throw GateFailure("TailnetNode.run ended before cancellation: \(failures.joined(separator: "; "))") }
    } catch {
        let failures = await stopNodes()
        await tool.stop()
        var detail = redacted(String(describing: error))
        if !failures.isEmpty { detail += "\nTailnetNode.run: \(failures.joined(separator: "; "))" }
        throw GateFailure("\(detail)\n\(await tool.diagnostics())")
    }
}
