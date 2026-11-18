import CryptoKit
import Testing

import SwiftailBase
import SwiftailCrypto
@testable import SwiftailMagicsock

/// The identity of one test node, including its disco private key, node key, and UDP address. Test keys are derived from fixed bytes.
struct TestIdentity {
    let discoKey: Curve25519.KeyAgreement.PrivateKey
    let nodeKey: NodePublicKey
    let address: IPEndpoint

    init(_ seed: UInt8, address: String) throws {
        discoKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: [UInt8](repeating: seed, count: 32))
        nodeKey = try #require(NodePublicKey(rawValue: [UInt8](repeating: seed, count: 32)))
        self.address = try #require(IPEndpoint(address))
    }

    var discoPublicKey: DiscoPublicKey { DiscoPublicKey(discoKey.publicKey) }

    /// Represents this identity as a netmap peer.
    func peer(homeDERP: Int64 = 1, endpoints: [IPEndpoint]) -> Magicsock.Peer {
        Magicsock.Peer(key: nodeKey, discoKey: discoPublicKey, homeDERP: homeDERP, endpoints: endpoints)
    }

    /// Creates a `Magicsock` for this identity using `localAddresses` for the interface addresses and its own address's port.
    func magicsock(localAddresses: [IPAddress] = [], at now: ContinuousClock.Instant = sockT0) -> Magicsock {
        Magicsock(
            discoKey: discoKey, nodeKey: nodeKey, localPort: address.port,
            localAddresses: localAddresses, loopbackAddresses: [], now: now
        )
    }

    /// Opens a disco packet received by this identity. Reads the sender key from the packet.
    func open(_ packet: [UInt8]) throws -> DiscoMessage {
        let sender = try #require(DiscoPacket.senderKey(of: packet))
        return try DiscoPacket.open(packet, sharedKey: DiscoSharedKey(privateKey: discoKey, peerPublicKey: sender))
    }

    /// Builds a disco packet for this identity to send to `receiver`.
    func seal(_ message: DiscoMessage, to receiver: DiscoPublicKey, nonce: UInt8 = 1) throws -> [UInt8] {
        try seal(plaintext: message.plaintext, to: receiver, nonce: nonce)
    }

    /// Seals arbitrary plaintext into a disco packet, for making unsupported types.
    func seal(plaintext: [UInt8], to receiver: DiscoPublicKey, nonce: UInt8 = 1) throws -> [UInt8] {
        let sharedKey = try DiscoSharedKey(privateKey: discoKey, peerPublicKey: receiver)
        let nonceBytes = [UInt8](repeating: nonce, count: NaClSecretBox.nonceByteCount)
        return DiscoPacket.magic + discoPublicKey.rawValue + nonceBytes + sharedKey.seal(plaintext, nonce: nonceBytes)
    }
}

/// The test reference time and times after it.
let sockT0 = ContinuousClock.now

func sockTime(_ milliseconds: Int64) -> ContinuousClock.Instant {
    sockT0 + .milliseconds(milliseconds)
}

/// A test STUN server that builds an XOR-MAPPED-ADDRESS response from the request TxID and source address (RFC 5389 §15.2).
enum TestSTUN {
    static func server() throws -> IPEndpoint { try #require(IPEndpoint("198.51.100.53:3478")) }

    static func response(to request: [UInt8], mapped: IPEndpoint) -> [UInt8] {
        let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        let txID = Array(request.dropFirst(8).prefix(12))
        let port = mapped.port ^ 0x2112
        let address = zip(mapped.address.bytes, cookie).map { $0 ^ $1 }
        let attribute: [UInt8] = [0x00, 0x20, 0x00, 0x08, 0x00, 0x01, UInt8(port >> 8), UInt8(port & 0xFF)] + address
        return [0x01, 0x01, 0x00, UInt8(attribute.count)] + cookie + txID + attribute
    }
}

extension Magicsock.Output {
    /// Returns the bytes if this is a STUN request.
    var stunRequest: [UInt8]? {
        if case .udp(let bytes, _) = self, STUNMessage.looksLikeSTUN(bytes) { bytes } else { nil }
    }

    /// Returns the bytes and destination if this is a disco packet.
    var discoPacket: (bytes: [UInt8], udp: IPEndpoint?, derp: NodePublicKey?)? {
        switch self {
        case .udp(let bytes, let to) where DiscoPacket.isDisco(bytes): (bytes, to, nil)
        case .derp(let bytes, let to, _) where DiscoPacket.isDisco(bytes): (bytes, nil, to)
        default: nil
        }
    }
}

/// A test datagram that looks like WireGuard transport (type 4) and carries a sequence number. It is distinguishable from disco and STUN.
func testDatagram(_ sequence: UInt32) -> [UInt8] {
    [4, 0, 0, 0, UInt8(sequence >> 24), UInt8(sequence >> 16 & 0xFF), UInt8(sequence >> 8 & 0xFF), UInt8(sequence & 0xFF)]
}

func isTestDatagram(_ bytes: [UInt8]) -> Bool {
    bytes.count == 8 && bytes[0] == 4
}

/// A network connecting two `Magicsock` instances in memory.
///
/// Delivers each node's `.udp` to the node at that address (or the test STUN server) and `.derp` to the node for that key, after a delay. The network
/// can block UDP (STUN is exempt) and can temporarily drop only one node's outgoing UDP Pongs. In time order, it processes
/// delivery → deadlines (`advance`) → scheduled sends. Each sender-receiver pair has at most one scheduled send.
/// An `echo` node sends received WireGuard datagrams back to their sender.
struct TestNetwork {
    struct Node {
        let identity: TestIdentity
        var sock: Magicsock
        var random: PathTestRandom
        var echo = false
    }

    enum Delivery {
        case udp([UInt8], from: IPEndpoint)
        case derp([UInt8], from: NodePublicKey, region: Int64)
    }

    /// One delivered disco message.
    struct DiscoRecord {
        let time: ContinuousClock.Instant
        let from: Int
        let to: Int
        let viaDERP: Bool
        let message: DiscoMessage
    }

    /// One send from a node, grouping UDP and DERP output with the same bytes and time.
    struct DataSend {
        let time: ContinuousClock.Instant
        var udp: Bool
        var derp: Bool
        var dropped: Bool
    }

    var nodes: [Node]
    let stunServer: IPEndpoint
    private(set) var now = sockT0
    var udpBlocked = false
    /// Drops UDP Pongs sent by this node during this range (exclusive end).
    var pongLoss: (from: Int, during: Range<ContinuousClock.Instant>)?
    /// One-way UDP latency.
    var udpLatency: Duration = .milliseconds(1)
    let derpLatency: Duration = .milliseconds(10)
    let stunLatency: Duration = .milliseconds(5)

    /// All output, with its time and node.
    private(set) var log: [(time: ContinuousClock.Instant, node: Int, output: Magicsock.Output)] = []
    private(set) var discoLog: [DiscoRecord] = []
    /// Datagrams a node delivered as `.wireGuard`.
    private(set) var received: [(time: ContinuousClock.Instant, node: Int, bytes: [UInt8])] = []
    /// Counts how often `nextDeadline` differed from the earliest component deadline or stayed in the past after `advance`.
    private(set) var deadlineViolations = 0

    private var inFlight: [(time: ContinuousClock.Instant, to: Int, delivery: Delivery)] = []
    private var schedules: [(from: Int, to: Int, interval: Duration, next: ContinuousClock.Instant)] = []
    private var sequence: UInt32 = 0

    init(_ identities: [TestIdentity]) throws {
        nodes = identities.enumerated().map { index, identity in
            Node(identity: identity, sock: identity.magicsock(), random: PathTestRandom(state: UInt64(index + 1) * 1000))
        }
        stunServer = try TestSTUN.server()
    }

    // MARK: Inputs

    mutating func setPeers(_ node: Int, _ peers: [Magicsock.Peer]) {
        apply(nodes[node].sock.setPeers(peers, at: now), from: node)
    }

    mutating func setRegions(_ node: Int, _ regions: [Magicsock.Region]) {
        let now = self.now
        apply(step(node) { $0.setRegions(regions, at: now, using: &$1) }, from: node)
    }

    /// Injects `from`'s TSMP disco key advertisement as arriving at `to` now (the moment a WireGuard session is established, since this network has no WireGuard).
    mutating func advertiseDiscoKey(from: Int, to: Int) {
        let key = nodes[from].sock.discoPublicKey, sender = nodes[from].identity.nodeKey
        apply(nodes[to].sock.receiveDiscoKeyAdvertisement(key, from: sender, at: now), from: to)
    }

    /// Sends one test datagram from `from` to `to` now.
    mutating func send(from: Int, to: Int) {
        sequence += 1
        send(testDatagram(sequence), from: from, to: to)
    }

    /// Sends from `from` to `to` every `interval` starting now. Nil stops sends for that pair.
    mutating func sendRepeatedly(from: Int, to: Int, every interval: Duration?) {
        schedules.removeAll { $0.from == from && $0.to == to }
        if let interval {
            schedules.append((from, to, interval, now))
        }
    }

    /// Processes events through `end` and sets the time to `end`.
    mutating func run(until end: ContinuousClock.Instant) {
        var steps = 0
        while let next = nextEventTime(), next <= end {
            steps += 1
            guard steps < 200_000 else {
                Issue.record("Event processing did not finish (\(now))")
                return
            }
            now = next
            let due = inFlight.filter { $0.time <= now }
            inFlight.removeAll { $0.time <= now }
            for item in due {
                deliver(item.delivery, to: item.to)
            }
            for index in nodes.indices {
                guard let deadline = nodes[index].sock.nextDeadline, deadline <= now else { continue }
                let now = self.now
                apply(step(index) { $0.advance(to: now, using: &$1) }, from: index)
                if let after = nodes[index].sock.nextDeadline, after <= now { deadlineViolations += 1 }
            }
            for index in schedules.indices where schedules[index].next <= now {
                schedules[index].next += schedules[index].interval
                send(from: schedules[index].from, to: schedules[index].to)
            }
            checkDeadlines()
        }
        now = end
    }

    // MARK: Queries

    /// Returns `peer` path events emitted by `node` and their times.
    func pathEvents(_ node: Int, peer: Int) -> [(time: ContinuousClock.Instant, path: PeerPath?)] {
        let key = nodes[peer].identity.nodeKey
        return log.compactMap { entry in
            guard entry.node == node, case .pathChanged(let changed, let path) = entry.output, changed == key else { return nil }
            return (entry.time, path)
        }
    }

    /// Reports whether each test datagram sent by `node` (including echoes) went out over UDP or DERP.
    func dataSends(_ node: Int) -> [DataSend] {
        var sends: [DataSend] = []
        var lastKey: (ContinuousClock.Instant, [UInt8])?
        for entry in log where entry.node == node {
            let bytes: [UInt8]
            var send = DataSend(time: entry.time, udp: false, derp: false, dropped: false)
            switch entry.output {
            case .udp(let data, _) where isTestDatagram(data): bytes = data; send.udp = true
            case .derp(let data, _, _) where isTestDatagram(data): bytes = data; send.derp = true
            default: continue
            }
            if let lastKey, lastKey.0 == entry.time, lastKey.1 == bytes, var last = sends.popLast() {
                last.udp = last.udp || send.udp
                last.derp = last.derp || send.derp
                sends.append(last)
            } else {
                sends.append(send)
            }
            lastKey = (entry.time, bytes)
        }
        return sends
    }

    // MARK: Network

    /// Calls `body` with a node's `Magicsock` and random generator because two elements of the same array cannot be passed together as inout.
    private mutating func step(
        _ index: Int,
        _ body: (inout Magicsock, inout PathTestRandom) -> [Magicsock.Output]
    ) -> [Magicsock.Output] {
        var node = nodes[index]
        let outputs = body(&node.sock, &node.random)
        nodes[index] = node
        return outputs
    }

    private func nextEventTime() -> ContinuousClock.Instant? {
        let deadlines = nodes.compactMap(\.sock.nextDeadline)
        return (inFlight.map(\.time) + deadlines + schedules.map(\.next)).min()
    }

    private mutating func send(_ datagram: [UInt8], from: Int, to: Int) {
        let key = nodes[to].identity.nodeKey
        let now = self.now
        apply(step(from) { $0.send(datagram, to: key, at: now, using: &$1) }, from: from)
    }

    private mutating func apply(_ outputs: [Magicsock.Output], from node: Int) {
        for output in outputs {
            log.append((now, node, output))
            switch output {
            case .udp(let bytes, let destination):
                if destination == stunServer {
                    let response = TestSTUN.response(to: bytes, mapped: nodes[node].identity.address)
                    inFlight.append((now + stunLatency, node, .udp(response, from: stunServer)))
                } else if !udpBlocked, let target = nodes.firstIndex(where: { $0.identity.address == destination }),
                          !losesPong(bytes, from: node, to: target) {
                    inFlight.append((now + udpLatency, target, .udp(bytes, from: nodes[node].identity.address)))
                }
            case .derp(let bytes, let key, let region):
                if let target = nodes.firstIndex(where: { $0.identity.nodeKey == key }) {
                    inFlight.append((now + derpLatency, target, .derp(bytes, from: nodes[node].identity.nodeKey, region: region)))
                }
            case .wireGuard(let bytes, _):
                received.append((now, node, bytes))
                if nodes[node].echo, let other = nodes.indices.first(where: { $0 != node }) {
                    send(bytes, from: node, to: other)
                }
            default:
                break
            }
        }
    }

    /// Checks whether `pongLoss` applies to this Pong.
    private func losesPong(_ bytes: [UInt8], from node: Int, to target: Int) -> Bool {
        guard let pongLoss, pongLoss.from == node, pongLoss.during.contains(now), DiscoPacket.isDisco(bytes) else { return false }
        return (try? nodes[target].identity.open(bytes))?.isPong == true
    }

    private mutating func deliver(_ delivery: Delivery, to node: Int) {
        let now = self.now
        let outputs: [Magicsock.Output]
        switch delivery {
        case .udp(let bytes, let source):
            recordDisco(bytes, to: node, viaDERP: false)
            outputs = step(node) { $0.receiveUDP(bytes, from: source, at: now, using: &$1) }
        case .derp(let bytes, let sender, let region):
            recordDisco(bytes, to: node, viaDERP: true)
            outputs = step(node) { $0.receiveDERP(bytes, from: sender, region: region, at: now, using: &$1) }
        }
        apply(outputs, from: node)
    }

    private mutating func recordDisco(_ bytes: [UInt8], to node: Int, viaDERP: Bool) {
        guard let sender = DiscoPacket.senderKey(of: bytes),
              let from = nodes.firstIndex(where: { $0.identity.discoPublicKey == sender }),
              let message = try? nodes[node].identity.open(bytes)
        else { return }
        discoLog.append(DiscoRecord(time: now, from: from, to: node, viaDERP: viaDERP, message: message))
    }

    /// Checks that `nextDeadline` is the earliest component deadline, including the idle deadline.
    private mutating func checkDeadlines() {
        for node in nodes {
            let parts = node.sock.peers.values.flatMap { [$0.path.nextDeadline, Magicsock.idleDeadline(of: $0)] }
                + [node.sock.netcheck.nextDeadline]
            if node.sock.nextDeadline != parts.compactMap({ $0 }).min() { deadlineViolations += 1 }
        }
    }
}

extension DiscoMessage {
    var isPing: Bool { if case .ping = self { true } else { false } }
    var isPong: Bool { if case .pong = self { true } else { false } }
    var callMeMaybeEndpoints: [IPEndpoint]? { if case .callMeMaybe(let endpoints) = self { endpoints } else { nil } }
}
