import CryptoKit
import Testing

import SwiftailBase
import SwiftailCrypto
@testable import SwiftailMagicsock

/// 시험용 노드 하나의 신원: disco 개인 키, node 키, UDP 주소. 키는 고정 바이트에서 만든 시험용 값이다.
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

    /// 이 신원을 netmap의 피어로 본 값.
    func peer(homeDERP: Int64 = 1, endpoints: [IPEndpoint]) -> Magicsock.Peer {
        Magicsock.Peer(key: nodeKey, discoKey: discoPublicKey, homeDERP: homeDERP, endpoints: endpoints)
    }

    /// 이 신원의 `Magicsock`. 인터페이스 주소는 `localAddresses`, 포트는 자기 주소의 포트다.
    func magicsock(localAddresses: [IPAddress] = [], at now: ContinuousClock.Instant = sockT0) -> Magicsock {
        Magicsock(
            discoKey: discoKey, nodeKey: nodeKey, localPort: address.port,
            localAddresses: localAddresses, loopbackAddresses: [], now: now
        )
    }

    /// 이 신원이 받은 disco 패킷을 연다. 보낸 쪽 키는 패킷에서 읽는다.
    func open(_ packet: [UInt8]) throws -> DiscoMessage {
        let sender = try #require(DiscoPacket.senderKey(of: packet))
        return try DiscoPacket.open(packet, sharedKey: DiscoSharedKey(privateKey: discoKey, peerPublicKey: sender))
    }

    /// 이 신원이 `receiver`에게 보낼 disco 패킷.
    func seal(_ message: DiscoMessage, to receiver: DiscoPublicKey, nonce: UInt8 = 1) throws -> [UInt8] {
        try seal(plaintext: message.plaintext, to: receiver, nonce: nonce)
    }

    /// 임의 평문을 봉한 disco 패킷. 처리하지 않는 종류를 만드는 데 쓴다.
    func seal(plaintext: [UInt8], to receiver: DiscoPublicKey, nonce: UInt8 = 1) throws -> [UInt8] {
        let sharedKey = try DiscoSharedKey(privateKey: discoKey, peerPublicKey: receiver)
        let nonceBytes = [UInt8](repeating: nonce, count: NaClSecretBox.nonceByteCount)
        return DiscoPacket.magic + discoPublicKey.rawValue + nonceBytes + sharedKey.seal(plaintext, nonce: nonceBytes)
    }
}

/// 시험의 기준 시각과 그 뒤의 시각.
let sockT0 = ContinuousClock.now

func sockTime(_ milliseconds: Int64) -> ContinuousClock.Instant {
    sockT0 + .milliseconds(milliseconds)
}

/// 시험용 STUN 서버: 요청의 TxID와 보낸 쪽 주소로 XOR-MAPPED-ADDRESS 응답을 만든다(RFC 5389 15.2).
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
    /// STUN 요청이면 그 바이트.
    var stunRequest: [UInt8]? {
        if case .udp(let bytes, _) = self, STUNMessage.looksLikeSTUN(bytes) { bytes } else { nil }
    }

    /// disco 패킷이면 그 바이트와 갈 곳.
    var discoPacket: (bytes: [UInt8], udp: IPEndpoint?, derp: NodePublicKey?)? {
        switch self {
        case .udp(let bytes, let to) where DiscoPacket.isDisco(bytes): (bytes, to, nil)
        case .derp(let bytes, let to, _) where DiscoPacket.isDisco(bytes): (bytes, nil, to)
        default: nil
        }
    }
}

/// 시험 데이터그램: WireGuard transport 모양(type 4)에 일련번호를 담는다. disco·STUN으로 보이지 않는다.
func testDatagram(_ sequence: UInt32) -> [UInt8] {
    [4, 0, 0, 0, UInt8(sequence >> 24), UInt8(sequence >> 16 & 0xFF), UInt8(sequence >> 8 & 0xFF), UInt8(sequence & 0xFF)]
}

func isTestDatagram(_ bytes: [UInt8]) -> Bool {
    bytes.count == 8 && bytes[0] == 4
}

/// `Magicsock` 둘을 메모리에서 맞물린 망.
///
/// 각 노드의 `.udp`는 그 주소의 노드(또는 시험 STUN 서버)로, `.derp`는 그 키의 노드로 지연 뒤에 배달한다. 망은
/// UDP를 막을 수 있다(STUN은 막지 않는다). 시각 순서대로 배달 → 기한(`advance`) → 예약한 송신을 처리한다.
/// 받은 WireGuard 데이터그램은 `echo`인 노드가 보낸 쪽으로 되보낸다.
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

    /// 배달된 disco 메시지 하나.
    struct DiscoRecord {
        let time: ContinuousClock.Instant
        let from: Int
        let to: Int
        let viaDERP: Bool
        let message: DiscoMessage
    }

    /// 한 노드의 송신 한 번(같은 시각, 같은 바이트의 UDP·DERP 출력을 묶는다).
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
    let udpLatency: Duration = .milliseconds(1)
    let derpLatency: Duration = .milliseconds(10)
    let stunLatency: Duration = .milliseconds(5)

    /// 모든 출력과 그 시각·노드.
    private(set) var log: [(time: ContinuousClock.Instant, node: Int, output: Magicsock.Output)] = []
    private(set) var discoLog: [DiscoRecord] = []
    /// 노드가 `.wireGuard`로 올린 데이터그램.
    private(set) var received: [(time: ContinuousClock.Instant, node: Int, bytes: [UInt8])] = []
    /// `nextDeadline`이 부품 기한의 최솟값과 달랐거나 `advance` 뒤에도 지난 시각에 머문 횟수.
    private(set) var deadlineViolations = 0

    private var inFlight: [(time: ContinuousClock.Instant, to: Int, delivery: Delivery)] = []
    private var schedule: (from: Int, to: Int, interval: Duration, next: ContinuousClock.Instant)?
    private var sequence: UInt32 = 0

    init(_ identities: [TestIdentity]) throws {
        nodes = identities.enumerated().map { index, identity in
            Node(identity: identity, sock: identity.magicsock(), random: PathTestRandom(state: UInt64(index + 1) * 1000))
        }
        stunServer = try TestSTUN.server()
    }

    // MARK: 입력

    mutating func setPeers(_ node: Int, _ peers: [Magicsock.Peer]) {
        apply(nodes[node].sock.setPeers(peers, at: now), from: node)
    }

    mutating func setRegions(_ node: Int, _ regions: [Magicsock.Region]) {
        let now = self.now
        apply(step(node) { $0.setRegions(regions, at: now, using: &$1) }, from: node)
    }

    /// `from`의 TSMP disco 키 광고가 지금 `to`에 닿은 것으로 넣는다(WireGuard 세션이 선 순간. 이 망에는 WireGuard가 없다).
    mutating func advertiseDiscoKey(from: Int, to: Int) {
        let key = nodes[from].sock.discoPublicKey, sender = nodes[from].identity.nodeKey
        apply(nodes[to].sock.receiveDiscoKeyAdvertisement(key, from: sender, at: now), from: to)
    }

    /// 지금 `from`에서 `to`로 시험 데이터그램 하나를 보낸다.
    mutating func send(from: Int, to: Int) {
        sequence += 1
        send(testDatagram(sequence), from: from, to: to)
    }

    /// 지금부터 `interval`마다 보낸다. nil이면 멈춘다.
    mutating func sendRepeatedly(from: Int, to: Int, every interval: Duration?) {
        schedule = interval.map { (from, to, $0, now) }
    }

    /// `end`까지 사건을 처리하고 시각을 `end`로 둔다.
    mutating func run(until end: ContinuousClock.Instant) {
        var steps = 0
        while let next = nextEventTime(), next <= end {
            steps += 1
            guard steps < 200_000 else {
                Issue.record("사건이 끝나지 않는다(\(now))")
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
            if let current = schedule, current.next <= now {
                schedule?.next = current.next + current.interval
                send(from: current.from, to: current.to)
            }
            checkDeadlines()
        }
        now = end
    }

    // MARK: 조회

    /// `node`가 낸 `peer`의 경로 사건과 그 시각.
    func pathEvents(_ node: Int, peer: Int) -> [(time: ContinuousClock.Instant, path: PeerPath?)] {
        let key = nodes[peer].identity.nodeKey
        return log.compactMap { entry in
            guard entry.node == node, case .pathChanged(let changed, let path) = entry.output, changed == key else { return nil }
            return (entry.time, path)
        }
    }

    /// `node`가 보낸 시험 데이터그램(되보낸 것 포함)마다 UDP·DERP로 나갔는지.
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

    // MARK: 망

    /// 노드 하나의 `Magicsock`과 난수로 `body`를 부른다(같은 배열의 두 칸을 함께 inout으로 넘길 수 없어서다).
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
        return (inFlight.map(\.time) + deadlines + [schedule?.next].compactMap { $0 }).min()
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
                } else if !udpBlocked, let target = nodes.firstIndex(where: { $0.identity.address == destination }) {
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

    /// `nextDeadline`이 부품들의 기한(유휴 기한 포함) 가운데 가장 이른 것인지 본다.
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
