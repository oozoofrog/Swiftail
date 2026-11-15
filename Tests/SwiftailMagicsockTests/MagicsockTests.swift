import CryptoKit
import Testing

import SwiftailBase
import SwiftailCrypto
@testable import SwiftailMagicsock

// 기대값은 계약(`docs/contracts/SwiftailMagicsock.md`)과 노트(`docs/protocol-notes/disco-magicsock.md`)에서 정했다.
// 타이머 값(신뢰 6.5초, Ping 기한 5초, heartbeat 3초, 후보별 Ping 간격 5초, CallMeMaybe 신선도 27초, 유휴 45초,
// STUN 0·100·200 ms와 3초)은 Go `wgengine/magicsock`·`net/netcheck`(BSD-3-Clause)의 값을 노트 5절에서 옮겼다.

private func txID(_ value: UInt8) throws -> TransactionID {
    try #require(TransactionID([UInt8](repeating: value, count: TransactionID.byteCount)))
}

private func endpoint(_ text: String) throws -> IPEndpoint {
    try #require(IPEndpoint(text))
}

/// 두 노드 A(0)·B(1)와 시험 STUN 서버 하나를 둔 망. B는 받은 데이터를 되보낸다.
private func twoNodes(aKnowsB: IPEndpoint?, bKnowsA: Bool, regions: Bool) throws -> TestNetwork {
    let a = try TestIdentity(1, address: "192.0.2.1:41641")
    let b = try TestIdentity(2, address: "192.0.2.2:41641")
    var network = try TestNetwork([a, b])
    network.nodes[1].echo = true
    network.setPeers(0, [b.peer(endpoints: aKnowsB.map { [$0] } ?? [])])
    network.setPeers(1, [a.peer(endpoints: bKnowsA ? [a.address] : [])])
    if regions {
        let region = Magicsock.Region(id: 1, stunServers: [network.stunServer])
        network.setRegions(0, [region])
        network.setRegions(1, [region])
    }
    return network
}

// MARK: - 두 노드

@Suite("Magicsock 두 노드")
struct MagicsockNetworkTests {
    @Test("netmap으로 서로의 엔드포인트를 알면 처음에는 DERP로 가다가 Ping·Pong 뒤 직접 경로가 선다")
    func directPathFromNetmap() throws {
        var network = try twoNodes(aKnowsB: try endpoint("192.0.2.2:41641"), bKnowsA: true, regions: true)
        let a = network.nodes[0].identity, b = network.nodes[1].identity
        network.run(until: sockTime(1_000))
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(10_000))
        network.sendRepeatedly(from: 0, to: 1, every: nil)
        network.run(until: sockTime(10_100))

        // 노트 4.5 2·4.8 2: 첫 송신은 신뢰된 직접 경로가 없어 DERP로 간다.
        let sends = network.dataSends(0)
        let first = try #require(sends.first)
        #expect(first.derp && !first.udp)

        let aEvents = network.pathEvents(0, peer: 1)
        #expect(aEvents.first?.path == .relayed(derpRegion: 1))
        let direct = try #require(aEvents.first { $0.path == .direct(b.address) })
        // 첫 Ping의 Pong이 오면 바로 선다(UDP 왕복 2 ms).
        #expect(direct.time <= sockTime(1_000) + .milliseconds(5))
        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(a.address))
        #expect(network.nodes[0].sock.path(to: b.nodeKey, at: network.now) == .direct(b.address))

        // 노트 4.5 1: 신뢰된 직접 경로가 선 뒤에는 UDP로만 보낸다.
        let afterDirect = sends.filter { $0.time > direct.time }
        #expect(!afterDirect.isEmpty)
        #expect(afterDirect.allSatisfy { $0.udp && !$0.derp })
        // 보낸 데이터는 WireGuard 데이터그램으로 올라가고 되돌아온다.
        #expect(network.received.filter { $0.node == 1 }.count == sends.count)
        #expect(network.received.contains { $0.node == 0 && isTestDatagram($0.bytes) })
        #expect(network.deadlineViolations == 0)
    }

    @Test("B가 A의 엔드포인트를 몰라도 받은 Ping의 출처로 배워 직접 경로가 선다(노트 4.8 계산)")
    func learnsFromPingSource() throws {
        // 지역이 없으면 엔드포인트를 정하지 못해 CallMeMaybe가 나가지 않는다. Ping 출처만으로 서는지 본다.
        var network = try twoNodes(aKnowsB: try endpoint("192.0.2.2:41641"), bKnowsA: false, regions: false)
        let a = network.nodes[0].identity
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(5_000))

        #expect(!network.discoLog.contains { $0.message.callMeMaybeEndpoints != nil })
        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(a.address))
        #expect(network.pathEvents(0, peer: 1).last?.path == .direct(network.nodes[1].identity.address))
    }

    @Test("CallMeMaybe를 받은 쪽은 곧바로 그 주소에 Ping하고, 둘 다 직접 경로가 선다")
    func callMeMaybeExchange() throws {
        // A가 아는 B의 주소는 닿지 않는 옛 주소이고 B는 A를 모른다. A의 CallMeMaybe만이 길을 연다.
        var network = try twoNodes(aKnowsB: try endpoint("198.51.100.99:41641"), bKnowsA: false, regions: true)
        let a = network.nodes[0].identity, b = network.nodes[1].identity
        network.run(until: sockTime(1_000))
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(8_000))

        let callMeMaybe = try #require(network.discoLog.first { $0.from == 0 && $0.message.callMeMaybeEndpoints != nil })
        #expect(callMeMaybe.viaDERP)
        // 노트 4.8 4.2: 자기 엔드포인트 전체(여기서는 STUN 결과 하나)를 담는다.
        #expect(callMeMaybe.message.callMeMaybeEndpoints == [a.address])
        // 노트 4.8 5: 받자마자 Ping한다(UDP 지연 1 ms 뒤 A에 닿는다).
        let bPing = try #require(network.discoLog.first { $0.from == 1 && $0.message.isPing })
        #expect(bPing.time == callMeMaybe.time + network.udpLatency)
        #expect(!bPing.viaDERP)
        // 받은 CallMeMaybe가 부른 전체 Ping은 CallMeMaybe를 되보내지 않는다.
        #expect(!network.discoLog.contains { $0.from == 1 && $0.message.callMeMaybeEndpoints != nil && $0.time <= bPing.time })

        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(a.address))
        #expect(network.pathEvents(0, peer: 1).last?.path == .direct(b.address))
    }

    @Test("UDP를 막으면 마지막 Pong + 6.5초에 .relayed가 되고, 그 사이 데이터는 UDP와 DERP로 함께 나가며, 풀면 다시 .direct가 된다")
    func blockAndUnblock() throws {
        var network = try twoNodes(aKnowsB: try endpoint("192.0.2.2:41641"), bKnowsA: true, regions: true)
        let b = network.nodes[1].identity
        network.run(until: sockTime(1_000))
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(20_000))
        #expect(network.nodes[0].sock.path(to: b.nodeKey, at: network.now) == .direct(b.address))

        let blockedAt = sockTime(20_000)
        network.udpBlocked = true
        network.run(until: sockTime(40_000))

        // 마지막으로 A에 닿은 B의 UDP Pong.
        let lastPong = try #require(network.discoLog.last { $0.to == 0 && $0.from == 1 && !$0.viaDERP && $0.message.isPong })
        #expect(lastPong.time <= blockedAt)
        let trustEnd = lastPong.time + .milliseconds(6_500)

        // 계약 D7·G1: 신뢰가 끝나는 시각의 advance에서 .relayed가 나온다(신뢰는 그 시각을 포함한다).
        let relayed = try #require(network.pathEvents(0, peer: 1).first { $0.time > blockedAt })
        #expect(relayed.path == .relayed(derpRegion: 1))
        #expect(relayed.time > trustEnd)
        #expect(relayed.time <= trustEnd + .milliseconds(1))

        let sends = network.dataSends(0).filter { $0.time > blockedAt && $0.time < sockTime(40_000) }
        // 노트 4.5 1: 신뢰 기간에는 UDP로만.
        #expect(sends.filter { $0.time <= trustEnd }.allSatisfy { $0.udp && !$0.derp })
        // 노트 4.5 2: 신뢰가 지난 뒤에는 남은 bestAddr와 DERP로 함께.
        let heartbeatPingExpiry = lastPong.time + .seconds(3) + .seconds(5)
        #expect(sends.contains { $0.time > trustEnd && $0.time < heartbeatPingExpiry && $0.udp && $0.derp })
        // 노트 4.6 3: 신뢰가 지난 뒤 기한이 지난 heartbeat Ping(Pong 뒤 3초 안에 보냄, 5초 기한)이 bestAddr를 지워 DERP만 남는다.
        let derpOnly = sends.filter { $0.time > heartbeatPingExpiry }
        #expect(!derpOnly.isEmpty)
        #expect(derpOnly.allSatisfy { $0.derp && !$0.udp })
        // 막힌 동안에도 데이터는 DERP로 닿는다.
        #expect(network.received.contains { $0.node == 1 && $0.time > heartbeatPingExpiry })

        // 풀면: 송신마다 하는 전체 Ping(후보별 5초 간격)의 Pong으로 돌아온다(노트 7.2 3).
        let unblockedAt = network.now
        network.udpBlocked = false
        network.run(until: sockTime(50_000))
        let recovered = try #require(network.pathEvents(0, peer: 1).first { $0.time > unblockedAt })
        #expect(recovered.path == .direct(b.address))
        #expect(recovered.time <= unblockedAt + .seconds(5) + .milliseconds(10))
        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(network.nodes[0].identity.address))
        #expect(network.deadlineViolations == 0)
    }
}

// MARK: - 한 노드: 분류와 규칙

@Suite("Magicsock 받기와 규칙")
struct MagicsockRulesTests {
    let a: TestIdentity
    let b: TestIdentity
    let c: TestIdentity

    init() throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        c = try TestIdentity(3, address: "192.0.2.3:41641")
    }

    private func makeSock(peers: [Magicsock.Peer]) -> Magicsock {
        var sock = a.magicsock()
        _ = sock.setPeers(peers, at: sockT0)
        return sock
    }

    private func candidates(_ sock: Magicsock, _ peer: TestIdentity) -> [IPEndpoint] {
        sock.peers[peer.nodeKey]?.path.candidates.map(\.address) ?? []
    }

    /// 출력 가운데 UDP로 나가는 disco Ping의 목적지. 모두 `a`의 node 키를 담은 Ping이어야 한다.
    private func pingDestinations(_ outputs: [Magicsock.Output], openedBy peer: TestIdentity) throws -> [IPEndpoint] {
        try outputs.compactMap(\.discoPacket).compactMap { packet -> IPEndpoint? in
            guard let destination = packet.udp else { return nil }
            guard case .ping(_, let nodeKey) = try peer.open(packet.bytes) else { return nil }
            #expect(nodeKey == a.nodeKey)
            return destination
        }
    }

    // MARK: 분류 (동작 A)

    @Test("disco·STUN이 아닌 데이터그램은 내용을 보지 않고 .wireGuard로 올라간다")
    func plainDatagram() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let initiation: [UInt8] = [1, 0, 0, 0] + [UInt8](repeating: 0, count: 144)
        for datagram in [testDatagram(1), [], initiation] {
            #expect(sock.receiveUDP(datagram, from: b.address, at: sockT0, using: &random) == [.wireGuard(datagram, from: .udp(b.address))])
        }
        // 피어의 후보가 아닌 주소에서 온 것도 그 주소를 출처로 싣는다(WireGuard가 cookie reply를 그리로 되돌린다).
        let stranger = IPEndpoint(address: b.address.address, port: b.address.port &+ 1)
        #expect(sock.receiveUDP(initiation, from: stranger, at: sockT0, using: &random) == [.wireGuard(initiation, from: .udp(stranger))])
    }

    @Test("IPv6이나 포트 0인 출처는 받지 않는다", arguments: ["[2001:db8::1]:41641", "192.0.2.2:0"])
    func unsupportedSource(_ text: String) throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let source = try endpoint(text)
        let ping = try b.seal(.ping(try txID(1), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(ping, from: source, at: sockT0, using: &random) == [.dropped(.unsupportedSource)])
        #expect(sock.receiveUDP(testDatagram(1), from: source, at: sockT0, using: &random) == [.dropped(.unsupportedSource)])
        #expect(candidates(sock, b).isEmpty)
    }

    @Test("회차 밖이거나 해석할 수 없는 STUN 응답은 버리고, 회차의 응답은 엔드포인트가 된다")
    func stunResponses() throws {
        var sock = a.magicsock()
        var random = PathTestRandom(state: 7)
        let server = try TestSTUN.server()
        let stray = TestSTUN.response(to: STUNMessage.bindingRequest(try txID(9)), mapped: a.address)
        #expect(sock.receiveUDP(stray, from: server, at: sockT0, using: &random) == [.dropped(.unexpectedSTUN)])

        let start = sock.setRegions([Magicsock.Region(id: 1, stunServers: [server])], at: sockT0, using: &random)
        let request = try #require(start.compactMap(\.stunRequest).first)
        // 주소 속성이 없는 응답: STUN 모양이라 WireGuard로도 가지 않는다.
        var headerOnly = Array(TestSTUN.response(to: request, mapped: a.address).prefix(STUNMessage.headerLength))
        headerOnly[3] = 0
        #expect(sock.receiveUDP(headerOnly, from: server, at: sockTime(1), using: &random) == [.dropped(.unexpectedSTUN)])

        let response = TestSTUN.response(to: request, mapped: a.address)
        // 계약 E4: STUN 전역 주소(.stun) 뒤에 인터페이스 주소(여기서는 없음).
        #expect(sock.receiveUDP(response, from: server, at: sockTime(5), using: &random)
            == [.endpointsChanged([Magicsock.Endpoint(address: a.address, source: .stun)])])
        #expect(sock.receiveUDP(response, from: server, at: sockTime(6), using: &random) == [.dropped(.unexpectedSTUN)])
    }

    @Test("setRegions는 대체 홈을 곧바로 내고, 회차가 끝나면 지연으로 홈을 고르고 엔드포인트를 올린다")
    func regionsAndHome() throws {
        let local = try #require(IPAddress("192.0.2.1"))
        var sock = a.magicsock(localAddresses: [local])
        var random = PathTestRandom(state: 7)
        let server1 = try endpoint("198.51.100.53:3478"), server2 = try endpoint("198.51.100.54:3478")
        let start = sock.setRegions(
            [Magicsock.Region(id: 1, stunServers: [server1]), Magicsock.Region(id: 2, stunServers: [server2])],
            at: sockT0, using: &random
        )
        // 계약 E6 "대체 홈": 지역 ID가 가장 작은 것.
        #expect(start.first == .homeRegionChanged(1))
        let requests = start.compactMap { output -> (bytes: [UInt8], to: IPEndpoint)? in
            if case .udp(let bytes, let to) = output, STUNMessage.looksLikeSTUN(bytes) { (bytes, to) } else { nil }
        }
        #expect(requests.map(\.to).sorted { $0.description < $1.description } == [server1, server2])
        let request1 = try #require(requests.first { $0.to == server1 }), request2 = try #require(requests.first { $0.to == server2 })

        let mapped = try endpoint("203.0.113.7:61000")
        // 지역 2가 5 ms, 지역 1이 50 ms에 답한다. 둘 다 답해야 회차가 끝난다.
        #expect(sock.receiveUDP(TestSTUN.response(to: request2.bytes, mapped: mapped), from: server2, at: sockTime(5), using: &random) == [])
        let finished = sock.receiveUDP(TestSTUN.response(to: request1.bytes, mapped: mapped), from: server1, at: sockTime(50), using: &random)
        // 45 ms 차이(10 ms 이상)이고 5 ms가 50 ms의 2/3보다 작으므로 홈을 옮긴다(DERP 노트 4.10 5).
        #expect(finished == [
            .endpointsChanged([
                Magicsock.Endpoint(address: mapped, source: .stun),
                Magicsock.Endpoint(address: try endpoint("192.0.2.1:41641"), source: .local),
            ]),
            .homeRegionChanged(2),
        ])
    }

    @Test("Geneve로 감싼 데이터그램은 버리고, Go가 맨 WireGuard로 보는 머리는 그대로 올린다")
    func geneve() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        func header(_ protocolType: UInt16, control: Bool = false) -> [UInt8] {
            [0, control ? 0x80 : 0, UInt8(protocolType >> 8), UInt8(protocolType & 0xFF), 0, 0, 1, 0]
        }
        let ping = try b.seal(.ping(try txID(1), nodeKey: b.nodeKey), to: a.discoPublicKey)
        let before = candidates(sock, b)
        for dropped in [header(0x7A12) + testDatagram(1), header(0x7A12, control: true) + testDatagram(1), header(0x7A11) + ping] {
            #expect(sock.receiveUDP(dropped, from: try endpoint("203.0.113.9:5000"), at: sockT0, using: &random) == [.dropped(.unsupportedDisco)])
        }
        #expect(candidates(sock, b) == before)
        for passed in [header(0x7A11) + testDatagram(2), header(0x6558) + testDatagram(3)] {
            #expect(sock.receiveUDP(passed, from: b.address, at: sockT0, using: &random) == [.wireGuard(passed, from: .udp(b.address))])
        }
    }

    // MARK: disco 받기 (동작 B·C)

    @Test("모르는 disco 키의 패킷은 공유 키를 계산하지 않고 버린다")
    func unknownDiscoKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let ping = try c.seal(.ping(try txID(1), nodeKey: c.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(ping, from: c.address, at: sockT0, using: &random) == [.dropped(.unknownDiscoKey)])
        #expect(sock.receiveDERP(ping, from: b.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.unknownDiscoKey)])
        #expect(Array(sock.discoPeers.keys) == [b.discoPublicKey])
    }

    @Test("열리지 않거나 잘린 disco는 malformedDisco로 버리고 Pong하지 않는다")
    func malformedDisco() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let ping = try b.seal(.ping(try txID(1), nodeKey: b.nodeKey), to: a.discoPublicKey)
        var tamperedTag = ping
        tamperedTag[62] ^= 1
        var tamperedNonce = ping
        tamperedNonce[40] ^= 1
        var tamperedCiphertext = ping
        tamperedCiphertext[ping.count - 1] ^= 1
        let classifiedOnly = DiscoPacket.magic + b.discoPublicKey.rawValue
        let tooShortToOpen = classifiedOnly + [UInt8](repeating: 0, count: 23)
        for packet in [tamperedTag, tamperedNonce, tamperedCiphertext, classifiedOnly, tooShortToOpen] {
            #expect(sock.receiveUDP(packet, from: try endpoint("203.0.113.9:5000"), at: sockT0, using: &random) == [.dropped(.malformedDisco)])
        }
        #expect(candidates(sock, b) == [b.address])
    }

    @Test("처리하지 않는 disco 종류(peer relay)는 상태를 바꾸지 않고 버린다", arguments: UInt8(0x04)...UInt8(0x09))
    func relayTypes(_ type: UInt8) throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let packet = try b.seal(plaintext: [type, 0] + [UInt8](repeating: 0x11, count: 160), to: a.discoPublicKey)
        let before = sock.peers[b.nodeKey]?.path.candidates
        #expect(sock.receiveUDP(packet, from: try endpoint("203.0.113.9:5000"), at: sockT0, using: &random) == [.dropped(.unsupportedDisco)])
        #expect(sock.receiveDERP(packet, from: b.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.unsupportedDisco)])
        #expect(sock.peers[b.nodeKey]?.path.candidates == before)
    }

    @Test("UDP로 온 Ping에는 출처로 Pong하고 출처를 후보로 배우며, 같은 Ping의 재전송에는 답하지 않는다")
    func udpPing() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let source = try endpoint("203.0.113.9:5000")
        let id = try txID(1)
        let ping = try b.seal(.ping(id, nodeKey: b.nodeKey), to: a.discoPublicKey)
        let outputs = sock.receiveUDP(ping, from: source, at: sockT0, using: &random)
        try #require(outputs.count == 1)
        guard case .udp(let pong, let destination) = outputs[0] else {
            Issue.record("Pong이 UDP로 나가지 않았다: \(outputs)")
            return
        }
        #expect(destination == source)
        #expect(try b.open(pong) == .pong(id, source: source))
        #expect(sock.receiveUDP(ping, from: source, at: sockTime(1), using: &random) == [])

        // 배운 출처는 다음 송신의 Ping 대상이다(노트 4.2 4.2).
        let sent = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(2), using: &random)
        #expect(try pingDestinations(sent, openedBy: b) == [source])
    }

    @Test("DERP로 온 Ping에는 같은 지역 DERP로 Pong하고 Src는 127.3.3.40:<지역>이며 후보를 넣지 않는다")
    func derpPing() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let id = try txID(1)
        let ping = try b.seal(.ping(id, nodeKey: b.nodeKey), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(ping, from: b.nodeKey, region: 7, at: sockT0, using: &random)
        try #require(outputs.count == 1)
        guard case .derp(let pong, let to, let region) = outputs[0] else {
            Issue.record("Pong이 DERP로 나가지 않았다: \(outputs)")
            return
        }
        #expect(to == b.nodeKey)
        #expect(region == 7)
        #expect(try b.open(pong) == .pong(id, source: try endpoint("127.3.3.40:7")))
        #expect(candidates(sock, b) == [b.address])
    }

    @Test("모르는 DERP 보낸 쪽의 Ping은 버리고 답하지 않는다")
    func derpPingFromUnknownSender() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let ping = try b.seal(.ping(try txID(1), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveDERP(ping, from: c.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
    }

    @Test("UDP로 온 CallMeMaybe와 DERP 보낸 쪽의 disco 키가 맞지 않는 CallMeMaybe는 버린다")
    func misroutedCallMeMaybe() throws {
        var sock = makeSock(peers: [b.peer(endpoints: []), c.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let callMeMaybe = try b.seal(.callMeMaybe([try endpoint("203.0.113.10:41641")]), to: a.discoPublicKey)
        #expect(sock.receiveUDP(callMeMaybe, from: b.address, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
        #expect(sock.receiveDERP(callMeMaybe, from: c.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
        #expect(sock.receiveDERP(callMeMaybe, from: a.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
        #expect(candidates(sock, b).isEmpty && candidates(sock, c).isEmpty)
    }

    @Test("DERP로 온 CallMeMaybe는 모든 후보에 곧바로 Ping하고 CallMeMaybe를 되보내지 않는다")
    func callMeMaybePingsAllCandidates() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let x = try endpoint("203.0.113.10:41641"), y = try endpoint("203.0.113.11:41641")
        // 후보별 5초 간격을 CallMeMaybe가 풀어 주는지 보려고 먼저 한 번 Ping해 둔다.
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
        let callMeMaybe = try b.seal(.callMeMaybe([x, y]), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(callMeMaybe, from: b.nodeKey, region: 1, at: sockTime(10), using: &random)
        #expect(outputs.allSatisfy { if case .udp = $0 { true } else { false } })
        #expect(Set(try pingDestinations(outputs, openedBy: b)) == [b.address, x, y])
        #expect(outputs.count == 3)
    }

    @Test("DERP로 온 WireGuard 데이터그램은 아는 피어의 것만 보낸 쪽과 지역을 실어 올린다")
    func derpWireGuard() {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        #expect(sock.receiveDERP(testDatagram(1), from: b.nodeKey, region: 1, at: sockT0, using: &random) == [.wireGuard(testDatagram(1), from: .derp(b.nodeKey, region: 1))])
        #expect(sock.receiveDERP(testDatagram(2), from: c.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.unknownDERPSender)])
    }

    @Test("disco 길이 한도: 한도 길이의 패딩 Ping에는 답하고, 1바이트 넘으면 열지 않고 버린다")
    func discoLengthLimit() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let limit = Magicsock.maxDiscoPacketLength
        func paddedPing(_ id: TransactionID, total: Int) throws -> [UInt8] {
            let unpadded = DiscoMessage.ping(id, nodeKey: b.nodeKey).plaintext
            let padding = total - 62 - NaClSecretBox.overhead - unpadded.count
            return try b.seal(plaintext: unpadded + [UInt8](repeating: 0, count: padding), to: a.discoPublicKey)
        }
        let atLimit = try paddedPing(try txID(1), total: limit)
        #expect(atLimit.count == limit)
        let answered = sock.receiveUDP(atLimit, from: b.address, at: sockT0, using: &random)
        #expect(answered.count == 1 && answered.first.map { if case .udp = $0 { true } else { false } } == true)
        let over = try paddedPing(try txID(2), total: limit + 1)
        #expect(sock.receiveUDP(over, from: b.address, at: sockTime(1), using: &random) == [.dropped(.malformedDisco)])
    }

    // MARK: 보내기 (동작 D·F)

    @Test("직접 주소도 DERP 지역도 없으면 데이터그램을 버리고, 그때도 Ping은 보낸다")
    func noRouteToPeer() throws {
        let d = try TestIdentity(4, address: "192.0.2.4:41641")
        var sock = makeSock(peers: [b.peer(homeDERP: 0, endpoints: [b.address]), c.peer(homeDERP: 0, endpoints: [])])
        var random = PathTestRandom(state: 7)
        let outputs = sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
        #expect(outputs.contains(.dropped(.noRouteToPeer)))
        #expect(!outputs.contains(.udp(testDatagram(1), to: b.address)))
        #expect(try pingDestinations(outputs, openedBy: b) == [b.address])
        #expect(sock.send(testDatagram(2), to: c.nodeKey, at: sockT0, using: &random)
            == [.dropped(.noRouteToPeer), .pathChanged(c.nodeKey, .relayed(derpRegion: 0))])
        #expect(sock.send(testDatagram(3), to: d.nodeKey, at: sockT0, using: &random) == [.dropped(.noRouteToPeer)])
    }

    @Test("엔드포인트가 27초보다 낡았으면 CallMeMaybe를 미루고 회차를 시작하며, 회차가 끝나면 보낸다")
    func deferredCallMeMaybe() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let server = try TestSTUN.server()
        let start = sock.setRegions([Magicsock.Region(id: 1, stunServers: [server])], at: sockT0, using: &random)
        let request = try #require(start.compactMap(\.stunRequest).first)
        _ = sock.receiveUDP(TestSTUN.response(to: request, mapped: a.address), from: server, at: sockTime(5), using: &random)

        func callMeMaybes(_ outputs: [Magicsock.Output]) throws -> [[IPEndpoint]] {
            try outputs.compactMap(\.discoPacket).filter { $0.derp == b.nodeKey }.compactMap {
                try b.open($0.bytes).callMeMaybeEndpoints
            }
        }

        // 엔드포인트를 정한 지 27초 안: Ping과 함께 곧바로 보낸다.
        let fresh = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(5 + 26_999), using: &random)
        #expect(try callMeMaybes(fresh) == [[a.address]])

        // 27초가 지남: 미루고 회차를 시작한다. 한 번 더 보내도 피어당 한 칸이다.
        let staleAt = sockTime(5 + 26_999 + 5_000)
        let stale = sock.send(testDatagram(2), to: b.nodeKey, at: staleAt, using: &random)
        #expect(try callMeMaybes(stale).isEmpty)
        #expect(try pingDestinations(stale, openedBy: b) == [b.address])
        let restun = try #require(stale.compactMap(\.stunRequest).first)
        #expect(sock.pendingCallMeMaybe == [b.nodeKey])
        _ = sock.send(testDatagram(3), to: b.nodeKey, at: staleAt + .seconds(5), using: &random)
        #expect(sock.pendingCallMeMaybe == [b.nodeKey])

        let refreshed = sock.receiveUDP(TestSTUN.response(to: restun, mapped: a.address), from: server, at: staleAt + .seconds(6), using: &random)
        #expect(try callMeMaybes(refreshed) == [[a.address]])
        #expect(sock.pendingCallMeMaybe.isEmpty)
    }

    // MARK: 피어 표 (동작 B·G)

    @Test("새 피어는 보내기 전까지 경로가 없고, 보내면 .relayed(홈 DERP), 홈이 바뀌면 새 지역, 빼면 nil이 나오며 같은 값은 다시 내지 않는다")
    func peerEvents() {
        var sock = a.magicsock()
        var random = PathTestRandom(state: 7)
        #expect(sock.setPeers([b.peer(homeDERP: 3, endpoints: [])], at: sockT0) == [])
        #expect(sock.path(to: b.nodeKey, at: sockT0) == nil)
        #expect(sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(1), using: &random)
            == [.derp(testDatagram(1), to: b.nodeKey, region: 3), .pathChanged(b.nodeKey, .relayed(derpRegion: 3))])
        #expect(sock.setPeers([b.peer(homeDERP: 3, endpoints: [])], at: sockTime(2)) == [])
        #expect(sock.setPeers([b.peer(homeDERP: 4, endpoints: [])], at: sockTime(3)) == [.pathChanged(b.nodeKey, .relayed(derpRegion: 4))])
        #expect(sock.setPeers([], at: sockTime(4)) == [.pathChanged(b.nodeKey, nil)])
        #expect(sock.path(to: b.nodeKey, at: sockTime(4)) == nil)
        #expect(sock.discoPeers.isEmpty)
        // 알린 적 없는(유휴) 피어는 빠져도 nil을 다시 내지 않는다.
        _ = sock.setPeers([c.peer(endpoints: [])], at: sockTime(5))
        #expect(sock.setPeers([], at: sockTime(6)) == [])
    }

    @Test("마지막 송신 뒤 45초가 넘으면 그 시각의 advance가 경로 nil을 내고, 다시 보내면 그때의 경로가 나온다(동작 G3)")
    func idlePeerHasNoPath() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)
        let idleAt = sockT0 + PeerPathState.sessionActiveTimeout + .nanoseconds(1)

        var events: [(ContinuousClock.Instant, PeerPath?)] = []
        while let deadline = sock.nextDeadline, deadline <= idleAt + .seconds(60) {
            for case .pathChanged(b.nodeKey, let path) in sock.advance(to: deadline, using: &random) {
                events.append((deadline, path))
            }
        }
        // 신뢰가 끝나 .relayed가 되고(Pong이 더 오지 않는다), 45초 경계에서 nil이 된다. 그 뒤로는 걸린 기한이 없다.
        #expect(events.map(\.1) == [.relayed(derpRegion: 1), nil])
        #expect(events.last?.0 == idleAt)
        #expect(sock.path(to: b.nodeKey, at: idleAt - .nanoseconds(1)) == .relayed(derpRegion: 1))
        #expect(sock.path(to: b.nodeKey, at: idleAt) == nil)
        #expect(sock.nextDeadline == nil)

        let resumed = sock.send(testDatagram(2), to: b.nodeKey, at: idleAt + .seconds(60), using: &random)
        #expect(resumed.last == .pathChanged(b.nodeKey, .relayed(derpRegion: 1)))
    }

    @Test("netmap 엔드포인트가 바뀌면 새 주소에 Ping하고 빠진 주소에는 하지 않는다")
    func endpointChange() throws {
        let old = try endpoint("203.0.113.20:41641"), new = try endpoint("203.0.113.21:41641")
        var sock = makeSock(peers: [b.peer(endpoints: [old])])
        var random = PathTestRandom(state: 7)
        #expect(try pingDestinations(sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random), openedBy: b) == [old])
        _ = sock.setPeers([b.peer(endpoints: [new])], at: sockTime(100))
        #expect(try pingDestinations(sock.send(testDatagram(2), to: b.nodeKey, at: sockTime(200), using: &random), openedBy: b) == [new])
    }

    /// `sock`이 `peer`에게 보내고, `peer`가 그 Ping에 Pong해 직접 경로를 세운다.
    private func establishDirect(_ sock: inout Magicsock, with peer: TestIdentity, at time: ContinuousClock.Instant, random: inout PathTestRandom) throws {
        let outputs = sock.send(testDatagram(1), to: peer.nodeKey, at: time, using: &random)
        let ping = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == peer.address })
        guard case .ping(let id, _) = try peer.open(ping.bytes) else {
            Issue.record("Ping이 아니다")
            return
        }
        let pong = try peer.seal(.pong(id, source: a.address), to: a.discoPublicKey)
        #expect(sock.receiveUDP(pong, from: peer.address, at: time + .milliseconds(2), using: &random)
            == [.pathChanged(peer.nodeKey, .direct(peer.address))])
    }

    @Test("피어의 disco 키가 바뀌면 신뢰를 지우고 옛 키를 버린다")
    func discoKeyChange() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)

        let rotated = try TestIdentity(9, address: "192.0.2.9:41641")
        var changed = b.peer(endpoints: [b.address])
        changed.discoKey = rotated.discoPublicKey
        // Go처럼 송신 기록도 지우므로(`invalidateDiscoPathLocked`의 `lastSendExt = 0`) 다음 송신까지 유휴다.
        #expect(sock.setPeers([changed], at: sockTime(10)) == [.pathChanged(b.nodeKey, nil)])
        #expect(Array(sock.discoPeers.keys) == [rotated.discoPublicKey])
        let oldPing = try b.seal(.ping(try txID(3), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(oldPing, from: b.address, at: sockTime(11), using: &random) == [.dropped(.unknownDiscoKey)])
    }

    @Test("같은 disco 키를 두 netmap 피어가 내세우면 둘 다 그 키로 disco를 한다(Go `nodesOfDisco`, 동작 B1)")
    func sharedDiscoKey() throws {
        var cWithBKey = c.peer(endpoints: [c.address])
        cWithBKey.discoKey = b.discoPublicKey
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), cWithBKey])
        var random = PathTestRandom(state: 7)
        #expect(sock.discoPeers.count == 1)
        #expect(sock.discoPeers[b.discoPublicKey]?.nodes == [b.nodeKey, c.nodeKey])
        // c에게 보내면 c의 주소로 그 키로 봉한 Ping이 나간다.
        #expect(try pingDestinations(sock.send(testDatagram(1), to: c.nodeKey, at: sockT0, using: &random), openedBy: b) == [c.address])

        // CallMeMaybe는 DERP 보낸 쪽 피어가 그 키를 쥐었으면 그 피어만 받는다.
        let callMeMaybe = try b.seal(.callMeMaybe([try endpoint("203.0.113.10:41641")]), to: a.discoPublicKey)
        let before = candidates(sock, b)
        #expect(!sock.receiveDERP(callMeMaybe, from: c.nodeKey, region: 1, at: sockTime(1), using: &random).contains(.dropped(.misroutedDisco)))
        #expect(candidates(sock, c).contains(try endpoint("203.0.113.10:41641")))
        #expect(candidates(sock, b) == before)
    }

    @Test("disco 키가 0인 피어는 DERP만 쓴다")
    func zeroDiscoKey() {
        var peer = b.peer(endpoints: [b.address])
        peer.discoKey = .zero
        var sock = makeSock(peers: [peer])
        var random = PathTestRandom(state: 7)
        #expect(sock.discoPeers.isEmpty)
        #expect(sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
            == [.derp(testDatagram(1), to: b.nodeKey, region: 1), .pathChanged(b.nodeKey, .relayed(derpRegion: 1))])
    }

    @Test("빠진 피어는 미뤄 둔 CallMeMaybe 목록에서도 빠진다")
    func removedPeerLeavesPendingList() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
        #expect(sock.pendingCallMeMaybe == [b.nodeKey])
        _ = sock.setPeers([], at: sockTime(1))
        #expect(sock.pendingCallMeMaybe.isEmpty)
    }

    // MARK: 기한 (동작 D7·E5)

    @Test("nextDeadline은 STUN 회차와 피어 타이머의 기한 가운데 가장 이른 것이고, advance는 그것을 처리한다")
    func deadlines() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        #expect(sock.nextDeadline == nil)
        _ = sock.setRegions([Magicsock.Region(id: 1, stunServers: [try TestSTUN.server()])], at: sockT0, using: &random)
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(50), using: &random)

        // STUN 요청 100·200 ms, 회차 마감 3초(계약 E2), heartbeat 송신 + 3초, Ping 기한 송신 + 5초(노트 5절).
        var seen: [ContinuousClock.Instant] = []
        while let deadline = sock.nextDeadline, deadline <= sockTime(5_050) {
            seen.append(deadline)
            _ = sock.advance(to: deadline, using: &random)
            #expect(sock.nextDeadline.map { $0 > deadline } ?? true)
        }
        #expect(seen == [sockTime(100), sockTime(200), sockTime(3_000), sockTime(3_050), sockTime(5_050)])
    }

    @Test("45초 넘게 보내지 않으면 heartbeat와 주기 STUN이 멈추고, 다음 송신이 회차를 다시 건다")
    func idleStopsPeriodicSTUN() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let server = try TestSTUN.server()
        let start = sock.setRegions([Magicsock.Region(id: 1, stunServers: [server])], at: sockT0, using: &random)
        let request = try #require(start.compactMap(\.stunRequest).first)
        _ = sock.receiveUDP(TestSTUN.response(to: request, mapped: a.address), from: server, at: sockTime(5), using: &random)
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(1_000), using: &random)

        var requestTimes: [ContinuousClock.Instant] = []
        while let deadline = sock.nextDeadline, deadline <= sockTime(300_000) {
            if !sock.advance(to: deadline, using: &random).compactMap(\.stunRequest).isEmpty {
                requestTimes.append(deadline)
            }
        }
        #expect(sock.nextDeadline == nil)
        // 송신 뒤 45초 안에 시작한 주기 회차만 있다(20–26초 간격).
        #expect(!requestTimes.isEmpty)
        #expect(requestTimes.allSatisfy { $0 <= sockTime(1_000 + 45_000) + .milliseconds(200) })

        let resumed = sock.send(testDatagram(2), to: b.nodeKey, at: sockTime(300_000), using: &random)
        #expect(resumed.contains { $0.stunRequest != nil })
    }

    // MARK: 신뢰할 수 없는 입력과 비밀 (동작 H·I)

    @Test("임의 바이트열(고정 시드)로 죽지 않고, disco 모양은 WireGuard로 넘어가지 않으며, 공유 키는 피어 수를 넘지 않는다")
    func randomInputs() throws {
        var leaks = 0
        for seed in UInt64(1)...3 {
            var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(homeDERP: 2, endpoints: [])])
            var random = PathTestRandom(state: seed)
            var input = PathTestRandom(state: seed + 100)
            _ = sock.setRegions([Magicsock.Region(id: 1, stunServers: [try TestSTUN.server()])], at: sockT0, using: &random)
            let senders = [b.nodeKey, c.nodeKey, a.nodeKey]
            for step in 0..<3_000 {
                let now = sockTime(Int64(step) * 7)
                let length = Int.random(in: 0...200, using: &input)
                var bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &input) }
                let prefix: [UInt8] = switch step % 5 {
                case 1: DiscoPacket.magic
                case 2: DiscoPacket.magic + b.discoPublicKey.rawValue
                case 3: [0x01, 0x01, 0x00, 0x0C] + STUNMessage.magicCookie
                case 4: [0, 0, 0x7A, 0x11, 0, 0, 1, 0] + DiscoPacket.magic
                default: []
                }
                bytes.replaceSubrange(0..<min(prefix.count, bytes.count), with: prefix)
                let isDisco = DiscoPacket.isDisco(bytes)
                let udp = sock.receiveUDP(bytes, from: step.isMultiple(of: 2) ? b.address : c.address, at: now, using: &random)
                let derp = sock.receiveDERP(bytes, from: senders[step % 3], region: Int64(step % 4), at: now, using: &random)
                if isDisco, (udp + derp).contains(where: { if case .wireGuard = $0 { true } else { false } }) {
                    leaks += 1
                }
                if step.isMultiple(of: 50) {
                    _ = sock.send(testDatagram(UInt32(step)), to: b.nodeKey, at: now, using: &random)
                    _ = sock.advance(to: now, using: &random)
                }
            }
            #expect(sock.discoPeers.count <= sock.peers.count)
        }
        #expect(leaks == 0)
    }

    @Test("dump와 설명에 disco 개인 키와 공유 키가 나오지 않는다")
    func secretsAreHidden() throws {
        let sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        let privateKey = Array(a.discoKey.rawRepresentation)
        let sharedKey = try NaClBox.sharedKey(privateKey: privateKey, peerPublicKey: b.discoPublicKey.rawValue)
        var dumped = ""
        dump(sock, to: &dumped)
        let texts = dumped + String(describing: sock) + String(reflecting: sock)
        #expect(!texts.contains(privateKey.hex))
        #expect(!texts.contains(sharedKey.hex))
        #expect(Mirror(reflecting: sock).children.map(\.label) == ["discoPublicKey", "peerCount", "homeRegion"])
    }
}
