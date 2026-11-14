import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// 기대값은 계약 `docs/contracts/SwiftailTunnel.md` 동작 N 2·3.3과 노트 `docs/protocol-notes/disco-magicsock.md` 4.11에서 정했다.
// Go가 재결속 때 지우는 것(`endpoint.go` `noteConnectivityChange`)과 남기는 것은 `PeerPathStateTests`가 따로 덮는다.

/// 재결속 시험의 한 장면: 노드 `a`가 피어 `b`와 직접 경로를 세운 상태.
private struct Scene {
    let a: TestIdentity
    let b: TestIdentity
    let server: IPEndpoint
    let mapped: IPEndpoint
    let localAddress: IPAddress
    var sock: Magicsock
    var random = PathTestRandom(state: 7)
    /// 마지막으로 보낸 시각. 이 뒤의 시각만 쓴다.
    var now = sockT0

    init(withDirectPath: Bool = true) throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        server = try TestSTUN.server()
        mapped = try #require(IPEndpoint("203.0.113.7:61000"))
        localAddress = try #require(IPAddress("192.0.2.1"))
        sock = a.magicsock(localAddresses: [localAddress])
        _ = sock.setPeers([b.peer(endpoints: [b.address])], at: sockT0)
        let start = sock.setRegions([Magicsock.Region(id: 1, stunServers: [server])], at: sockT0, using: &random)
        let request = try #require(start.compactMap(\.stunRequest).first)
        _ = sock.receiveUDP(TestSTUN.response(to: request, mapped: mapped), from: server, at: sockTime(5), using: &random)
        if withDirectPath {
            let outputs = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(10), using: &random)
            let pong = try b.seal(.pong(try pingID(in: outputs), source: a.address), to: a.discoPublicKey)
            let events = sock.receiveUDP(pong, from: b.address, at: sockTime(12), using: &random)
            #expect(events == [.pathChanged(b.nodeKey, .direct(b.address))])
            now = sockTime(12)
        }
    }

    /// 출력 가운데 `b`의 주소로 간 Ping의 TxID.
    func pingID(in outputs: [Magicsock.Output]) throws -> TransactionID {
        let ping = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping(let id, _) = try b.open(ping.bytes) else {
            Issue.record("Ping이 아니다")
            throw CancellationError()
        }
        return id
    }

    /// 출력 가운데 DERP로 `b`에게 간 CallMeMaybe가 담은 주소들. 없으면 nil.
    func callMeMaybe(in outputs: [Magicsock.Output]) throws -> [IPEndpoint]? {
        try outputs.compactMap(\.discoPacket).filter { $0.derp == b.nodeKey }.compactMap {
            try b.open($0.bytes).callMeMaybeEndpoints
        }.first
    }

    /// 지금 인터페이스 주소와 포트로 `rebind`한다.
    mutating func rebind(
        port: UInt16 = 41641,
        addresses: [IPAddress]? = nil,
        at time: ContinuousClock.Instant
    ) -> [Magicsock.Output] {
        sock.rebind(
            localPort: port, localAddresses: addresses ?? [localAddress], loopbackAddresses: [], at: time, using: &random
        )
    }
}

@Suite("Magicsock 재결속")
struct MagicsockRebindTests {
    @Test("직접 경로가 선 피어는 rebind 뒤 .relayed가 되고 .pathChanged가 한 번 나오며, Pong이 오면 다시 .direct가 된다")
    func directPathFallsBackAndRecovers() throws {
        var scene = try Scene()
        let at = sockTime(1000)
        let outputs = scene.rebind(at: at)
        #expect(outputs.filter { if case .pathChanged = $0 { true } else { false } }
            == [.pathChanged(scene.b.nodeKey, .relayed(derpRegion: 1))])
        #expect(scene.sock.path(to: scene.b.nodeKey, at: at) == .relayed(derpRegion: 1))
        // 같은 상태에서 다시 부르면 바뀐 것이 없으므로 경로 사건이 없다.
        #expect(scene.rebind(at: at + .milliseconds(1)).allSatisfy { if case .pathChanged = $0 { false } else { true } })

        // 다음 송신은 전체 Ping과 CallMeMaybe를 내고 DERP로도 보낸다(신뢰가 없으므로. Go와 같다).
        let send = scene.sock.send(testDatagram(2), to: scene.b.nodeKey, at: sockTime(1100), using: &scene.random)
        #expect(send.contains(.derp(testDatagram(2), to: scene.b.nodeKey, region: 1)))
        #expect(!send.contains(.udp(testDatagram(2), to: scene.b.address)))
        let id = try scene.pingID(in: send)
        #expect(try scene.callMeMaybe(in: send) != nil)

        let pong = try scene.b.seal(.pong(id, source: scene.a.address), to: scene.a.discoPublicKey)
        let recovered = scene.sock.receiveUDP(pong, from: scene.b.address, at: sockTime(1105), using: &scene.random)
        #expect(recovered == [.pathChanged(scene.b.nodeKey, .direct(scene.b.address))])
    }

    @Test("rebind 전에 보낸 Ping의 Pong은 뒤늦게 와도 경로를 세우지 않는다")
    func pongOfPreRebindPingIsIgnored() throws {
        var scene = try Scene(withDirectPath: false)
        let sent = scene.sock.send(testDatagram(1), to: scene.b.nodeKey, at: sockTime(10), using: &scene.random)
        let oldPing = try scene.pingID(in: sent)
        _ = scene.rebind(at: sockTime(20))

        let stale = try scene.b.seal(.pong(oldPing, source: scene.a.address), to: scene.a.discoPublicKey)
        #expect(scene.sock.receiveUDP(stale, from: scene.b.address, at: sockTime(30), using: &scene.random) == [])
        #expect(scene.sock.path(to: scene.b.nodeKey, at: sockTime(30)) == .relayed(derpRegion: 1))
        #expect(scene.sock.peers[scene.b.nodeKey]?.path.bestAddr == nil)
    }

    @Test("rebind가 버린 회차의 STUN 응답은 뒤늦게 와도 받지 않고, 새 회차의 응답만 엔드포인트를 정한다")
    func staleRoundResponseIsDropped() throws {
        var scene = try Scene(withDirectPath: false)
        let first = scene.sock.restartSTUN(at: sockTime(100), using: &scene.random)
        let oldRequest = try #require(first.compactMap(\.stunRequest).first)

        let fresh = try #require(IPEndpoint("203.0.113.9:62000"))
        let outputs = scene.rebind(at: sockTime(200))
        let newRequest = try #require(outputs.compactMap(\.stunRequest).first)
        #expect(newRequest != oldRequest)

        let stale = TestSTUN.response(to: oldRequest, mapped: fresh)
        #expect(scene.sock.receiveUDP(stale, from: scene.server, at: sockTime(205), using: &scene.random)
            == [.dropped(.unexpectedSTUN)])

        let result = scene.sock.receiveUDP(
            TestSTUN.response(to: newRequest, mapped: fresh), from: scene.server, at: sockTime(210), using: &scene.random
        )
        #expect(result == [.endpointsChanged([
            Magicsock.Endpoint(address: fresh, source: .stun),
            Magicsock.Endpoint(address: IPEndpoint(address: scene.localAddress, port: 41641), source: .local),
        ])])
    }

    @Test("새 포트와 주소는 다음 .endpointsChanged에 반영되고, 같은 값이면 나오지 않는다")
    func newInputsReachEndpoints() throws {
        var scene = try Scene(withDirectPath: false)
        let newAddress = try #require(IPAddress("192.0.2.50"))

        // 같은 값: STUN 결과도 같으므로 집합이 같다.
        let same = scene.rebind(at: sockTime(100))
        let sameRequest = try #require(same.compactMap(\.stunRequest).first)
        #expect(scene.sock.receiveUDP(
            TestSTUN.response(to: sameRequest, mapped: scene.mapped), from: scene.server, at: sockTime(105), using: &scene.random
        ) == [])

        // 새 포트·주소: 인터페이스 주소가 바뀐다. STUN 바깥 주소는 같다.
        let changed = scene.rebind(port: 41700, addresses: [newAddress], at: sockTime(200))
        let request = try #require(changed.compactMap(\.stunRequest).first)
        #expect(scene.sock.receiveUDP(
            TestSTUN.response(to: request, mapped: scene.mapped), from: scene.server, at: sockTime(205), using: &scene.random
        ) == [.endpointsChanged([
            Magicsock.Endpoint(address: scene.mapped, source: .stun),
            Magicsock.Endpoint(address: IPEndpoint(address: newAddress, port: 41700), source: .local),
        ])])
    }

    @Test("STUN만 다시 시작하는 진입점은 회차를 곧바로 시작하고 경로 상태를 건드리지 않으며, 진행 중이면 한 번 더 시작하지 않는다")
    func restartSTUNOnly() throws {
        var scene = try Scene()
        let at = sockTime(1000)
        let started = scene.sock.restartSTUN(at: at, using: &scene.random)
        #expect(started.compactMap(\.stunRequest).count == 1)
        #expect(started.allSatisfy { $0.stunRequest != nil })
        #expect(scene.sock.path(to: scene.b.nodeKey, at: at) == .direct(scene.b.address))
        #expect(scene.sock.peers[scene.b.nodeKey]?.path.bestAddr?.address == scene.b.address)
        #expect(scene.sock.nextDeadline == at + .milliseconds(100))

        #expect(scene.sock.restartSTUN(at: at + .milliseconds(1), using: &scene.random) == [])
    }

    @Test("지역이 없으면 rebind는 소켓 입력만 바꾸고 STUN을 내지 않으며, 지역이 오면 새 값으로 엔드포인트를 정한다")
    func withoutRegions() throws {
        let a = try TestIdentity(1, address: "192.0.2.1:41641")
        var sock = a.magicsock()
        var random = PathTestRandom(state: 7)
        let newAddress = try #require(IPAddress("192.0.2.50"))
        #expect(sock.rebind(localPort: 41700, localAddresses: [newAddress], loopbackAddresses: [], at: sockT0, using: &random) == [])
        #expect(sock.restartSTUN(at: sockT0, using: &random) == [])
        #expect(sock.nextDeadline == nil)

        let server = try TestSTUN.server()
        let start = sock.setRegions([Magicsock.Region(id: 1, stunServers: [server])], at: sockTime(10), using: &random)
        let request = try #require(start.compactMap(\.stunRequest).first)
        let mapped = try #require(IPEndpoint("203.0.113.7:61000"))
        #expect(sock.receiveUDP(TestSTUN.response(to: request, mapped: mapped), from: server, at: sockTime(15), using: &random)
            == [.endpointsChanged([
                Magicsock.Endpoint(address: mapped, source: .stun),
                Magicsock.Endpoint(address: IPEndpoint(address: newAddress, port: 41700), source: .local),
            ])])
    }

    @Test("유휴 피어(경로 nil)는 rebind 뒤에도 nil이고 경로 사건이 나오지 않는다")
    func idlePeerStaysIdle() throws {
        var scene = try Scene(withDirectPath: false)
        // 보낸 적이 없다.
        #expect(scene.rebind(at: sockTime(100)).allSatisfy { if case .pathChanged = $0 { false } else { true } })
        #expect(scene.sock.path(to: scene.b.nodeKey, at: sockTime(100)) == nil)

        // 보낸 뒤 45초가 지나 nil을 알린 피어.
        _ = scene.sock.send(testDatagram(1), to: scene.b.nodeKey, at: sockTime(200), using: &scene.random)
        let idleAt = sockTime(200) + PeerPathState.sessionActiveTimeout + .nanoseconds(1)
        #expect(scene.sock.path(to: scene.b.nodeKey, at: idleAt) == nil)
        _ = scene.sock.advance(to: idleAt, using: &scene.random)
        let outputs = scene.rebind(at: idleAt + .seconds(1))
        #expect(outputs.allSatisfy { if case .pathChanged = $0 { false } else { true } })
        #expect(scene.sock.path(to: scene.b.nodeKey, at: idleAt + .seconds(1)) == nil)
    }
}

@Suite("PeerPathState 연결 변경")
struct PeerPathConnectivityTests {
    @Test("noteConnectivityChange는 bestAddr·신뢰·Ping 기록을 지우고 후보와 그 출처, 송신 기록은 남긴다(Go noteConnectivityChange)")
    func clearsDerivedState() throws {
        let netmapEndpoint = try pathEndpoint("203.0.113.1:41641")
        let learned = try pathEndpoint("203.0.113.2:41641")
        let fromCallMeMaybe = try pathEndpoint("203.0.113.3:41641")
        var random = PathTestRandom(state: 1)
        var state = PeerPathState(homeDERP: 1, endpoints: [netmapEndpoint])

        _ = state.planSend(at: pathTime(0), using: &random)
        _ = state.receivePing(try #require(TransactionID([UInt8](repeating: 9, count: TransactionID.byteCount))), from: learned, at: pathTime(1))
        let actions = state.receiveCallMeMaybe([fromCallMeMaybe], at: pathTime(10), using: &random)
        #expect(state.receivePong(try actions.txID(to: netmapEndpoint), from: netmapEndpoint, at: pathTime(20)))
        #expect(state.bestAddr?.address == netmapEndpoint)
        #expect(!state.sentPings.isEmpty)

        state.noteConnectivityChange()

        #expect(state.bestAddr == nil)
        #expect(state.trustedUntil == nil)
        #expect(state.sentPings.isEmpty)
        #expect(state.candidates.map(\.address) == [netmapEndpoint, learned, fromCallMeMaybe])
        #expect(state.candidates.allSatisfy { $0.lastPingSent == nil && $0.lastPingReceivedTxID == nil })
        #expect(state.candidates.map(\.inNetmap) == [true, false, false])
        #expect(state.candidates.map { $0.lastPingReceived != nil } == [false, true, false])
        #expect(state.candidates.map(\.fromCallMeMaybe) == [false, false, true])
        // 송신 기록과 heartbeat는 그대로다. 재결속은 세션을 끊지 않는다(Go는 `lastSendExt`를 건드리지 않는다).
        #expect(state.lastSend == pathTime(0))
        #expect(state.heartbeatDeadline == pathTime(0) + PeerPathState.heartbeatInterval)

        // 다음 송신은 모든 후보에 Ping하고 CallMeMaybe도 낸다.
        let plan = state.planSend(at: pathTime(30), using: &random)
        #expect(Set(plan.actions.pingDestinations) == [netmapEndpoint, learned, fromCallMeMaybe])
        #expect(plan.actions.callMeMaybeCount == 1)
        #expect(plan.udp == nil && plan.derpRegion == 1)
    }
}
