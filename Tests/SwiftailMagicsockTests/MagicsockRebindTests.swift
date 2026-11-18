import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// Expected values come from the `docs/contracts/SwiftailTunnel.md` contract, behavior N 2 and 3.3, and `docs/protocol-notes/disco-magicsock.md` §4.11.
// `PeerPathStateTests` separately covers what Go clears and retains when rebinding (`noteConnectivityChange` in `endpoint.go`).

/// A rebind test scenario where node `a` has established a direct path to peer `b`.
private struct Scene {
    let a: TestIdentity
    let b: TestIdentity
    let server: IPEndpoint
    let mapped: IPEndpoint
    let localAddress: IPAddress
    var sock: Magicsock
    var random = PathTestRandom(state: 7)
    /// The time of the last send. The test uses only later times.
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

    /// Returns the TxID of the Ping sent to `b`'s address in the output.
    func pingID(in outputs: [Magicsock.Output]) throws -> TransactionID {
        let ping = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping(let id, _) = try b.open(ping.bytes) else {
            Issue.record("Expected a Ping")
            throw CancellationError()
        }
        return id
    }

    /// Returns the addresses in a CallMeMaybe sent over DERP to `b` in the output, or nil if absent.
    func callMeMaybe(in outputs: [Magicsock.Output]) throws -> [IPEndpoint]? {
        try outputs.compactMap(\.discoPacket).filter { $0.derp == b.nodeKey }.compactMap {
            try b.open($0.bytes).callMeMaybeEndpoints
        }.first
    }

    /// Calls `rebind` with the current interface addresses and port.
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

@Suite("Magicsock rebinding")
struct MagicsockRebindTests {
    @Test("A direct peer becomes .relayed after rebind, emits .pathChanged once, and returns to .direct when a Pong arrives")
    func directPathFallsBackAndRecovers() throws {
        var scene = try Scene()
        let at = sockTime(1000)
        let outputs = scene.rebind(at: at)
        #expect(outputs.filter { if case .pathChanged = $0 { true } else { false } }
            == [.pathChanged(scene.b.nodeKey, .relayed(derpRegion: 1))])
        #expect(scene.sock.path(to: scene.b.nodeKey, at: at) == .relayed(derpRegion: 1))
        // Calling it again in the same state produces no path event because nothing has changed.
        let again = scene.rebind(at: at + .milliseconds(1))
        #expect(again.allSatisfy { if case .pathChanged = $0 { false } else { true } })

        // The next send Pings all candidates and also sends over DERP because there is no trust, as in Go.
        let send = scene.sock.send(testDatagram(2), to: scene.b.nodeKey, at: sockTime(1100), using: &scene.random)
        #expect(send.contains(.derp(testDatagram(2), to: scene.b.nodeKey, region: 1)))
        #expect(!send.contains(.udp(testDatagram(2), to: scene.b.address)))
        let id = try scene.pingID(in: send)
        // CallMeMaybe waits for the new round to finish so it does not advertise the old socket's endpoints. Go behaves differently.
        #expect(try scene.callMeMaybe(in: send) == nil)
        let request = try #require(again.compactMap(\.stunRequest).first)
        let fresh = try #require(IPEndpoint("203.0.113.9:62000"))
        let roundEnd = scene.sock.receiveUDP(
            TestSTUN.response(to: request, mapped: fresh), from: scene.server, at: sockTime(1102), using: &scene.random
        )
        #expect(try scene.callMeMaybe(in: roundEnd)?.first == fresh)

        let pong = try scene.b.seal(.pong(id, source: scene.a.address), to: scene.a.discoPublicKey)
        let recovered = scene.sock.receiveUDP(pong, from: scene.b.address, at: sockTime(1105), using: &scene.random)
        #expect(recovered == [.pathChanged(scene.b.nodeKey, .direct(scene.b.address))])
    }

    @Test("A late Pong for a Ping sent before rebind does not establish a path")
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

    @Test("Late STUN responses for the round discarded by rebind are rejected. Only new-round responses determine endpoints")
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

    @Test("The new port and addresses appear in the next .endpointsChanged, and identical values produce no event")
    func newInputsReachEndpoints() throws {
        var scene = try Scene(withDirectPath: false)
        let newAddress = try #require(IPAddress("192.0.2.50"))

        // Same values. The STUN result is also the same, so the set stays the same.
        let same = scene.rebind(at: sockTime(100))
        let sameRequest = try #require(same.compactMap(\.stunRequest).first)
        #expect(scene.sock.receiveUDP(
            TestSTUN.response(to: sameRequest, mapped: scene.mapped), from: scene.server, at: sockTime(105), using: &scene.random
        ) == [])

        // New port and addresses. The interface address changes and the external STUN address stays the same.
        let changed = scene.rebind(port: 41700, addresses: [newAddress], at: sockTime(200))
        let request = try #require(changed.compactMap(\.stunRequest).first)
        #expect(scene.sock.receiveUDP(
            TestSTUN.response(to: request, mapped: scene.mapped), from: scene.server, at: sockTime(205), using: &scene.random
        ) == [.endpointsChanged([
            Magicsock.Endpoint(address: scene.mapped, source: .stun),
            Magicsock.Endpoint(address: IPEndpoint(address: newAddress, port: 41700), source: .local),
        ])])
    }

    @Test("The STUN-only restart entry point starts a round immediately, preserves path state, and leaves an in-progress round running without starting another")
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

    @Test("With no regions, rebind updates only the socket inputs and sends no STUN. Once a region arrives, it uses the new inputs to determine endpoints")
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

    @Test("An idle peer with a nil path still has a nil path after rebind and emits no path event")
    func idlePeerStaysIdle() throws {
        var scene = try Scene(withDirectPath: false)
        // No sends yet.
        #expect(scene.rebind(at: sockTime(100)).allSatisfy { if case .pathChanged = $0 { false } else { true } })
        #expect(scene.sock.path(to: scene.b.nodeKey, at: sockTime(100)) == nil)

        // A peer whose path was reported as nil 45 seconds after sending.
        _ = scene.sock.send(testDatagram(1), to: scene.b.nodeKey, at: sockTime(200), using: &scene.random)
        let idleAt = sockTime(200) + PeerPathState.sessionActiveTimeout + .nanoseconds(1)
        #expect(scene.sock.path(to: scene.b.nodeKey, at: idleAt) == nil)
        _ = scene.sock.advance(to: idleAt, using: &scene.random)
        let outputs = scene.rebind(at: idleAt + .seconds(1))
        #expect(outputs.allSatisfy { if case .pathChanged = $0 { false } else { true } })
        #expect(scene.sock.path(to: scene.b.nodeKey, at: idleAt + .seconds(1)) == nil)
    }
}

@Suite("PeerPathState connectivity changes")
struct PeerPathConnectivityTests {
    @Test("noteConnectivityChange clears bestAddr, trust, and Ping history and retains candidates, their sources, and send history (Go noteConnectivityChange)")
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
        // Send history and heartbeat persist. Rebinding preserves the session (Go leaves `lastSendExt` intact).
        #expect(state.lastSend == pathTime(0))
        #expect(state.heartbeatDeadline == pathTime(0) + PeerPathState.heartbeatInterval)

        // The next send Pings every candidate and also emits CallMeMaybe.
        let plan = state.planSend(at: pathTime(30), using: &random)
        #expect(Set(plan.actions.pingDestinations) == [netmapEndpoint, learned, fromCallMeMaybe])
        #expect(plan.actions.callMeMaybeCount == 1)
        #expect(plan.udp == nil && plan.derpRegion == 1)
    }
}
