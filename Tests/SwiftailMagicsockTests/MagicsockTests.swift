import CryptoKit
import Testing

import SwiftailBase
import SwiftailCrypto
@testable import SwiftailMagicsock

// Expected values come from the contract (`docs/contracts/SwiftailMagicsock.md`) and notes (`docs/protocol-notes/disco-magicsock.md`).
// Timer values (trust 6.5 seconds, Ping timeout 5 seconds, heartbeat 3 seconds, per-candidate Ping interval 5 seconds, CallMeMaybe freshness 27 seconds, idle 45 seconds,
// STUN 0, 100, and 200 ms and 3 seconds) are taken from notes §5, which records Go `wgengine/magicsock` and `net/netcheck` values (BSD-3-Clause).

private func txID(_ value: UInt8) throws -> TransactionID {
    try #require(TransactionID([UInt8](repeating: value, count: TransactionID.byteCount)))
}

private func endpoint(_ text: String) throws -> IPEndpoint {
    try #require(IPEndpoint(text))
}

/// A network with two nodes, A (0) and B (1), and one test STUN server. B echoes received data.
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

// MARK: - Two nodes

@Suite("Two Magicsock nodes")
struct MagicsockNetworkTests {
    @Test("If netmap gives both nodes each other's endpoints, traffic starts over DERP and a Ping and Pong establish a direct path")
    func directPathFromNetmap() throws {
        var network = try twoNodes(aKnowsB: try endpoint("192.0.2.2:41641"), bKnowsA: true, regions: true)
        let a = network.nodes[0].identity, b = network.nodes[1].identity
        network.run(until: sockTime(1_000))
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(10_000))
        network.sendRepeatedly(from: 0, to: 1, every: nil)
        network.run(until: sockTime(10_100))

        // Notes §4.5 2 and §4.8 2. The first send uses DERP because there is no trusted direct path.
        let sends = network.dataSends(0)
        let first = try #require(sends.first)
        #expect(first.derp && !first.udp)

        let aEvents = network.pathEvents(0, peer: 1)
        #expect(aEvents.first?.path == .relayed(derpRegion: 1))
        let direct = try #require(aEvents.first { $0.path == .direct(b.address) })
        // The path is established as soon as the first Ping's Pong arrives (2 ms UDP round trip).
        #expect(direct.time <= sockTime(1_000) + .milliseconds(5))
        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(a.address))
        #expect(network.nodes[0].sock.path(to: b.nodeKey, at: network.now) == .direct(b.address))

        // Notes §4.5 1. Once a trusted direct path is established, sends use only UDP.
        let afterDirect = sends.filter { $0.time > direct.time }
        #expect(!afterDirect.isEmpty)
        #expect(afterDirect.allSatisfy { $0.udp && !$0.derp })
        // The data sent is delivered as a WireGuard datagram and echoed.
        #expect(network.received.filter { $0.node == 1 }.count == sends.count)
        #expect(network.received.contains { $0.node == 0 && isTestDatagram($0.bytes) })
        #expect(network.deadlineViolations == 0)
    }

    @Test("Even without A's endpoint, B learns it from the source of the received Ping and establishes a direct path (calculation in notes §4.8)")
    func learnsFromPingSource() throws {
        // Without a region, endpoints cannot be determined and no CallMeMaybe goes out. Check that the Ping source alone establishes the path.
        var network = try twoNodes(aKnowsB: try endpoint("192.0.2.2:41641"), bKnowsA: false, regions: false)
        let a = network.nodes[0].identity
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(5_000))

        #expect(!network.discoLog.contains { $0.message.callMeMaybeEndpoints != nil })
        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(a.address))
        #expect(network.pathEvents(0, peer: 1).last?.path == .direct(network.nodes[1].identity.address))
    }

    @Test("A CallMeMaybe recipient immediately Pings the advertised address and both sides establish a direct path")
    func callMeMaybeExchange() throws {
        // A knows an old, unreachable address for B, and B does not know A's address. Only A's CallMeMaybe opens the path.
        var network = try twoNodes(aKnowsB: try endpoint("198.51.100.99:41641"), bKnowsA: false, regions: true)
        let a = network.nodes[0].identity, b = network.nodes[1].identity
        network.run(until: sockTime(1_000))
        network.sendRepeatedly(from: 0, to: 1, every: .seconds(1))
        network.run(until: sockTime(8_000))

        let callMeMaybe = try #require(network.discoLog.first { $0.from == 0 && $0.message.callMeMaybeEndpoints != nil })
        #expect(callMeMaybe.viaDERP)
        // Notes §4.8 4.2. Includes all local endpoints (here, one STUN result).
        #expect(callMeMaybe.message.callMeMaybeEndpoints == [a.address])
        // Notes §4.8 5. Pings immediately on receipt (reaches A after 1 ms of UDP latency).
        let bPing = try #require(network.discoLog.first { $0.from == 1 && $0.message.isPing })
        #expect(bPing.time == callMeMaybe.time + network.udpLatency)
        #expect(!bPing.viaDERP)
        // The full Ping sweep triggered by the incoming CallMeMaybe sends no CallMeMaybe back.
        #expect(!network.discoLog.contains { $0.from == 1 && $0.message.callMeMaybeEndpoints != nil && $0.time <= bPing.time })

        #expect(network.pathEvents(1, peer: 0).last?.path == .direct(a.address))
        #expect(network.pathEvents(0, peer: 1).last?.path == .direct(b.address))
    }

    @Test("Blocking UDP makes the path .relayed at last Pong + 6.5 seconds, sends data over both UDP and DERP in the meantime, and returns to .direct when unblocked")
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

        // The last UDP Pong from B that reached A.
        let lastPong = try #require(network.discoLog.last { $0.to == 0 && $0.from == 1 && !$0.viaDERP && $0.message.isPong })
        #expect(lastPong.time <= blockedAt)
        let trustEnd = lastPong.time + .milliseconds(6_500)

        // Contract D7 and G1. advance emits .relayed at the time trust expires (the trust period includes that exact time).
        let relayed = try #require(network.pathEvents(0, peer: 1).first { $0.time > blockedAt })
        #expect(relayed.path == .relayed(derpRegion: 1))
        #expect(relayed.time > trustEnd)
        #expect(relayed.time <= trustEnd + .milliseconds(1))

        let sends = network.dataSends(0).filter { $0.time > blockedAt && $0.time < sockTime(40_000) }
        // Notes §4.5 1. Uses only UDP during the trust period.
        #expect(sends.filter { $0.time <= trustEnd }.allSatisfy { $0.udp && !$0.derp })
        // Notes §4.5 2. After trust expires, uses both the remaining bestAddr and DERP.
        let heartbeatPingExpiry = lastPong.time + .seconds(3) + .seconds(5)
        #expect(sends.contains { $0.time > trustEnd && $0.time < heartbeatPingExpiry && $0.udp && $0.derp })
        // Notes §4.6 3. After trust expires, an expired heartbeat Ping (sent within 3 seconds after the Pong, with a 5-second deadline) clears bestAddr and leaves only DERP.
        let derpOnly = sends.filter { $0.time > heartbeatPingExpiry }
        #expect(!derpOnly.isEmpty)
        #expect(derpOnly.allSatisfy { $0.derp && !$0.udp })
        // Data still arrives over DERP while UDP is blocked.
        #expect(network.received.contains { $0.node == 1 && $0.time > heartbeatPingExpiry })

        // Once UDP is unblocked, a Pong from the full Ping sweep on each send (5-second interval per candidate) restores the direct path (notes §7.2 3).
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

// MARK: - One node, classification and rules

@Suite("Magicsock receive handling and rules")
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

    /// Returns the destinations of outgoing UDP disco Pings. Every Ping must contain the node key of `a`.
    private func pingDestinations(_ outputs: [Magicsock.Output], openedBy peer: TestIdentity) throws -> [IPEndpoint] {
        try outputs.compactMap(\.discoPacket).compactMap { packet -> IPEndpoint? in
            guard let destination = packet.udp else { return nil }
            guard case .ping(_, let nodeKey) = try peer.open(packet.bytes) else { return nil }
            #expect(nodeKey == a.nodeKey)
            return destination
        }
    }

    // MARK: Classification (behavior A)

    @Test("Datagrams other than disco and STUN are delivered as .wireGuard without inspecting their contents")
    func plainDatagram() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let initiation: [UInt8] = [1, 0, 0, 0] + [UInt8](repeating: 0, count: 144)
        for datagram in [testDatagram(1), [], initiation] {
            #expect(sock.receiveUDP(datagram, from: b.address, at: sockT0, using: &random) == [.wireGuard(datagram, from: .udp(b.address))])
        }
        // The source is preserved even if the address is outside the peer's candidates (WireGuard sends the cookie reply there).
        let stranger = IPEndpoint(address: b.address.address, port: b.address.port &+ 1)
        #expect(sock.receiveUDP(initiation, from: stranger, at: sockT0, using: &random) == [.wireGuard(initiation, from: .udp(stranger))])
    }

    @Test("Rejects source addresses with IPv6 or port 0", arguments: ["[2001:db8::1]:41641", "192.0.2.2:0"])
    func unsupportedSource(_ text: String) throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let source = try endpoint(text)
        let ping = try b.seal(.ping(try txID(1), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(ping, from: source, at: sockT0, using: &random) == [.dropped(.unsupportedSource)])
        #expect(sock.receiveUDP(testDatagram(1), from: source, at: sockT0, using: &random) == [.dropped(.unsupportedSource)])
        #expect(candidates(sock, b).isEmpty)
    }

    @Test("Drops out-of-round or unparseable STUN responses, and uses responses for the current round as endpoints")
    func stunResponses() throws {
        var sock = a.magicsock()
        var random = PathTestRandom(state: 7)
        let server = try TestSTUN.server()
        let stray = TestSTUN.response(to: STUNMessage.bindingRequest(try txID(9)), mapped: a.address)
        #expect(sock.receiveUDP(stray, from: server, at: sockT0, using: &random) == [.dropped(.unexpectedSTUN)])

        let start = sock.setRegions([Magicsock.Region(id: 1, stunServers: [server])], at: sockT0, using: &random)
        let request = try #require(start.compactMap(\.stunRequest).first)
        // A response without an address attribute still looks like STUN, so it is never delivered to WireGuard.
        var headerOnly = Array(TestSTUN.response(to: request, mapped: a.address).prefix(STUNMessage.headerLength))
        headerOnly[3] = 0
        #expect(sock.receiveUDP(headerOnly, from: server, at: sockTime(1), using: &random) == [.dropped(.unexpectedSTUN)])

        let response = TestSTUN.response(to: request, mapped: a.address)
        // Contract E4. STUN global addresses (.stun) precede interface addresses (none here).
        #expect(sock.receiveUDP(response, from: server, at: sockTime(5), using: &random)
            == [.endpointsChanged([Magicsock.Endpoint(address: a.address, source: .stun)])])
        #expect(sock.receiveUDP(response, from: server, at: sockTime(6), using: &random) == [.dropped(.unexpectedSTUN)])
    }

    @Test("setRegions emits the fallback home immediately, then chooses a home by latency and publishes endpoints at the end of the round")
    func regionsAndHome() throws {
        let local = try #require(IPAddress("192.0.2.1"))
        var sock = a.magicsock(localAddresses: [local])
        var random = PathTestRandom(state: 7)
        let server1 = try endpoint("198.51.100.53:3478"), server2 = try endpoint("198.51.100.54:3478")
        let start = sock.setRegions(
            [Magicsock.Region(id: 1, stunServers: [server1]), Magicsock.Region(id: 2, stunServers: [server2])],
            at: sockT0, using: &random
        )
        // Contract E6 "fallback home" uses the lowest region ID.
        #expect(start.first == .homeRegionChanged(1))
        let requests = start.compactMap { output -> (bytes: [UInt8], to: IPEndpoint)? in
            if case .udp(let bytes, let to) = output, STUNMessage.looksLikeSTUN(bytes) { (bytes, to) } else { nil }
        }
        #expect(requests.map(\.to).sorted { $0.description < $1.description } == [server1, server2])
        let request1 = try #require(requests.first { $0.to == server1 }), request2 = try #require(requests.first { $0.to == server2 })

        let mapped = try endpoint("203.0.113.7:61000")
        // Region 2 replies at 5 ms and region 1 at 50 ms. Both must reply for the round to finish.
        #expect(sock.receiveUDP(TestSTUN.response(to: request2.bytes, mapped: mapped), from: server2, at: sockTime(5), using: &random) == [])
        let finished = sock.receiveUDP(TestSTUN.response(to: request1.bytes, mapped: mapped), from: server1, at: sockTime(50), using: &random)
        // The home switches because the difference is 45 ms (at least 10 ms) and 5 ms is below 2/3 of 50 ms (DERP notes §4.10 5).
        #expect(finished == [
            .endpointsChanged([
                Magicsock.Endpoint(address: mapped, source: .stun),
                Magicsock.Endpoint(address: try endpoint("192.0.2.1:41641"), source: .local),
            ]),
            .homeRegionChanged(2),
        ])
    }

    @Test("Drops Geneve-wrapped datagrams and delivers packets whose headers Go treats as bare WireGuard unchanged")
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

    // MARK: Receiving disco (behaviors B and C)

    @Test("Drops packets from unknown disco keys without computing a shared key")
    func unknownDiscoKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let ping = try c.seal(.ping(try txID(1), nodeKey: c.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(ping, from: c.address, at: sockT0, using: &random) == [.dropped(.unknownDiscoKey)])
        #expect(sock.receiveDERP(ping, from: b.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.unknownDiscoKey)])
        #expect(Array(sock.discoPeers.keys) == [b.discoPublicKey])
    }

    @Test("Drops disco that cannot be opened or is truncated as malformedDisco and sends no Pong")
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

    @Test("Drops unsupported disco types (peer relay) with state intact", arguments: UInt8(0x04)...UInt8(0x09))
    func relayTypes(_ type: UInt8) throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let packet = try b.seal(plaintext: [type, 0] + [UInt8](repeating: 0x11, count: 160), to: a.discoPublicKey)
        let before = sock.peers[b.nodeKey]?.path.candidates
        #expect(sock.receiveUDP(packet, from: try endpoint("203.0.113.9:5000"), at: sockT0, using: &random) == [.dropped(.unsupportedDisco)])
        #expect(sock.receiveDERP(packet, from: b.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.unsupportedDisco)])
        #expect(sock.peers[b.nodeKey]?.path.candidates == before)
    }

    @Test("Replies to a UDP Ping with a Pong to the source, learns the source as a candidate, and ignores replays of that Ping")
    func udpPing() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let source = try endpoint("203.0.113.9:5000")
        let id = try txID(1)
        let ping = try b.seal(.ping(id, nodeKey: b.nodeKey), to: a.discoPublicKey)
        let outputs = sock.receiveUDP(ping, from: source, at: sockT0, using: &random)
        try #require(outputs.count == 1)
        guard case .udp(let pong, let destination) = outputs[0] else {
            Issue.record("Pong did not go out over UDP: \(outputs)")
            return
        }
        #expect(destination == source)
        #expect(try b.open(pong) == .pong(id, source: source))
        #expect(sock.receiveUDP(ping, from: source, at: sockTime(1), using: &random) == [])

        // The learned source is a Ping target on the next send (notes §4.2 4.2).
        let sent = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(2), using: &random)
        #expect(try pingDestinations(sent, openedBy: b) == [source])
    }

    @Test("Replies to a DERP Ping over DERP in the same region with Src 127.3.3.40:<region> and adds no candidate")
    func derpPing() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let id = try txID(1)
        let ping = try b.seal(.ping(id, nodeKey: b.nodeKey), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(ping, from: b.nodeKey, region: 7, at: sockT0, using: &random)
        try #require(outputs.count == 1)
        guard case .derp(let pong, let to, let region) = outputs[0] else {
            Issue.record("Pong did not go out over DERP: \(outputs)")
            return
        }
        #expect(to == b.nodeKey)
        #expect(region == 7)
        #expect(try b.open(pong) == .pong(id, source: try endpoint("127.3.3.40:7")))
        #expect(candidates(sock, b) == [b.address])
    }

    @Test("Drops a Ping from an unknown DERP sender without a reply")
    func derpPingFromUnknownSender() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let ping = try b.seal(.ping(try txID(1), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveDERP(ping, from: c.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
    }

    @Test("Drops UDP CallMeMaybe and CallMeMaybe with a disco key that does not match the DERP sender")
    func misroutedCallMeMaybe() throws {
        var sock = makeSock(peers: [b.peer(endpoints: []), c.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        let callMeMaybe = try b.seal(.callMeMaybe([try endpoint("203.0.113.10:41641")]), to: a.discoPublicKey)
        #expect(sock.receiveUDP(callMeMaybe, from: b.address, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
        #expect(sock.receiveDERP(callMeMaybe, from: c.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
        #expect(sock.receiveDERP(callMeMaybe, from: a.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.misroutedDisco)])
        #expect(candidates(sock, b).isEmpty && candidates(sock, c).isEmpty)
    }

    @Test("A DERP CallMeMaybe immediately triggers a Ping to every candidate without sending a CallMeMaybe back")
    func callMeMaybePingsAllCandidates() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let x = try endpoint("203.0.113.10:41641"), y = try endpoint("203.0.113.11:41641")
        // Ping once first to check whether CallMeMaybe overrides the 5-second per-candidate interval.
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
        let callMeMaybe = try b.seal(.callMeMaybe([x, y]), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(callMeMaybe, from: b.nodeKey, region: 1, at: sockTime(10), using: &random)
        #expect(outputs.allSatisfy { if case .udp = $0 { true } else { false } })
        #expect(Set(try pingDestinations(outputs, openedBy: b)) == [b.address, x, y])
        #expect(outputs.count == 3)
    }

    @Test("Only known peers' DERP WireGuard datagrams are delivered, with sender and region")
    func derpWireGuard() {
        var sock = makeSock(peers: [b.peer(endpoints: [])])
        var random = PathTestRandom(state: 7)
        #expect(sock.receiveDERP(testDatagram(1), from: b.nodeKey, region: 1, at: sockT0, using: &random) == [.wireGuard(testDatagram(1), from: .derp(b.nodeKey, region: 1))])
        #expect(sock.receiveDERP(testDatagram(2), from: c.nodeKey, region: 1, at: sockT0, using: &random) == [.dropped(.unknownDERPSender)])
    }

    @Test("At the disco length limit, a padded Ping gets a reply. A Ping 1 byte over the limit is dropped unopened")
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

    // MARK: Sending (behaviors D and F)

    @Test("With neither a direct address nor a DERP region, the datagram is dropped and Pings still go out")
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

    @Test("If endpoints are older than 27 seconds, CallMeMaybe is deferred and a round starts. CallMeMaybe is sent when the round finishes")
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

        // Within 27 seconds of determining endpoints, send immediately with the Ping.
        let fresh = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(5 + 26_999), using: &random)
        #expect(try callMeMaybes(fresh) == [[a.address]])

        // After 27 seconds, defer and start a round. Even with another send, there is one slot per peer.
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

    // MARK: Peer table (behaviors B and G)

    @Test("A new peer has no path until a send emits .relayed (home DERP), a home change emits the new region, and removal emits nil. Repeated values are suppressed")
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
        // Removing an idle peer whose path was never reported emits no nil.
        _ = sock.setPeers([c.peer(endpoints: [])], at: sockTime(5))
        #expect(sock.setPeers([], at: sockTime(6)) == [])
    }

    @Test("After more than 45 seconds since the last send, advance at that time emits a nil path. The next send emits the path at that time (behavior G3)")
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
        // Trust expires and the path becomes .relayed (no more Pongs), then becomes nil at the 45-second boundary. No deadline remains after that.
        #expect(events.map(\.1) == [.relayed(derpRegion: 1), nil])
        #expect(events.last?.0 == idleAt)
        #expect(sock.path(to: b.nodeKey, at: idleAt - .nanoseconds(1)) == .relayed(derpRegion: 1))
        #expect(sock.path(to: b.nodeKey, at: idleAt) == nil)
        #expect(sock.nextDeadline == nil)

        let resumed = sock.send(testDatagram(2), to: b.nodeKey, at: idleAt + .seconds(60), using: &random)
        #expect(resumed.last == .pathChanged(b.nodeKey, .relayed(derpRegion: 1)))
    }

    @Test("When netmap endpoints change, Pings go to new addresses and skip removed addresses")
    func endpointChange() throws {
        let old = try endpoint("203.0.113.20:41641"), new = try endpoint("203.0.113.21:41641")
        var sock = makeSock(peers: [b.peer(endpoints: [old])])
        var random = PathTestRandom(state: 7)
        #expect(try pingDestinations(sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random), openedBy: b) == [old])
        _ = sock.setPeers([b.peer(endpoints: [new])], at: sockTime(100))
        #expect(try pingDestinations(sock.send(testDatagram(2), to: b.nodeKey, at: sockTime(200), using: &random), openedBy: b) == [new])
    }

    /// Sends from `sock` to `peer`. Then `peer` returns a Pong to establish a direct path.
    private func establishDirect(_ sock: inout Magicsock, with peer: TestIdentity, at time: ContinuousClock.Instant, random: inout PathTestRandom) throws {
        let outputs = sock.send(testDatagram(1), to: peer.nodeKey, at: time, using: &random)
        let ping = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == peer.address })
        guard case .ping(let id, _) = try peer.open(ping.bytes) else {
            Issue.record("Expected a Ping")
            return
        }
        let pong = try peer.seal(.pong(id, source: a.address), to: a.discoPublicKey)
        #expect(sock.receiveUDP(pong, from: peer.address, at: time + .milliseconds(2), using: &random)
            == [.pathChanged(peer.nodeKey, .direct(peer.address))])
    }

    @Test("Changing a peer's disco key clears trust and discards the old key")
    func discoKeyChange() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)

        let rotated = try TestIdentity(9, address: "192.0.2.9:41641")
        var changed = b.peer(endpoints: [b.address])
        changed.discoKey = rotated.discoPublicKey
        // As in Go, this also clears send history (`lastSendExt = 0` in `invalidateDiscoPathLocked`), so it stays idle until the next send.
        #expect(sock.setPeers([changed], at: sockTime(10)) == [.pathChanged(b.nodeKey, nil)])
        #expect(Array(sock.discoPeers.keys) == [rotated.discoPublicKey])
        let oldPing = try b.seal(.ping(try txID(3), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(oldPing, from: b.address, at: sockTime(11), using: &random) == [.dropped(.unknownDiscoKey)])
    }

    @Test("If two netmap peers claim the same disco key, both use it for disco (Go `nodesOfDisco`, behavior B1)")
    func sharedDiscoKey() throws {
        var cWithBKey = c.peer(endpoints: [c.address])
        cWithBKey.discoKey = b.discoPublicKey
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), cWithBKey])
        var random = PathTestRandom(state: 7)
        #expect(sock.discoPeers.count == 1)
        #expect(sock.discoPeers[b.discoPublicKey]?.nodes == [b.nodeKey, c.nodeKey])
        // Sending to c emits a Ping sealed with that key to c's address.
        #expect(try pingDestinations(sock.send(testDatagram(1), to: c.nodeKey, at: sockT0, using: &random), openedBy: b) == [c.address])

        // Only the DERP sender peer receives CallMeMaybe if that peer holds the key.
        let callMeMaybe = try b.seal(.callMeMaybe([try endpoint("203.0.113.10:41641")]), to: a.discoPublicKey)
        let before = candidates(sock, b)
        #expect(!sock.receiveDERP(callMeMaybe, from: c.nodeKey, region: 1, at: sockTime(1), using: &random).contains(.dropped(.misroutedDisco)))
        #expect(candidates(sock, c).contains(try endpoint("203.0.113.10:41641")))
        #expect(candidates(sock, b) == before)
    }

    @Test("A peer whose disco key is 0 uses only DERP")
    func zeroDiscoKey() {
        var peer = b.peer(endpoints: [b.address])
        peer.discoKey = .zero
        var sock = makeSock(peers: [peer])
        var random = PathTestRandom(state: 7)
        #expect(sock.discoPeers.isEmpty)
        #expect(sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
            == [.derp(testDatagram(1), to: b.nodeKey, region: 1), .pathChanged(b.nodeKey, .relayed(derpRegion: 1))])
    }

    @Test("Removing a peer also removes it from the deferred CallMeMaybe list")
    func removedPeerLeavesPendingList() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockT0, using: &random)
        #expect(sock.pendingCallMeMaybe == [b.nodeKey])
        _ = sock.setPeers([], at: sockTime(1))
        #expect(sock.pendingCallMeMaybe.isEmpty)
    }

    // MARK: Deadlines (behaviors D7 and E5)

    @Test("nextDeadline is the earliest deadline among the STUN round and peer timers, and advance handles it")
    func deadlines() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        #expect(sock.nextDeadline == nil)
        _ = sock.setRegions([Magicsock.Region(id: 1, stunServers: [try TestSTUN.server()])], at: sockT0, using: &random)
        _ = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(50), using: &random)

        // STUN requests at 100 and 200 ms, round deadline at 3 seconds (contract E2), heartbeat at send + 3 seconds, and Ping deadline at send + 5 seconds (notes §5).
        var seen: [ContinuousClock.Instant] = []
        while let deadline = sock.nextDeadline, deadline <= sockTime(5_050) {
            seen.append(deadline)
            _ = sock.advance(to: deadline, using: &random)
            #expect(sock.nextDeadline.map { $0 > deadline } ?? true)
        }
        #expect(seen == [sockTime(100), sockTime(200), sockTime(3_000), sockTime(3_050), sockTime(5_050)])
    }

    @Test("After more than 45 seconds without sending, heartbeat and periodic STUN stop, and the next send restarts the round")
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
        // The only periodic rounds are those started within 45 seconds of the send (20–26-second intervals).
        #expect(!requestTimes.isEmpty)
        #expect(requestTimes.allSatisfy { $0 <= sockTime(1_000 + 45_000) + .milliseconds(200) })

        let resumed = sock.send(testDatagram(2), to: b.nodeKey, at: sockTime(300_000), using: &random)
        #expect(resumed.contains { $0.stunRequest != nil })
    }

    // MARK: Untrusted input and secrets (behaviors H and I)

    @Test("Arbitrary bytes (fixed seed) do not crash, disco-shaped input never reaches WireGuard, and shared keys never outnumber peers")
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

    @Test("dump and descriptions hide the disco private key and shared keys")
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
