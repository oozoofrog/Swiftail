import CryptoKit
import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// Active key selection on receipt of a TSMP disco key advertisement (the "TSMP disco key advertisement" contract, behaviors T3–T5).
// Expected values come from tailscale.com v1.104.7 `wgengine/magicsock/endpoint.go` (`updateDiscoKey`, `updateTSMPDiscoKey`,
// `checkAndUpdateDiscoKey`) and `magicsock.go` (`HandleDiscoKeyAdvertisement`, BSD-3-Clause).

private func discoKey(_ byte: UInt8) -> DiscoPublicKey {
    DiscoPublicKey(rawValue: [UInt8](repeating: byte, count: 32))!
}

@Suite("PeerDiscoKeys active key decision table")
struct PeerDiscoKeysTests {
    let control = discoKey(0xC1)
    let newer = discoKey(0xC2)
    let tsmp = discoKey(0x71)

    @Test("If only the netmap key is present, it is active, and seeing it again leaves it unchanged")
    func netmapOnly() {
        var keys = PeerDiscoKeys()
        #expect(keys.active == nil)
        let result1 = keys.updateNetmap(nil)
        #expect(result1 == false)
        let result2 = keys.updateNetmap(control)
        #expect(result2)
        #expect(keys.active == control)
        let result3 = keys.updateNetmap(control)
        #expect(result3 == false)
        let result4 = keys.updateNetmap(newer)
        #expect(result4)
        #expect(keys.active == newer)
    }

    @Test("A TSMP advertisement makes its key active. Seeing the same key again leaves it unchanged")
    func tsmpWins() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        let result5 = keys.updateTSMP(tsmp)
        #expect(result5)
        #expect(keys.active == tsmp)
        let result6 = keys.updateTSMP(tsmp)
        #expect(result6 == false)
        #expect(keys.netmap == control)
    }

    @Test("The first advertisement counts as a change even if its key matches the netmap key (rediscovers paths, as in Go)")
    func firstAdvertisementEqualToNetmap() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        let result7 = keys.updateTSMP(control)
        #expect(result7)
        #expect(keys.active == control)
        #expect(keys.tsmpActive)
        let result8 = keys.updateTSMP(control)
        #expect(result8 == false)
    }

    @Test("An active TSMP key stays active if netmap later supplies a different key. This still counts as a change")
    func netmapLaterWithDifferentKey() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        let result9 = keys.updateNetmap(newer)
        #expect(result9)
        #expect(keys.active == tsmp)
        #expect(keys.netmap == newer)
    }

    @Test("When netmap catches up to the TSMP key, the active key stays the same and the update counts as a change")
    func netmapCatchesUp() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        let result10 = keys.updateNetmap(tsmp)
        #expect(result10)
        #expect(keys.active == tsmp)
    }

    @Test("If the advertisement arrives before netmap, the TSMP key becomes active and the later netmap key leaves it active")
    func tsmpBeforeNetmap() {
        var keys = PeerDiscoKeys()
        let result11 = keys.updateTSMP(tsmp)
        #expect(result11)
        #expect(keys.active == tsmp)
        let result12 = keys.updateNetmap(control)
        #expect(result12)
        #expect(keys.active == tsmp)
    }

    @Test("The TSMP key is active even if it is older than the netmap key (Go ignores the order)")
    func staleAdvertisement() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(newer)
        let result13 = keys.updateTSMP(control)
        #expect(result13)
        #expect(keys.active == control)
    }

    @Test("Receiving disco under the inactive key makes it active. Repeating the same advertisement leaves it active")
    func seenInactiveKey() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        let result14 = keys.noteSeen(tsmp)
        #expect(result14 == (true, false))
        let result15 = keys.noteSeen(newer)
        #expect(result15 == (false, false))
        let result16 = keys.noteSeen(control)
        #expect(result16 == (true, true))
        #expect(keys.active == control)
        let result17 = keys.updateTSMP(tsmp)
        #expect(result17 == false)
        #expect(keys.active == control)
        let result18 = keys.noteSeen(tsmp)
        #expect(result18 == (true, true))
        #expect(keys.active == tsmp)
    }

    @Test("Removing the netmap key makes the TSMP key active. With neither key, disco is disabled")
    func keysRemoved() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        _ = keys.noteSeen(control)
        let result19 = keys.updateNetmap(nil)
        #expect(result19)
        #expect(keys.active == tsmp)

        var netmapOnly = PeerDiscoKeys()
        _ = netmapOnly.updateNetmap(control)
        let result20 = netmapOnly.updateNetmap(nil)
        #expect(result20)
        #expect(netmapOnly.active == nil)
        #expect(netmapOnly == PeerDiscoKeys())
    }
}

@Suite("Magicsock receipt of TSMP disco key advertisements")
struct MagicsockDiscoAdvertisementTests {
    let a: TestIdentity
    let b: TestIdentity
    let c: TestIdentity
    /// The new disco key b creates on restart. It is only for sealing and opening, so the node key is ignored (b's node key is supplied separately).
    let restartedB: TestIdentity

    init() throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        c = try TestIdentity(3, address: "192.0.2.3:41641")
        restartedB = try TestIdentity(9, address: "192.0.2.2:41641")
    }

    private func makeSock(peers: [Magicsock.Peer]) -> Magicsock {
        var sock = a.magicsock()
        _ = sock.setPeers(peers, at: sockT0)
        return sock
    }

    /// Sends data to `peer` to emit a Ping and returns a Pong to establish a direct path.
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

    @Test("Accepts disco sealed with the advertised new key before a netmap update and seals the reply with that key. The old netmap key remains known")
    func advertisedKeyIsUsed() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let ping = try restartedB.seal(.ping(try #require(TransactionID([UInt8](repeating: 1, count: 12))), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(ping, from: b.address, at: sockTime(1), using: &random) == [.dropped(.unknownDiscoKey)])

        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2)).isEmpty)
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(Set(sock.discoPeers.keys) == [b.discoPublicKey, restartedB.discoPublicKey])

        let outputs = sock.receiveUDP(ping, from: b.address, at: sockTime(3), using: &random)
        let pong = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .pong = try restartedB.open(pong.bytes) else {
            Issue.record("Expected a Pong")
            return
        }
        // Outgoing Ping is also sealed with the new key.
        let sent = sock.send(testDatagram(2), to: b.nodeKey, at: sockTime(4), using: &random)
        let newPing = try #require(sent.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping = try restartedB.open(newPing.bytes) else {
            Issue.record("Could not open with the new key")
            return
        }
    }

    @Test("An active key change clears trust and pending Pings. Repeating the same advertisement has no effect")
    func advertisementResetsPath() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(10))
            == [.pathChanged(b.nodeKey, nil)])
        #expect(sock.peers[b.nodeKey]?.path.trustedUntil == nil)
        #expect(sock.peers[b.nodeKey]?.path.sentPings.isEmpty == true)
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(11)).isEmpty)

        // When the TSMP key changes again, the previous TSMP key is forgotten (the netmap key remains).
        let third = try TestIdentity(10, address: "192.0.2.2:41641")
        _ = sock.receiveDiscoKeyAdvertisement(third.discoPublicKey, from: b.nodeKey, at: sockTime(12))
        #expect(Set(sock.discoPeers.keys) == [b.discoPublicKey, third.discoPublicKey])
    }

    @Test("A key set to 0 or an advertisement from an unknown peer leaves state intact")
    func ignoredAdvertisements() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        #expect(sock.receiveDiscoKeyAdvertisement(.zero, from: b.nodeKey, at: sockTime(1)).isEmpty)
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: c.nodeKey, at: sockTime(1)).isEmpty)
        #expect(sock.peers[b.nodeKey]?.discoKeys == {
            var keys = PeerDiscoKeys()
            _ = keys.updateNetmap(b.discoPublicKey)
            return keys
        }())
        #expect(Array(sock.discoPeers.keys) == [b.discoPublicKey])
    }

    @Test("An advertisement changes only the sender's key. If it advertises a disco key used by another peer, both hold that key and the other peer stays unchanged")
    func advertisingAnotherPeersKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)
        // c advertises b's netmap key. It becomes c's TSMP key, while b's keys, path, and trust stay intact.
        #expect(sock.receiveDiscoKeyAdvertisement(b.discoPublicKey, from: c.nodeKey, at: sockTime(1)).isEmpty)
        #expect(sock.discoPeers[b.discoPublicKey]?.nodes == [b.nodeKey, c.nodeKey])
        #expect(sock.peers[c.nodeKey]?.discoKey == b.discoPublicKey)
        #expect(sock.peers[b.nodeKey]?.discoKey == b.discoPublicKey)
        #expect(sock.path(to: b.nodeKey, at: sockTime(1)) == .direct(b.address))

        // The same holds for a key b holds via TSMP. b's active key stays the same when c advertises it.
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2))
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: c.nodeKey, at: sockTime(3))
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.nodes == [b.nodeKey, c.nodeKey])
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        // Even when c releases its previous TSMP key (b's netmap key), b still holds it.
        #expect(sock.discoPeers[b.discoPublicKey]?.nodes == [b.nodeKey])
    }

    @Test("Netmap updates retain the TSMP key, even if another peer claims the same key as its netmap key")
    func netmapKeepsTSMPKey() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])])
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(1))
        _ = sock.setPeers([b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])], at: sockTime(2))
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.nodes == [b.nodeKey])

        var cWithThatKey = c.peer(endpoints: [c.address])
        cWithThatKey.discoKey = restartedB.discoPublicKey
        _ = sock.setPeers([b.peer(endpoints: [b.address]), cWithThatKey], at: sockTime(3))
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.nodes == [b.nodeKey, c.nodeKey])
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.peers[c.nodeKey]?.discoKey == restartedB.discoPublicKey)
    }

    @Test("Accepts a DERP CallMeMaybe sealed with an inactive key and makes that key active")
    func callMeMaybeFromInactiveKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])])
        var random = PathTestRandom(state: 7)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(1))
        let callMeMaybe = try b.seal(.callMeMaybe([b.address]), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(callMeMaybe, from: b.nodeKey, region: 1, at: sockTime(2), using: &random)
        #expect(!outputs.contains(.dropped(.misroutedDisco)))
        #expect(sock.peers[b.nodeKey]?.discoKey == b.discoPublicKey)
        // A CallMeMaybe sealed with a key other than the DERP sender's (another peer's key) is still dropped.
        let stranger = try c.seal(.callMeMaybe([c.address]), to: a.discoPublicKey)
        #expect(sock.receiveDERP(stranger, from: b.nodeKey, region: 1, at: sockTime(3), using: &random) == [.dropped(.misroutedDisco)])
    }

    @Test("A UDP Ping can make an inactive key active if the node key belongs to that peer. A different node key leaves the active key intact")
    func pingFromInactiveKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(1))
        let txID = try #require(TransactionID([UInt8](repeating: 2, count: 12)))
        let withoutNodeKey = try b.seal(.ping(txID, nodeKey: nil), to: a.discoPublicKey)
        _ = sock.receiveUDP(withoutNodeKey, from: b.address, at: sockTime(2), using: &random)
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        let withNodeKey = try b.seal(.ping(txID, nodeKey: b.nodeKey), to: a.discoPublicKey, nonce: 2)
        _ = sock.receiveUDP(withNodeKey, from: b.address, at: sockTime(3), using: &random)
        #expect(sock.peers[b.nodeKey]?.discoKey == b.discoPublicKey)
    }
}

/// Tests whose state incoming disco changes when multiple peers hold one disco key (decision table for T5 in the "TSMP disco key advertisement" contract).
/// c holds the same key because it advertised b's netmap key. c cannot seal with it because c lacks its private key.
@Suite("Magicsock peers that hold the same disco key")
struct MagicsockSharedDiscoKeyTests {
    let a: TestIdentity
    let b: TestIdentity
    let c: TestIdentity
    let restartedB: TestIdentity

    init() throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        c = try TestIdentity(3, address: "192.0.2.3:41641")
        restartedB = try TestIdentity(9, address: "192.0.2.2:41641")
    }

    /// Adds b and c to netmap and has c advertise b's netmap key so both hold it.
    private func squatted() -> Magicsock {
        var sock = a.magicsock()
        _ = sock.setPeers([b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])], at: sockT0)
        _ = sock.receiveDiscoKeyAdvertisement(b.discoPublicKey, from: c.nodeKey, at: sockT0)
        return sock
    }

    private func txID(_ value: UInt8) throws -> TransactionID {
        try #require(TransactionID([UInt8](repeating: value, count: TransactionID.byteCount)))
    }

    @Test("Only b receives a Pong for b's Ping because its TxID matches. c holds the same key and its path stays intact")
    func pongGoesToPingOwner() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 7)
        let sent = sock.send(testDatagram(1), to: b.nodeKey, at: sockTime(1), using: &random)
        let ping = try #require(sent.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping(let id, _) = try b.open(ping.bytes) else {
            Issue.record("Expected a Ping")
            return
        }
        let pong = try b.seal(.pong(id, source: a.address), to: a.discoPublicKey)
        #expect(sock.receiveUDP(pong, from: b.address, at: sockTime(1) + .milliseconds(2), using: &random)
            == [.pathChanged(b.nodeKey, .direct(b.address))])
        #expect(sock.peers[c.nodeKey]?.path.trustedUntil == nil)
    }

    @Test("If the Ping names a peer that does not hold the sealing key, that peer's key stays the same")
    func pingNodeKeyMustHoldSenderKey() throws {
        var sock = a.magicsock()
        _ = sock.setPeers([b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])], at: sockT0)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockT0)
        var random = PathTestRandom(state: 7)
        let bBefore = sock.peers[b.nodeKey]?.discoKeys
        let bCandidates = sock.peers[b.nodeKey]?.path.candidates.map(\.address)
        // c seals with its own key and sets the node key to b.
        let forged = try c.seal(.ping(try txID(4), nodeKey: b.nodeKey), to: a.discoPublicKey)
        let outputs = sock.receiveUDP(forged, from: try #require(IPEndpoint("203.0.113.30:41641")), at: sockTime(1), using: &random)
        #expect(outputs.contains { $0.discoPacket != nil })
        #expect(sock.peers[b.nodeKey]?.discoKeys == bBefore)
        #expect(sock.peers[b.nodeKey]?.path.candidates.map(\.address) == bCandidates)
        #expect(sock.peers[c.nodeKey]?.path.candidates.contains { $0.address == IPEndpoint("203.0.113.30:41641") } == true)
    }

    @Test("A DERP Ping gets a reply only to the DERP sender and leaves all peers' candidates intact")
    func derpPingTouchesNoCandidates() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 7)
        let bCandidates = sock.peers[b.nodeKey]?.path.candidates.map(\.address)
        let cCandidates = sock.peers[c.nodeKey]?.path.candidates.map(\.address)
        let ping = try b.seal(.ping(try txID(5), nodeKey: b.nodeKey), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(ping, from: b.nodeKey, region: 1, at: sockTime(1), using: &random)
        #expect(outputs.count == 1)
        #expect(outputs.first?.discoPacket?.derp == b.nodeKey)
        #expect(sock.peers[b.nodeKey]?.path.candidates.map(\.address) == bCandidates)
        #expect(sock.peers[c.nodeKey]?.path.candidates.map(\.address) == cCandidates)
    }

    @Test("A UDP Ping supplies a candidate to every peer holding that key and emits one Pong. A repeated Ping gets no reply")
    func udpPingReachesAllHolders() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 7)
        let source = try #require(IPEndpoint("203.0.113.31:41641"))
        let ping = try b.seal(.ping(try txID(6), nodeKey: b.nodeKey), to: a.discoPublicKey)
        let first = sock.receiveUDP(ping, from: source, at: sockTime(1), using: &random)
        #expect(first.compactMap(\.discoPacket).map(\.udp) == [source])
        for peer in [b, c] {
            #expect(sock.peers[peer.nodeKey]?.path.candidates.contains { $0.address == source } == true)
        }
        #expect(sock.receiveUDP(ping, from: source, at: sockTime(2), using: &random).isEmpty)
    }
}
