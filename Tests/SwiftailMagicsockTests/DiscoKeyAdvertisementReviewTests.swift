import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// Independent review tests for TSMP disco key advertisements on the magicsock side. Checks against Go what one peer can change with an advertisement.
// Reference is tailscale.com v1.104.7 `wgengine/magicsock/magicsock.go` (`HandleDiscoKeyAdvertisement`,
// `unambiguousNodeKeyOfPingLocked`, `handlePingLocked`) and `peermap.go` (`upsertEndpoint` and `nodesOfDisco`, a set that holds
// multiple nodes for one key). BSD-3-Clause.

@Suite("Review of disco keys previously advertised by another peer")
struct DiscoKeyAdvertisementReviewTests {
    let a: TestIdentity
    /// An honest peer that restarted and uses a new disco key.
    let b: TestIdentity
    /// A malicious peer that learned b's new disco key (on the same tailnet, authenticated by WireGuard).
    let c: TestIdentity
    /// The disco key after b restarts. b's node key is supplied separately.
    let restartedB: TestIdentity

    init() throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        c = try TestIdentity(3, address: "192.0.2.3:41641")
        restartedB = try TestIdentity(9, address: "192.0.2.2:41641")
    }

    /// a's netmap has only b's old disco key because the update is delayed. c advertises b's new key before b does.
    private func squatted() -> Magicsock {
        var sock = a.magicsock()
        _ = sock.setPeers([b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])], at: sockT0)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: c.nodeKey, at: sockTime(1))
        return sock
    }

    @Test("Accepts b's own advertisement even if c advertises b's new key first (accepts both as Go does, making the new key b's active key)")
    func ownerAdvertisementIsAcceptedAfterSquat() {
        var sock = squatted()
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2))
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
    }

    @Test("b also gets the subsequent UDP Ping that b seals with its new key (node key = b). c holds the same key and learns b's address as a candidate")
    func ownersPingReachesOwner() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 11)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2))
        let txID = try #require(TransactionID([UInt8](repeating: 5, count: 12)))
        let ping = try restartedB.seal(.ping(txID, nodeKey: b.nodeKey), to: a.discoPublicKey)
        _ = sock.receiveUDP(ping, from: b.address, at: sockTime(3), using: &random)
        // As in Go, c also holds that key and learns b's address as a candidate (`forEachEndpointWithDiscoKey` in `handlePingLocked`).
        #expect(sock.peers[c.nodeKey]?.path.candidates.contains { $0.address == b.address } == true)
        // Go identifies b from the Ping's node key because b also holds that disco key (`unambiguousNodeKeyOfPingLocked`). b already has the candidate as a netmap
        // endpoint, so check whether the Ping reached that candidate.
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.peers[b.nodeKey]?.path.candidates.first { $0.address == b.address }?.lastPingReceivedTxID == txID)
    }

    @Test("c gets a direct path to b's address. WireGuard traffic from a to c goes to b (same as Go, and c loses only its own traffic)")
    func squatterPathPointsAtOwner() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 11)
        let txID = try #require(TransactionID([UInt8](repeating: 5, count: 12)))
        let ping = try restartedB.seal(.ping(txID, nodeKey: b.nodeKey), to: a.discoPublicKey)
        _ = sock.receiveUDP(ping, from: b.address, at: sockTime(3), using: &random)

        // When a sends data to c, a Ping sealed with c's active key (= b's new key) also goes to b's address. b can open it and replies.
        let sent = sock.send(testDatagram(1), to: c.nodeKey, at: sockTime(4), using: &random)
        let pingToB = try #require(sent.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping(let id, _) = try restartedB.open(pingToB.bytes) else {
            Issue.record("Expected a Ping that b could open")
            return
        }
        let pong = try restartedB.seal(.pong(id, source: a.address), to: a.discoPublicKey, nonce: 2)
        let outputs = sock.receiveUDP(pong, from: b.address, at: sockTime(5), using: &random)
        // Go also checks the Pong against every peer holding the key (`forEachEndpointWithDiscoKey`). It establishes c's path because its TxID matches.
        #expect(outputs.contains(.pathChanged(c.nodeKey, .direct(b.address))))
    }

    // The semantics changed. Before the fix, c lost its TSMP key when the netmap gave it to b (one peer per key). As in Go, allowing
    // multiple peers to hold a key lets c keep using the key it advertised. Only c's own advertisements change its state, and the only traffic lost is
    // c's own (`squatterPathPointsAtOwner`).
    @Test("When the netmap gives b its new key, b holds it as its netmap key. c keeps using the key it advertised (same as Go)")
    func recoversOnNetmap() {
        var sock = squatted()
        var newB = b.peer(endpoints: [b.address])
        newB.discoKey = restartedB.discoPublicKey
        _ = sock.setPeers([newB, c.peer(endpoints: [c.address])], at: sockTime(10))
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.nodes == [b.nodeKey, c.nodeKey])
        #expect(sock.peers[c.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.peers[c.nodeKey]?.discoKeys.netmap == c.discoPublicKey)
    }

    @Test("Even if a peer keeps advertising different keys, the table holds at most two keys per peer (Go also removes old TSMP keys)")
    func rotatingAdvertisementsAreBounded() throws {
        var sock = a.magicsock()
        _ = sock.setPeers([b.peer(endpoints: [b.address])], at: sockT0)
        for seed in UInt8(20)..<UInt8(120) {
            let rotated = try TestIdentity(seed, address: "192.0.2.2:41641")
            _ = sock.receiveDiscoKeyAdvertisement(rotated.discoPublicKey, from: b.nodeKey, at: sockTime(Int64(seed)))
        }
        #expect(sock.discoPeers.count == 2)
        #expect(sock.peers[b.nodeKey]?.discoKeys.netmap == b.discoPublicKey)
    }
}
