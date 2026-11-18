// Contract test 2 passes times directly to test timers and key rotation without waiting in real time.

import Testing

@testable import SwiftailWireGuard

@Suite("Timers and key rotation")
struct TimerTests {
    @Test("When a keypair is older than 120 seconds, the initiator rekeys after sending and still accepts late packets under the old keypair")
    func initiatorRekeysAfter120Seconds() throws {
        var pair = Pair()
        try pair.establish()
        let oldIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)

        // At exactly 120 seconds, rekeying is not due yet ("older than").
        let at120 = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(120))
        #expect(at120.messageTypes == [4])
        try pair.deliver(at120, from: .alice, at: t0 + .seconds(120))

        // Hold back a packet bob sent under the old keypair.
        let late = pair.packet(from: .bob, payload: [0x1A])
        let lateOutputs = try pair.bob.send(late, to: pair.key(.alice), at: t0 + .seconds(120))

        let now = t0 + .seconds(121)
        let rekey = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now)
        #expect(rekey.messageTypes == [4, 1])
        try pair.deliver(rekey, from: .alice, at: now)

        let newIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)
        #expect(newIndex != oldIndex)
        #expect(pair.keypairs(of: .alice)?.previous?.localIndex == oldIndex)

        // bob's new packet arrives with the new index.
        let fresh = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(fresh.datagrams.first?.uint32(at: 4) == newIndex)
        try pair.deliver(fresh, from: .bob, at: now)

        // Late packets under the old keypair (previous) are also accepted.
        #expect(lateOutputs.datagrams.first?.uint32(at: 4) == oldIndex)
        #expect(try pair.deliver(lateOutputs, from: .bob, at: now)[.alice] == [late])
    }

    @Test("The responder only rekeys at the peer's initiative and sends with current until next is confirmed")
    func responderSideRekey() throws {
        var pair = Pair()
        try pair.establish()
        let oldAliceIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)

        // The responder bob sends no initiation even after 120 seconds.
        let now = t0 + .seconds(121)
        let bobSend = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(bobSend.messageTypes == [4])
        try pair.deliver(bobSend, from: .bob, at: now)

        // alice rekeys. Deliver only the initiation to bob and hold back the response.
        let rekey = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now)
        #expect(rekey.messageTypes == [4, 1])
        _ = try pair.bob.receive(rekey.datagrams[0], at: now)
        let response = try pair.bob.receive(rekey.datagrams[1], at: now)
        #expect(response.messageTypes == [2])
        #expect(pair.keypairs(of: .bob)?.next != nil)

        // Before confirmation, bob sends with its old current (receiver = alice's old index).
        let beforeConfirm = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(beforeConfirm.datagrams.first?.uint32(at: 4) == oldAliceIndex)

        // When the response reaches alice, alice's keepalive confirms bob's next.
        try pair.deliver(response, from: .bob, at: now)
        let newAliceIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)
        #expect(newAliceIndex != oldAliceIndex)
        #expect(pair.keypairs(of: .bob)?.next == nil)

        let afterConfirm = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(afterConfirm.datagrams.first?.uint32(at: 4) == newAliceIndex)
        // A packet sent before confirmation is still accepted by alice's previous.
        try pair.deliver(beforeConfirm + afterConfirm, from: .bob, at: now)
    }

    @Test("A keypair older than 180 seconds is unusable for receiving or sending")
    func rejectAfter180Seconds() throws {
        var pair = Pair()
        try pair.establish()
        let old = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .seconds(1))

        #expect(throws: WireGuardError.noSession) { try pair.alice.receive(old.datagrams[0], at: t0 + .seconds(181)) }

        // On send, queue the packet and start a new handshake.
        let packet = pair.packet(from: .alice)
        let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0 + .seconds(181))
        #expect(outputs.messageTypes == [1])
        #expect(try pair.deliver(outputs, from: .alice, at: t0 + .seconds(181))[.bob] == [packet])
    }

    @Test("The initiator rekeys once after 165 seconds even if it only receives")
    func lastMinuteRekeyOnReceive() throws {
        var pair = Pair()
        try pair.establish()
        let now = t0 + .seconds(166)
        let bobSend = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        let reply = try pair.alice.receive(bobSend.datagrams[0], at: now)
        #expect(reply.messageTypes == [1])
        // Sends only once.
        let second = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now + .seconds(6))
        #expect(try pair.alice.receive(second.datagrams[0], at: now + .seconds(6)).messageTypes == [])
    }

    @Test("With no reply, it retries with a new initiation every 5 seconds plus jitter and gives up after 20 attempts")
    func retransmitAndGiveUp() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        var initiations = first.datagrams
        var lastSent = t0

        while let deadline = pair.alice.nextDeadline, deadline < t0 + .seconds(300) {
            let outputs = pair.alice.advance(to: deadline)
            guard !outputs.isEmpty else { break }
            #expect(outputs.messageTypes == [1])
            #expect(deadline - lastSent >= .seconds(5))
            #expect(deadline - lastSent < .seconds(5) + .milliseconds(334))
            initiations += outputs.datagrams
            lastSent = deadline
        }
        #expect(initiations.count == 20)
        // Each retry has a new sender index, ephemeral key, and timestamp ciphertext.
        #expect(Set(initiations.map { $0.uint32(at: 4) }).count == 20)
        #expect(Set(initiations.map { Array($0[8..<40]) }).count == 20)

        // Giving up discards the queue and leaves only key material removal after 540 seconds.
        let peer = try #require(pair.alice.peers[pair.key(.bob)])
        #expect(peer.staged.isEmpty)
        let giveUp = try #require(pair.alice.nextDeadline)
        #expect(giveUp > lastSent + .seconds(5) + .seconds(534))
        _ = pair.alice.advance(to: giveUp)
        #expect(pair.alice.peers[pair.key(.bob)]?.pendingHandshake == nil)
        #expect(pair.alice.indexTable.isEmpty)
        #expect(pair.alice.nextDeadline == nil)
    }

    @Test("Deletes key material after 540 seconds without a new key")
    func zeroKeyMaterialAfter540Seconds() throws {
        var pair = Pair()
        try pair.establish()
        let pending = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1))

        // For bob, only the 540-second timer remains after the 10-second keepalive goes out.
        let keepalive = pair.bob.advance(to: t0 + .seconds(10))
        #expect(keepalive.messageTypes == [4])
        #expect(pair.bob.nextDeadline == t0 + .seconds(540))
        let beforeExpiry = pair.bob.advance(to: t0 + .seconds(539))
        #expect(beforeExpiry.isEmpty)
        let atExpiry = pair.bob.advance(to: t0 + .seconds(540))
        #expect(atExpiry.isEmpty)

        let keypairs = try #require(pair.keypairs(of: .bob))
        #expect(keypairs.previous == nil && keypairs.current == nil && keypairs.next == nil)
        #expect(pair.bob.indexTable.isEmpty)
        #expect(pair.bob.nextDeadline == nil)
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive(pending.datagrams[0], at: t0 + .seconds(540)) }

        // A new handshake reconnects even after deletion.
        let packet = pair.packet(from: .alice)
        let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0 + .seconds(600))
        #expect(outputs.messageTypes == [1])
        #expect(try pair.deliver(outputs, from: .alice, at: t0 + .seconds(600))[.bob] == [packet])
    }

    @Test("removePeer clears the peer and its indices")
    func removePeer() throws {
        var pair = Pair()
        try pair.establish()
        let pending = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1))
        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.peers.isEmpty)
        #expect(pair.bob.indexTable.isEmpty)
        #expect(pair.bob.nextDeadline == nil)
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive(pending.datagrams[0], at: t0 + .seconds(1)) }

        // An initiation from an unknown peer also yields unknownPeer.
        var fresh = Pair()
        fresh.bob.removePeer(fresh.key(.alice))
        let initiation = try fresh.alice.send(fresh.packet(from: .alice), to: fresh.key(.bob), at: t0)
        #expect(throws: WireGuardError.unknownPeer) { try fresh.bob.receive(initiation.datagrams[0], at: t0) }
    }

    @Test("A responder that sent a response waits at least 5 seconds before sending an initiation")
    func rekeyTimeoutSuppression() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(initiation.datagrams[0], at: t0)
        #expect(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .milliseconds(4999)).isEmpty)
        #expect(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .seconds(5)).messageTypes == [1])
    }
}
