// Contract test 4 covers loss and tampering.
// Recovery after losing a response, stale responses leaving newer handshakes intact, tampered messages leaving state intact,
// and rejection of source addresses outside AllowedIPs.

import CryptoKit
import Testing

@testable import SwiftailWireGuard

@Suite("Loss and tampering")
struct LossAndTamperTests {
    @Test("A retry initiation recovers from a lost response")
    func recoversFromLostResponse() throws {
        var pair = Pair()
        let packet = pair.packet(from: .alice)
        let first = try pair.alice.send(packet, to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0) // Drop the response.

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(retry.messageTypes == [1])
        #expect(try pair.deliver(retry, from: .alice, at: retryAt)[.bob] == [packet])
    }

    @Test("Stale responses leave new handshakes intact, and previously processed responses are rejected")
    func staleResponseIsIgnored() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        let staleResponse = try pair.bob.receive(first.datagrams[0], at: t0)

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        let freshResponse = try pair.bob.receive(retry.datagrams[0], at: retryAt)

        // The old response's receiver index was discarded when the new initiation was made.
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.receive(staleResponse.datagrams[0], at: retryAt) }
        #expect(pair.alice.peers[pair.key(.bob)]?.pendingHandshake?.localIndex == retry.datagrams[0].uint32(at: 4))

        let confirm = try pair.alice.receive(freshResponse.datagrams[0], at: retryAt)
        #expect(confirm.messageTypes == [4])
        try pair.deliver(confirm, from: .alice, at: retryAt)

        // Replaying the same response is rejected. Its index has already been reassigned to the keypair.
        #expect(throws: WireGuardError.replayed) { try pair.alice.receive(freshResponse.datagrams[0], at: retryAt) }
    }

    @Test("Rejects a replay of the same initiation and a second initiation within 20 ms")
    func initiationReplayAndFlood() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }

        // alice makes a new initiation after 6 seconds. bob rejects it if it consumed an initiation within the preceding 20 ms.
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        var flooded = pair
        flooded.bob.peers[pair.key(.alice)]?.lastInitiationConsumed = retryAt - .milliseconds(20)
        #expect(throws: WireGuardError.replayed) { try flooded.bob.receive(retry.datagrams[0], at: retryAt) }
        #expect(try pair.bob.receive(retry.datagrams[0], at: retryAt).messageTypes == [2])
    }

    @Test("Removing and restoring a peer still rejects a replay of the old initiation and accepts a newer one")
    func removedPeerKeepsLastTimestamp() throws {
        var pair = Pair()
        let allowedIPs = try #require(pair.bob.peers[pair.key(.alice)]?.allowedIPs)
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)

        // A peer with the same key leaves the netmap and returns.
        pair.bob.removePeer(pair.key(.alice))
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }
        pair.bob.addPeer(pair.key(.alice), allowedIPs: allowedIPs)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(try pair.bob.receive(retry.datagrams[0], at: retryAt).messageTypes == [2])
    }

    @Test("Remembers up to 1,024 removed peers' timestamps. For equal timestamps, it evicts the earliest removal first. Restoring a peer removes it from the table")
    func retiredTimestampsAreBounded() throws {
        var pair = Pair()
        let allowedIPs = try #require(pair.bob.peers[pair.key(.alice)]?.allowedIPs)
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)
        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.retiredTimestamps.count == 1)

        // Restoring a peer takes it out of the table. Removing a peer that has never handshaken leaves no entry.
        pair.bob.addPeer(pair.key(.alice), allowedIPs: allowedIPs)
        #expect(pair.bob.retiredTimestamps.isEmpty)
        let silent = PublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
        pair.bob.addPeer(silent, allowedIPs: [])
        pair.bob.removePeer(silent)
        #expect(pair.bob.retiredTimestamps.isEmpty)

        // After removing alice and then 1,024 other peers, alice's entry is evicted.
        pair.bob.removePeer(pair.key(.alice))
        let stamp = try #require(pair.bob.retiredTimestamps.first?.timestamp)
        for _ in 0..<Constants.maxRetiredTimestamps {
            let key = PublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
            pair.bob.addPeer(key, allowedIPs: [])
            pair.bob.peers[key]?.lastAcceptedTimestamp = stamp
            pair.bob.removePeer(key)
        }
        #expect(pair.bob.retiredTimestamps.count == Constants.maxRetiredTimestamps)
        #expect(!pair.bob.retiredTimestamps.contains { $0.peer == pair.key(.alice) })
    }

    @Test("A full table evicts the earliest removal first. A far-future timestamp set by the other side cannot hold a slot")
    func retiredTimestampsForgetFirstRetired() throws {
        var pair = Pair()
        let allowedIPs = try #require(pair.bob.peers[pair.key(.alice)]?.allowedIPs)
        // Fill the table with peers that used far-future timestamps.
        for second in 0..<Int64(Constants.maxRetiredTimestamps) {
            let key = PublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
            pair.bob.addPeer(key, allowedIPs: [])
            pair.bob.peers[key]?.lastAcceptedTimestamp = TAI64N(sinceUnixEpoch: .seconds(4_000_000_000 + second))
            pair.bob.removePeer(key)
        }
        #expect(pair.bob.retiredTimestamps.count == Constants.maxRetiredTimestamps)

        // The record of a normal peer that handshakes and is then removed stays in the table. The earliest removal is evicted.
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)
        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.retiredTimestamps.count == Constants.maxRetiredTimestamps)
        #expect(pair.bob.retiredTimestamps.first?.timestamp == TAI64N(sinceUnixEpoch: .seconds(4_000_000_001)))

        pair.bob.addPeer(pair.key(.alice), allowedIPs: allowedIPs)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }
    }

    @Test("Rejects a tampered initiation and preserves state")
    func tamperedInitiation() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        // Skip mac2 (132..<148) because it is checked only under load. wireguard-go behaves the same way.
        for offset in 0..<132 {
            var tampered = initiation
            tampered[offset] ^= 0x01
            #expect(throws: WireGuardError.self) { try pair.bob.receive(tampered, at: t0) }
        }
        #expect(pair.bob.nextDeadline == nil)
        #expect(pair.bob.indexTable.isEmpty)
        // The original initiation is still accepted because its timestamp has not been consumed.
        #expect(try pair.bob.receive(initiation, at: t0).messageTypes == [2])
    }

    @Test("Rejects a tampered response and preserves state")
    func tamperedResponse() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        let response = try pair.bob.receive(initiation, at: t0).datagrams[0]
        let deadline = pair.alice.nextDeadline
        for offset in 0..<76 {
            var tampered = response
            tampered[offset] ^= 0x80
            #expect(throws: WireGuardError.self) { try pair.alice.receive(tampered, at: t0) }
        }
        #expect(pair.alice.nextDeadline == deadline)
        #expect(pair.keypairs(of: .alice)?.current == nil)
        #expect(try pair.alice.receive(response, at: t0).messageTypes == [4])
    }

    @Test("Tampered transport leaves the replay window and next intact")
    func tamperedTransport() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        let transport = try pair.alice.receive(response.datagrams[0], at: t0).datagrams[0]
        let deadline = pair.bob.nextDeadline

        for offset in 0..<transport.count {
            var tampered = transport
            tampered[offset] ^= 0x04
            #expect(throws: WireGuardError.self) { try pair.bob.receive(tampered, at: t0) }
        }
        // Truncated transport is also rejected.
        #expect(throws: WireGuardError.self) { try pair.bob.receive(Array(transport.dropLast()), at: t0) }
        #expect(pair.keypairs(of: .bob)?.next != nil)
        #expect(pair.bob.nextDeadline == deadline)

        // The original transport is accepted and confirms next. Receiving it again is a replay.
        #expect(try pair.bob.receive(transport, at: t0).count == 1)
        #expect(pair.keypairs(of: .bob)?.current != nil)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(transport, at: t0) }
    }

    @Test("Rejects a source address outside AllowedIPs but counts the packet as authenticated")
    func disallowedSource() throws {
        var pair = Pair()
        try pair.establish()
        let spoofed = ipv4Packet(source: "100.64.0.9", destination: Pair.bobAddress, payload: [1])
        let outputs = try pair.alice.send(spoofed, to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.bob.receive(outputs.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])
        // The replay window records it.
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(outputs.datagrams[0], at: t0 + .seconds(1)) }

        // IPv6 source addresses undergo the same check.
        let v6 = ipv6Packet(source: "fd7a:115c:a1e0::1", destination: "fd7a:115c:a1e0::2", payload: [1, 2])
        let v6Outputs = try pair.alice.send(v6, to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.bob.receive(v6Outputs.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])

        // Plaintext that is not an IP packet yields malformed.
        let garbage = try pair.alice.send([0x50, 1, 2, 3], to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.bob.receive(garbage.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.malformed, from: pair.key(.alice))])

        // Valid packets still get through.
        let good = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(2))
        #expect(try pair.deliver(good, from: .alice, at: t0 + .seconds(2))[.bob]?.count == 1)
    }

    @Test("A packet from outside AllowedIPs can confirm the responder's next, matching wireguard-go")
    func confirmationBySpoofedPacket() throws {
        var pair = Pair()
        let spoofed = ipv4Packet(source: "100.64.0.9", destination: Pair.bobAddress, payload: [1])
        let initiation = try pair.alice.send(spoofed, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        let transport = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(try pair.bob.receive(transport.datagrams[0], at: t0) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])
        #expect(pair.keypairs(of: .bob)?.current != nil)
        #expect(pair.keypairs(of: .bob)?.next == nil)
    }

    // Regression test for a bug found in the cross-review (GPT-6.1 Sol). Packets that fail the IP check still complete session processing.
    @Test("The responder flushes the queue as soon as a packet from outside AllowedIPs confirms next")
    func stagedPacketsFlushOnRejectedConfirmation() throws {
        var pair = Pair()
        let spoofed = ipv4Packet(source: "100.64.0.9", destination: Pair.bobAddress, payload: [1])
        let initiation = try pair.alice.send(spoofed, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        // Before confirmation, the responder cannot send with the new key, so it queues the packet.
        #expect(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0).isEmpty)
        let transport = try pair.alice.receive(response.datagrams[0], at: t0)

        let outputs = try pair.bob.receive(transport.datagrams[0], at: t0)
        #expect(outputs.messageTypes == [4])
        #expect(outputs.last == .rejectedIPPacket(.disallowedSource, from: pair.key(.alice)))
        #expect(try pair.alice.receive(outputs.datagrams[0], at: t0).ipPackets.count == 1)
    }

    @Test("After 165 seconds, the initiator starts a rekey even on receiving a packet from outside AllowedIPs")
    func rekeyOnRejectedPacket() throws {
        var pair = Pair()
        try pair.establish()
        let late = t0 + .seconds(166)
        let spoofed = ipv4Packet(source: "100.64.0.9", destination: Pair.aliceAddress, payload: [1])
        let transport = try pair.bob.send(spoofed, to: pair.key(.alice), at: late)
        let outputs = try pair.alice.receive(transport.datagrams[0], at: late)
        #expect(outputs.messageTypes == [1])
        #expect(outputs.last == .rejectedIPPacket(.disallowedSource, from: pair.key(.bob)))
    }
}

@Suite("Parsing received IP packets")
struct InboundIPPacketTests {
    @Test("IPv4 strips padding using total length")
    func ipv4Padding() throws {
        let packet = ipv4Packet(source: "100.64.0.1", destination: "100.64.0.2", payload: [1, 2, 3])
        let parsed = try #require(InboundIPPacket(plaintext: packet + [0, 0, 0, 0, 0]))
        #expect(parsed.bytes == packet)
        #expect(parsed.source.description == "100.64.0.1")
    }

    @Test("IPv6 strips padding using payload length + 40")
    func ipv6Padding() throws {
        let packet = ipv6Packet(source: "fd7a:115c:a1e0::1", destination: "fd7a:115c:a1e0::2", payload: [9])
        let parsed = try #require(InboundIPPacket(plaintext: packet + [0, 0, 0, 0, 0, 0, 0]))
        #expect(parsed.bytes == packet)
        #expect(parsed.source.description == "fd7a:115c:a1e0::1")
    }

    @Test("Yields nil if the length field points past the plaintext or is shorter than the header")
    func invalidLengths() {
        var v4 = ipv4Packet(source: "100.64.0.1", destination: "100.64.0.2", payload: [])
        #expect(InboundIPPacket(plaintext: v4) != nil)
        v4[3] = 21 // total length > actual length
        #expect(InboundIPPacket(plaintext: v4) == nil)
        v4[3] = 19 // total length < header length
        #expect(InboundIPPacket(plaintext: v4) == nil)
        #expect(InboundIPPacket(plaintext: Array(v4.prefix(19))) == nil)

        // payload length 0xFFFF + 40 overflows UInt16, but here it is rejected for exceeding the length.
        var v6 = ipv6Packet(source: "::1", destination: "::2", payload: [])
        v6[4] = 0xFF
        v6[5] = 0xFF
        #expect(InboundIPPacket(plaintext: v6) == nil)
        #expect(InboundIPPacket(plaintext: Array(v6.prefix(39))) == nil)

        #expect(InboundIPPacket(plaintext: []) == nil)
        #expect(InboundIPPacket(plaintext: [0x50] + [UInt8](repeating: 0, count: 60)) == nil)
    }
}
