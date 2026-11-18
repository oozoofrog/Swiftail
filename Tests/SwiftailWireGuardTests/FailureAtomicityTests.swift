// The "Errors and state" contract leaves peer state (sessions, counters, replay windows, timers, and the index table) intact when `send` or `receive`
// throws. Because peers are updated in place in the table, compare the entire state to check that a throwing path leaves no partial updates.

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailWireGuard

/// A comparable snapshot of the device's peer state. It contains only hashes of key material.
private struct Snapshot: Equatable {
    struct Slot: Equatable {
        var localIndex: UInt32
        var remoteIndex: UInt32
        var sendNonce: UInt64
        var created: ContinuousClock.Instant
        var replayFilter: Int
    }

    struct PeerState: Equatable {
        var previous: Slot?
        var current: Slot?
        var next: Slot?
        var pendingIndex: UInt32?
        var staged: [[UInt8]]
        var timers: [ContinuousClock.Instant?]
        var handshakeAttempts: Int
        var needAnotherKeepalive: Bool
        var sentLastMinuteHandshake: Bool
        var lastAcceptedTimestamp: TAI64N?
        var lastInitiationConsumed: ContinuousClock.Instant?
        var lastSentHandshake: ContinuousClock.Instant?
        var tabledIndexSlots: Peer.IndexSlots
        var cookieGenerator: Int
    }

    var peers: [PublicKey: PeerState]
    var indexTable: [UInt32: PublicKey]
    var nextDeadline: ContinuousClock.Instant?

    init(_ device: WireGuardDevice) {
        func slot(_ keypair: Keypair?) -> Slot? {
            keypair.map {
                Slot(
                    localIndex: $0.localIndex,
                    remoteIndex: $0.remoteIndex,
                    sendNonce: $0.sendNonce,
                    created: $0.created,
                    replayFilter: String(reflecting: $0.replayFilter).hashValue
                )
            }
        }
        peers = device.peers.mapValues { peer in
            PeerState(
                previous: slot(peer.keypairs.previous),
                current: slot(peer.keypairs.current),
                next: slot(peer.keypairs.next),
                pendingIndex: peer.pendingHandshake?.localIndex,
                staged: peer.staged,
                timers: PeerTimers.Kind.allCases.map { peer.timers[$0] },
                handshakeAttempts: peer.timers.handshakeAttempts,
                needAnotherKeepalive: peer.timers.needAnotherKeepalive,
                sentLastMinuteHandshake: peer.timers.sentLastMinuteHandshake,
                lastAcceptedTimestamp: peer.lastAcceptedTimestamp,
                lastInitiationConsumed: peer.lastInitiationConsumed,
                lastSentHandshake: peer.lastSentHandshake,
                tabledIndexSlots: peer.tabledIndexSlots,
                cookieGenerator: String(reflecting: peer.cookieGenerator).hashValue
            )
        }
        indexTable = device.indexTable
        nextDeadline = device.nextDeadline
    }
}

/// Recomputes mac1 for a handshake message (mac2 is 0). The message passes mac1 validation and is rejected at DH or AEAD authentication.
private func remacked(_ message: [UInt8], for receiver: PublicKey) -> [UInt8] {
    let head = Array(message.dropLast(32))
    return head + MAC.authenticate(head, key: MAC.mac1Key(for: receiver)) + [UInt8](repeating: 0, count: 16)
}

/// Checks that the index table matches the indices held by peers and that the slot each peer registered in the table still matches its current slot.
private func expectIndexTableConsistent(_ device: WireGuardDevice, sourceLocation: SourceLocation = #_sourceLocation) {
    var expected: [UInt32: PublicKey] = [:]
    for (key, peer) in device.peers {
        #expect(peer.tabledIndexSlots == peer.indexSlots, sourceLocation: sourceLocation)
        for index in peer.localIndices { expected[index] = key }
    }
    #expect(device.indexTable == expected, sourceLocation: sourceLocation)
}

@Suite("Failures preserve state")
struct FailureAtomicityTests {
    /// Checks that the input produces an error and leaves the device's peer state intact.
    private func expectRejected(
        _ device: inout WireGuardDevice,
        _ datagram: [UInt8],
        at now: ContinuousClock.Instant,
        _ expected: WireGuardError? = nil,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let before = Snapshot(device)
        do {
            _ = try device.receive(datagram, at: now)
            Issue.record("Accepted a datagram that should have been rejected", sourceLocation: sourceLocation)
        } catch {
            if let expected { #expect(error == expected, sourceLocation: sourceLocation) }
        }
        #expect(Snapshot(device) == before, sourceLocation: sourceLocation)
    }

    @Test("Transport after session establishment covers tampering, replay, unknown indices, and expiration")
    func rejectedTransports() throws {
        var pair = Pair()
        try pair.establish()
        // Start after the session's replay window and timers have advanced a bit.
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1)).datagrams[0]
        #expect(try pair.bob.receive(first, at: t0 + .seconds(1)).ipPackets.count == 1)
        let later = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(2)).datagrams[0]

        // Tampering with any byte causes rejection and leaves state intact.
        for offset in 0..<later.count {
            var tampered = later
            tampered[offset] ^= 0x01
            expectRejected(&pair.bob, tampered, at: t0 + .seconds(2))
        }
        // Replay of a counter already received.
        expectRejected(&pair.bob, first, at: t0 + .seconds(2))
        // Unknown receiver index.
        var unknown = later
        unknown[4] ^= 0xFF
        expectRejected(&pair.bob, unknown, at: t0 + .seconds(2))
        // Short input.
        expectRejected(&pair.bob, Array(later.prefix(31)), at: t0 + .seconds(2))
        // Valid transport after the keypair expires (past `rejectAfterTime`).
        expectRejected(&pair.bob, later, at: t0 + .seconds(200))

        // A rejection does not prevent a subsequent valid receive.
        #expect(try pair.bob.receive(later, at: t0 + .seconds(2)).ipPackets.count == 1)
    }

    @Test("Initiation, response, and cookie reply during the handshake cover tampering, replay, and unknown indices")
    func rejectedHandshakeMessages() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]

        // mac2 (132..<148) is checked only under load.
        for offset in 0..<132 {
            var tampered = initiation
            tampered[offset] ^= 0x01
            expectRejected(&pair.bob, tampered, at: t0)
        }
        let response = try pair.bob.receive(initiation, at: t0).datagrams[0]
        // Replay of an already accepted initiation (timestamp) and replay after a short interval (flood).
        expectRejected(&pair.bob, initiation, at: t0 + .seconds(1), .replayed)
        expectRejected(&pair.bob, initiation, at: t0 + .milliseconds(5), .replayed)

        for offset in 0..<60 {
            var tampered = response
            tampered[offset] ^= 0x01
            expectRejected(&pair.alice, tampered, at: t0)
        }
        // Response and cookie reply with an unknown receiver.
        var unknownResponse = response
        unknownResponse[8] ^= 0xFF
        expectRejected(&pair.alice, unknownResponse, at: t0)
        let garbageCookieReply = [3, 0, 0, 0] + (try #require(pair.alice.peers.values.first?.pendingHandshake?.localIndex)).littleEndianBytes
            + [UInt8](repeating: 7, count: 24 + 32)
        expectRejected(&pair.alice, garbageCookieReply, at: t0, .authenticationFailed)

        // Accepting the response establishes the session. Replaying it is rejected and leaves state intact.
        let transport = try pair.alice.receive(response, at: t0).datagrams[0]
        expectRejected(&pair.alice, response, at: t0 + .seconds(1), .replayed)
        // Tampered transport for an unconfirmed next keypair leaves it in next.
        var tampered = transport
        tampered[tampered.count - 1] ^= 0x01
        expectRejected(&pair.bob, tampered, at: t0)
        #expect(try pair.bob.receive(transport, at: t0).count == 1)
    }

    @Test("An initiation for a responder awaiting a response covers tampering with only a valid mac1 and a new initiation within 20 ms")
    func rejectedInitiationsWhileHandshakePending() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        // The retry timer generates another initiation with a newer timestamp.
        let retransmitAt = try #require(pair.alice.nextDeadline)
        let second = try #require(pair.alice.advance(to: retransmitAt).datagrams.first)
        // bob has also sent an initiation and is waiting for a response.
        _ = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0)
        #expect(pair.bob.peers.values.first?.pendingHandshake != nil)

        // A valid mac1 lets processing reach static and timestamp decryption, where it is rejected. The handshake in progress stays intact.
        for offset in stride(from: 8, to: 116, by: 6) {
            var tampered = first
            tampered[offset] ^= 0x01
            expectRejected(&pair.bob, remacked(tampered, for: pair.key(.bob)), at: t0, .authenticationFailed)
        }

        #expect(try pair.bob.receive(first, at: t0).datagrams.count == 1)
        // The newer timestamp passes the replay check, but the interval is within 20 ms, so the initiation is rejected as a flood.
        expectRejected(&pair.bob, second, at: t0 + .milliseconds(10), .replayed)
        #expect(try pair.bob.receive(second, at: t0 + .milliseconds(30)).datagrams.count == 1)
    }

    @Test("A response for an initiator with a timer waiting for a reply covers tampering with only a valid mac1")
    func rejectedResponseWhileAwaitingReply() throws {
        var pair = Pair()
        try pair.establish()
        // Sending after the rekey time in an established session sends a new initiation along with the data.
        let rekeyAt = t0 + Constants.rekeyAfterTime + .seconds(1)
        let outputs = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: rekeyAt).datagrams
        let initiation = try #require(outputs.first { $0.first == 1 })
        let response = try pair.bob.receive(initiation, at: rekeyAt).datagrams[0]
        let alicePeer = try #require(pair.alice.peers.values.first)
        #expect(alicePeer.pendingHandshake != nil)
        #expect(alicePeer.timers[.newHandshake] != nil)

        for offset in stride(from: 12, to: 60, by: 4) {
            var tampered = response
            tampered[offset] ^= 0x01
            expectRejected(&pair.alice, remacked(tampered, for: pair.key(.alice)), at: rekeyAt, .authenticationFailed)
        }
        #expect(try pair.alice.receive(response, at: rekeyAt).datagrams.count == 1)
    }

    @Test("After repeated rekeys, the index table matches peer indices and tampered transport for previous leaves state intact")
    func indexTableFollowsRotation() throws {
        var pair = Pair()
        try pair.establish()
        expectIndexTableConsistent(pair.alice)
        expectIndexTableConsistent(pair.bob)

        var now = t0
        var old: [UInt8] = []
        for _ in 0..<4 {
            // Transport encrypted with the pre-rekey keypair and held back from delivery.
            old = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now + .seconds(100)).datagrams[0]
            now += Constants.rekeyAfterTime + .seconds(1)
            try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now), from: .alice, at: now)
            expectIndexTableConsistent(pair.alice)
            expectIndexTableConsistent(pair.bob)
        }

        // That keypair is now in bob's previous slot.
        #expect(pair.bob.peers.values.first?.keypairs.previous != nil)
        var tampered = old
        tampered[tampered.count - 1] ^= 0x01
        expectRejected(&pair.bob, tampered, at: now, .authenticationFailed)
        #expect(try pair.bob.receive(old, at: now).ipPackets.count == 1)

        // The table still matches after the timer clears the session.
        _ = pair.alice.advance(to: now + .seconds(3600))
        _ = pair.bob.advance(to: now + .seconds(3600))
        expectIndexTableConsistent(pair.alice)
        expectIndexTableConsistent(pair.bob)

        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.indexTable.isEmpty)
    }

    @Test("send throws for an empty packet, a packet that is too large, or an unknown peer")
    func rejectedSends() throws {
        var pair = Pair()
        try pair.establish()
        let before = Snapshot(pair.alice)

        #expect(throws: WireGuardError.malformed) { try pair.alice.send([], to: pair.key(.bob), at: t0 + .seconds(1)) }
        let tooLarge = [UInt8](repeating: 0x45, count: Constants.maxContentSize + 1)
        #expect(throws: WireGuardError.packetTooLarge) { try pair.alice.send(tooLarge, to: pair.key(.bob), at: t0 + .seconds(1)) }
        let stranger = WireGuardDevice(privateKey: .init(), now: t0, wallClock: Date(timeIntervalSince1970: 1_800_000_000)).publicKey
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.send(pair.packet(from: .alice), to: stranger, at: t0 + .seconds(1)) }

        #expect(Snapshot(pair.alice) == before)
    }
}
