// A priority message is plaintext sent once before the queue each time a session key is established (the Tailscale fork of wireguard-go,
// `SendPriorityMessage` and its two call sites in `device/receive.go`). Tailscale uses it for TSMP disco key advertisements.

import Foundation
import Testing

import SwiftailBase

@testable import SwiftailWireGuard

@Suite("priority message")
struct PriorityMessageTests {
    /// Creates two devices, alice and bob, configured to send priority messages to each other.
    private static func pair() throws -> Pair {
        var pair = Pair()
        try pair.alice.setPriorityMessage(pair.packet(from: .alice, payload: Array("alice".utf8)), for: pair.key(.bob))
        try pair.bob.setPriorityMessage(pair.packet(from: .bob, payload: Array("bob".utf8)), for: pair.key(.alice))
        return pair
    }

    @Test("The initiator sends the priority message before the queue on receiving the response, and the responder sends it on receiving the first transport")
    func sentAtEstablishmentBeforeStagedPackets() throws {
        var pair = try Self.pair()
        let first = pair.packet(from: .alice)
        let initiation = try pair.alice.send(first, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        // The responder is still awaiting confirmation and sends nothing.
        #expect(response.messageTypes == [2])

        // The initiator sends the priority message followed by queued packets.
        let transports = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(transports.messageTypes == [4, 4])
        let priority = try pair.bob.receive(transports.datagrams[0], at: t0)
        // When the first transport (the initiator's priority message) confirms the session, the responder sends its own priority message first
        // and delivers the received packet upward.
        #expect(priority.messageTypes == [4])
        #expect(priority.ipPackets == [pair.packet(from: .alice, payload: Array("alice".utf8))])
        #expect(try pair.bob.receive(transports.datagrams[1], at: t0).ipPackets == [first])
        #expect(try pair.alice.receive(priority.datagrams[0], at: t0).ipPackets == [pair.packet(from: .bob, payload: Array("bob".utf8))])
    }

    @Test("With an empty queue, the initiator also sends a keepalive after the priority message")
    func initiatorStillSendsKeepalive() throws {
        var pair = try Self.pair()
        // alice handshakes without having received any data (as if started by the rekey timer).
        let outputs = try #require(pair.alice.edit(pair.key(.bob)) { device, peer in
            device.sendHandshakeInitiation(&peer, isRetry: false, at: t0)
        })
        let response = try pair.bob.receive(outputs.datagrams[0], at: t0)
        let transports = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(transports.messageTypes == [4, 4])
        // The second datagram is a keepalive (empty plaintext, 16-byte header + 16-byte tag).
        #expect(transports.datagrams[1].count == 32)
    }

    @Test("Sends once per session and sends again when rekeying establishes a new session")
    func oncePerSession() throws {
        var pair = try Self.pair()
        var log: [Pair.Side: [[UInt8]]] = [:]
        func record(_ delivered: [Pair.Side: [[UInt8]]]) {
            for (side, packets) in delivered { log[side, default: []] += packets }
        }
        let alicePriority = pair.packet(from: .alice, payload: Array("alice".utf8))
        let bobPriority = pair.packet(from: .bob, payload: Array("bob".utf8))

        record(try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0), from: .alice, at: t0))
        #expect(log[.bob]?.filter { $0 == alicePriority }.count == 1)
        #expect(log[.alice]?.filter { $0 == bobPriority }.count == 1)

        // Data in the same session does not carry it.
        let later = t0 + .seconds(1)
        record(try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: later), from: .alice, at: later))
        record(try pair.deliver(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: later), from: .bob, at: later))
        #expect(log[.bob]?.filter { $0 == alicePriority }.count == 1)
        #expect(log[.alice]?.filter { $0 == bobPriority }.count == 1)

        // If the initiator sends after 120 seconds have elapsed, rekeying begins and both sides send again in the new session.
        let rekey = t0 + .seconds(121)
        record(try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: rekey), from: .alice, at: rekey))
        #expect(log[.bob]?.filter { $0 == alicePriority }.count == 2)
        #expect(log[.alice]?.filter { $0 == bobPriority }.count == 2)
    }

    @Test("An unset or cleared priority message is never sent")
    func absentOrCleared() throws {
        var pair = try Self.pair()
        try pair.alice.setPriorityMessage(nil, for: pair.key(.bob))
        let first = pair.packet(from: .alice)
        let initiation = try pair.alice.send(first, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        let transports = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(transports.messageTypes == [4])
        let confirmed = try pair.bob.receive(transports.datagrams[0], at: t0)
        // bob still has a message configured and sends it on confirmation.
        #expect(confirmed.messageTypes == [4])
        #expect(confirmed.ipPackets == [first])
    }

    @Test("A priority message counts as a data send and starts a new handshake timer if there is no reply")
    func countsAsData() throws {
        var pair = try Self.pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        _ = try pair.alice.receive(response.datagrams[0], at: t0)
        let timers = try #require(pair.alice.peers[pair.key(.bob)]).timers
        #expect(timers[.newHandshake] != nil)
    }

    @Test("Input validation covers an empty packet, more than 512 bytes, and an unknown peer")
    func validation() throws {
        var pair = Pair()
        #expect(throws: WireGuardError.malformed) { try pair.alice.setPriorityMessage([], for: pair.key(.bob)) }
        #expect(throws: WireGuardError.packetTooLarge) {
            try pair.alice.setPriorityMessage([UInt8](repeating: 0x45, count: 513), for: pair.key(.bob))
        }
        try pair.alice.setPriorityMessage([UInt8](repeating: 0x45, count: 512), for: pair.key(.bob))
        let stranger = WireGuardDevice(privateKey: .init(), now: t0, wallClock: Date()).publicKey
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.setPriorityMessage([0x45], for: stranger) }
    }
}
