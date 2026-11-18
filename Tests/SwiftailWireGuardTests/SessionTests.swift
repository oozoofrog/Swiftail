// Contract test 1 connects two Swift devices in memory.
// Covers both handshake roles, bidirectional data, keepalive, and queue flushing.

import CryptoKit
import Foundation
import Testing

import SwiftailBase

@testable import SwiftailWireGuard

@Suite("Session handshake and data")
struct SessionTests {
    @Test("Bidirectional data after the handshake", arguments: [Pair.Side.alice, .bob])
    func handshakeAndData(initiator: Pair.Side) throws {
        var pair = Pair()
        let responder = initiator.other
        let first = pair.packet(from: initiator)

        // Without a session, only an initiation goes out.
        let initiation = try pair[initiator].send(first, to: pair.key(responder), at: t0)
        #expect(initiation.messageTypes == [1])
        #expect(initiation.datagrams.first?.count == Initiation.size)

        // The responder sends a response.
        let response = try pair[responder].receive(initiation.datagrams[0], at: t0)
        #expect(response.messageTypes == [2])
        #expect(response.datagrams.first?.count == Response.size)
        #expect(pair.keypairs(of: responder)?.next != nil)
        #expect(pair.keypairs(of: responder)?.current == nil)

        // The initiator sends queued packets as soon as it receives the response. This packet confirms the responder's next.
        let transport = try pair[initiator].receive(response.datagrams[0], at: t0)
        #expect(transport.messageTypes == [4])
        let delivered = try pair[responder].receive(transport.datagrams[0], at: t0)
        #expect(delivered == [.ipPacket(first, from: pair.key(initiator))])
        #expect(pair.keypairs(of: responder)?.current != nil)
        #expect(pair.keypairs(of: responder)?.next == nil)

        // Both sides now send immediately.
        let reply = pair.packet(from: responder, payload: Array(0..<100))
        let replyOutputs = try pair[responder].send(reply, to: pair.key(initiator), at: t0 + .milliseconds(1))
        #expect(replyOutputs.messageTypes == [4])
        #expect(try pair.deliver(replyOutputs, from: responder, at: t0 + .milliseconds(1))[initiator] == [reply])

        let again = pair.packet(from: initiator, payload: [7])
        let againOutputs = try pair[initiator].send(again, to: pair.key(responder), at: t0 + .milliseconds(2))
        #expect(try pair.deliver(againOutputs, from: initiator, at: t0 + .milliseconds(2))[responder] == [again])
    }

    @Test("Transport is padded to a multiple of 16 bytes and the receiver strips padding using the IP length")
    func padding() throws {
        var pair = Pair()
        try pair.establish()
        for size in [20, 21, 31, 32, 33, 100, 1399, 1419, 1420, 1421, 3000] {
            let packet = pair.packet(from: .alice, payload: [UInt8](repeating: 0x5A, count: size - 20))
            let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0)
            let datagram = try #require(outputs.datagrams.first)
            let plaintextSize = datagram.count - TransportData.minimumSize
            #expect(plaintextSize == packet.count + Keypair.paddingSize(for: packet.count, mtu: 1420))
            #expect(try pair.bob.receive(datagram, at: t0) == [.ipPacket(packet, from: pair.key(.alice))])
        }
        #expect(Keypair.paddingSize(for: 0, mtu: 1420) == 0)
        #expect(Keypair.paddingSize(for: 1, mtu: 1420) == 15)
        #expect(Keypair.paddingSize(for: 1419, mtu: 1420) == 1)
        #expect(Keypair.paddingSize(for: 1421, mtu: 1420) == 15)
    }

    @Test("Sends a keepalive if there is nothing to send for 10 seconds after receiving data")
    func keepalive() throws {
        var pair = Pair()
        try pair.establish()

        // bob received data, which schedules a keepalive for 10 seconds later.
        #expect(pair.bob.nextDeadline == t0 + .seconds(10))
        // alice sent data, which schedules a new handshake for 15 seconds plus jitter later.
        let aliceDeadline = try #require(pair.alice.nextDeadline)
        #expect(aliceDeadline >= t0 + .seconds(15) && aliceDeadline < t0 + .seconds(15) + .milliseconds(334))

        let beforeTimeout = pair.bob.advance(to: t0 + .seconds(9))
        #expect(beforeTimeout.isEmpty)
        let keepalive = pair.bob.advance(to: t0 + .seconds(10))
        #expect(keepalive.messageTypes == [4])
        #expect(keepalive.datagrams.first?.count == TransportData.minimumSize)

        // The keepalive cancels alice's new handshake timer and is never delivered as an IP packet.
        let delivered = try pair.deliver(keepalive, from: .bob, at: t0 + .seconds(10))
        #expect(delivered[.alice] == [])
        #expect(pair.alice.nextDeadline == t0 + .seconds(540))
        let aliceLater = pair.alice.advance(to: t0 + .seconds(20))
        #expect(aliceLater.isEmpty)
    }

    @Test("Omits the keepalive if data was already sent in reply")
    func noKeepaliveAfterReply() throws {
        var pair = Pair()
        try pair.establish()
        let reply = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .seconds(1))
        try pair.deliver(reply, from: .bob, at: t0 + .seconds(1))
        let afterReply = pair.bob.advance(to: t0 + .seconds(10))
        #expect(afterReply.isEmpty)
    }

    @Test("The responder queues packets sent before confirmation and flushes them after confirmation")
    func responderReleasesQueueOnConfirmation() throws {
        var pair = Pair()
        let first = pair.packet(from: .alice)
        let initiation = try pair.alice.send(first, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)

        // bob has no current yet. Less than 5 seconds have passed since sending the response, so it also sends no initiation.
        let early = pair.packet(from: .bob, payload: [1, 2, 3])
        #expect(try pair.bob.send(early, to: pair.key(.alice), at: t0 + .milliseconds(1)).isEmpty)

        let delivered = try pair.deliver(response, from: .bob, at: t0 + .milliseconds(2))
        #expect(delivered[.bob] == [first])
        #expect(delivered[.alice] == [early])
    }

    @Test("The presession queue holds 64 packets and drops the oldest first on overflow")
    func stagedQueueLimit() throws {
        var pair = Pair()
        let packets = (0..<70).map { pair.packet(from: .alice, payload: [UInt8($0)]) }
        var initiation: [WireGuardDevice.Output] = []
        for packet in packets {
            initiation += try pair.alice.send(packet, to: pair.key(.bob), at: t0)
        }
        // Only the first send emits an initiation. The 5-second suppression applies to the rest.
        #expect(initiation.messageTypes == [1])
        let delivered = try pair.deliver(initiation, from: .alice, at: t0)
        #expect(delivered[.bob] == Array(packets.suffix(64)))
    }

    @Test("send input validation")
    func sendValidation() throws {
        var pair = Pair()
        let stranger = try #require(PublicKey(rawValue: [UInt8](repeating: 9, count: 32)))
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.send([0x45], to: stranger, at: t0) }
        #expect(throws: WireGuardError.malformed) { try pair.alice.send([], to: pair.key(.bob), at: t0) }
        let tooLarge = [UInt8](repeating: 0, count: 65535 - 40 + 1)
        #expect(throws: WireGuardError.packetTooLarge) { try pair.alice.send(tooLarge, to: pair.key(.bob), at: t0) }
        // A rejected send leaves the handshake unstarted.
        #expect(pair.alice.nextDeadline == nil)
    }

    @Test("addPeer preserves an existing peer's session and updates only AllowedIPs")
    func addPeerKeepsSession() throws {
        var pair = Pair()
        try pair.establish()
        pair.bob.addPeer(pair.key(.alice), allowedIPs: [])
        let outputs = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(outputs.messageTypes == [4])
        #expect(try pair.bob.receive(outputs.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])
    }

    @Test("PublicKey formatting shows only the first 8 digits")
    func publicKeyDescription() throws {
        let key = try #require(PublicKey(rawValue: [UInt8](repeating: 0xAB, count: 32)))
        #expect(key.description == "abababab…")
        #expect(PublicKey(rawValue: [UInt8](repeating: 0, count: 31)) == nil)
    }
}

@Suite("Key material exposure")
struct SecretExposureTests {
    @Test("print and dump output omit secret keys and handshake and session material")
    func reflectionHidesSecrets() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        var device = WireGuardDevice(privateKey: privateKey, now: t0, wallClock: Date(timeIntervalSince1970: 1_800_000_000))
        var peer = WireGuardDevice(privateKey: .init(), now: t0, wallClock: Date(timeIntervalSince1970: 1_800_000_000))
        device.addPeer(peer.publicKey, allowedIPs: [])
        peer.addPeer(device.publicKey, allowedIPs: [])
        let initiation = try device.send([0x45], to: peer.publicKey, at: t0)
        _ = try peer.receive(initiation.datagrams[0], at: t0)

        var dumped = ""
        dump(device, to: &dumped)
        let printed = (String(describing: device) + String(reflecting: device) + dumped).lowercased()
        let state = try #require(device.peers[peer.publicKey])
        #expect(!printed.contains(Array(privateKey.rawRepresentation).hex))
        #expect(!printed.contains(try #require(state.staticStaticSecret).hex))
        // Even the names of secret fields within the peer remain hidden.
        for field in ["staticstaticsecret", "pendinghandshake", "chainingkey", "keypairs", "cookie"] {
            #expect(!printed.contains(field), "\(field)")
        }
    }
}
