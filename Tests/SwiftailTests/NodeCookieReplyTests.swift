import CryptoKit
import Foundation
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock
import SwiftailWireGuard
import Testing
@testable import Swiftail

/// The node passes the inbound path to the engine and returns the cookie reply from WireGuard under load via that path.
/// Connects `Magicsock` → `engine.receive` → `.cookieReply` → `Magicsock` output for the inbound path in the same order as the node.
@Suite("Returning the node's cookie reply")
struct NodeCookieReplyTests {
    private static let start = ContinuousClock.now

    /// An engine without peers (bob) and one initiation from a WireGuard device (alice) that has bob as a peer.
    private static func bobAndInitiation() throws -> (bob: TailnetEngine, alice: WireGuardDevice, initiation: [UInt8], aliceKey: NodePublicKey) {
        let bobKey = Curve25519.KeyAgreement.PrivateKey()
        let bob = TailnetEngine(nodeKey: bobKey, discoKey: .zero, now: start, wallClock: Date())
        var alice = WireGuardDevice(privateKey: .init(), now: start, wallClock: Date())
        let bobPublic = try #require(PublicKey(rawValue: bobKey.publicKey.rawRepresentation))
        alice.addPeer(bobPublic, allowedIPs: [])
        let packet: [UInt8] = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2]
        guard case let .datagram(initiation, _)? = try alice.send(packet, to: bobPublic, at: start).first else {
            throw NodeCookieReplyFailure()
        }
        let aliceKey = try #require(NodePublicKey(rawValue: alice.publicKey.rawValue))
        return (bob, alice, initiation, aliceKey)
    }

    /// Feed the same initiation up to the load threshold (128 in 1 second). Below the threshold, it is dropped for lack of a peer. At the threshold, a cookie reply is emitted.
    private static func overload(_ bob: inout TailnetEngine, with initiation: [UInt8], from source: Magicsock.Source) throws -> [UInt8] {
        for _ in 1..<128 {
            #expect(bob.receive(initiation, from: source.engineSource, at: start) == [.dropped(.wireGuard(.unknownPeer))])
        }
        guard case let .cookieReply(reply)? = bob.receive(initiation, from: source.engineSource, at: start).first else {
            throw NodeCookieReplyFailure()
        }
        return reply
    }

    @Test("A cookie reply for an initiation received via UDP returns to that address and the sender opens it")
    func udp() throws {
        var (bob, alice, initiation, _) = try Self.bobAndInitiation()
        let aliceAddress = try #require(IPEndpoint("192.0.2.7:41641"))
        var sock = Magicsock(discoKey: .init(), nodeKey: .zero, localPort: 41641, localAddresses: [], loopbackAddresses: [], now: Self.start)
        let received = sock.receiveUDP(initiation, from: aliceAddress, at: Self.start)
        #expect(received == [.wireGuard(initiation, from: .udp(aliceAddress))])

        let reply = try Self.overload(&bob, with: initiation, from: .udp(aliceAddress))
        #expect(Magicsock.Source.udp(aliceAddress).reply(reply) == .udp(reply, to: aliceAddress))
        #expect(try alice.receive(reply, from: WireGuardDevice.Source(address: [], host: []), at: Self.start).isEmpty)
    }

    @Test("A cookie reply for an initiation received via DERP returns to the sending peer through the same region")
    func derp() throws {
        var (bob, alice, initiation, aliceKey) = try Self.bobAndInitiation()
        var sock = Magicsock(discoKey: .init(), nodeKey: .zero, localPort: 41641, localAddresses: [], loopbackAddresses: [], now: Self.start)
        _ = sock.setPeers([Magicsock.Peer(key: aliceKey, discoKey: .zero, homeDERP: 7, endpoints: [])], at: Self.start)
        let received = sock.receiveDERP(initiation, from: aliceKey, region: 9, at: Self.start)
        #expect(received == [.wireGuard(initiation, from: .derp(aliceKey, region: 9))])

        let reply = try Self.overload(&bob, with: initiation, from: .derp(aliceKey, region: 9))
        #expect(Magicsock.Source.derp(aliceKey, region: 9).reply(reply) == .derp(reply, to: aliceKey, region: 9))
        #expect(try alice.receive(reply, from: WireGuardDevice.Source(address: [], host: []), at: Self.start).isEmpty)
    }

    @Test("WireGuard source: UDP uses address ‖ port (LE) and the address, and DERP uses the peer key regardless of region")
    func engineSource() throws {
        let udp = Magicsock.Source.udp(try #require(IPEndpoint("192.0.2.7:41641"))).engineSource
        #expect(udp.address == [192, 0, 2, 7, 0xA9, 0xA2] && udp.host == [192, 0, 2, 7])
        let key = try #require(NodePublicKey(rawValue: [UInt8](repeating: 0x5A, count: 32)))
        let derp = Magicsock.Source.derp(key, region: 1).engineSource
        #expect(derp == Magicsock.Source.derp(key, region: 2).engineSource)
        #expect(derp.address == key.rawValue && derp.host == key.rawValue)
    }
}

private struct NodeCookieReplyFailure: Error {}
