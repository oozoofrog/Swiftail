import CryptoKit
import Foundation
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock
import SwiftailWireGuard
import Testing
@testable import Swiftail

/// 노드가 받은 길을 엔진에 넘기고, 부하 상태의 WireGuard가 낸 cookie reply를 그 길로 되돌린다.
/// `Magicsock` → `engine.receive` → `.cookieReply` → 받은 길의 `Magicsock` 출력까지를 노드와 같은 순서로 잇는다.
@Suite("노드의 cookie reply 되돌리기")
struct NodeCookieReplyTests {
    private static let start = ContinuousClock.now

    /// 피어가 없는 엔진(bob)과, bob을 피어로 둔 WireGuard 장치(alice)가 만든 initiation 하나.
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

    /// 같은 initiation을 부하 문턱(1초 안에 128개)까지 넣는다. 문턱 전에는 피어가 없어 버리고, 문턱에서 cookie reply가 나온다.
    private static func overload(_ bob: inout TailnetEngine, with initiation: [UInt8], from source: Magicsock.Source) throws -> [UInt8] {
        for _ in 1..<128 {
            #expect(bob.receive(initiation, from: source.engineSource, at: start) == [.dropped(.wireGuard(.unknownPeer))])
        }
        guard case let .cookieReply(reply)? = bob.receive(initiation, from: source.engineSource, at: start).first else {
            throw NodeCookieReplyFailure()
        }
        return reply
    }

    @Test("UDP로 온 initiation의 cookie reply는 그 주소로 되돌아가고 보낸 쪽이 연다")
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

    @Test("DERP로 온 initiation의 cookie reply는 같은 지역으로 보낸 피어에게 되돌아간다")
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

    @Test("WireGuard 출처: UDP는 주소 ‖ 포트(LE)와 주소, DERP는 지역과 무관하게 피어 키다")
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
