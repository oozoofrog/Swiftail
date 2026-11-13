// 계약 시험 1: Swift 장치 둘을 메모리에서 연결한다.
// 양쪽 역할의 핸드셰이크, 양방향 데이터, keepalive, 대기열 방출.

import CryptoKit
import Foundation
import Testing

import SwiftailBase

@testable import SwiftailWireGuard

@Suite("세션: 핸드셰이크와 데이터")
struct SessionTests {
    @Test("핸드셰이크 뒤 양방향 데이터", arguments: [Pair.Side.alice, .bob])
    func handshakeAndData(initiator: Pair.Side) throws {
        var pair = Pair()
        let responder = initiator.other
        let first = pair.packet(from: initiator)

        // 세션이 없으니 initiation만 나간다.
        let initiation = try pair[initiator].send(first, to: pair.key(responder), at: t0)
        #expect(initiation.messageTypes == [1])
        #expect(initiation.datagrams.first?.count == Initiation.size)

        // 응답자는 response를 보낸다.
        let response = try pair[responder].receive(initiation.datagrams[0], at: t0)
        #expect(response.messageTypes == [2])
        #expect(response.datagrams.first?.count == Response.size)
        #expect(pair.keypairs(of: responder)?.next != nil)
        #expect(pair.keypairs(of: responder)?.current == nil)

        // 초기자는 response를 받자마자 대기열의 패킷을 보낸다. 이 패킷이 응답자의 next를 확인시킨다.
        let transport = try pair[initiator].receive(response.datagrams[0], at: t0)
        #expect(transport.messageTypes == [4])
        let delivered = try pair[responder].receive(transport.datagrams[0], at: t0)
        #expect(delivered == [.ipPacket(first, from: pair.key(initiator))])
        #expect(pair.keypairs(of: responder)?.current != nil)
        #expect(pair.keypairs(of: responder)?.next == nil)

        // 이제 양쪽 모두 바로 보낸다.
        let reply = pair.packet(from: responder, payload: Array(0..<100))
        let replyOutputs = try pair[responder].send(reply, to: pair.key(initiator), at: t0 + .milliseconds(1))
        #expect(replyOutputs.messageTypes == [4])
        #expect(try pair.deliver(replyOutputs, from: responder, at: t0 + .milliseconds(1))[initiator] == [reply])

        let again = pair.packet(from: initiator, payload: [7])
        let againOutputs = try pair[initiator].send(again, to: pair.key(responder), at: t0 + .milliseconds(2))
        #expect(try pair.deliver(againOutputs, from: initiator, at: t0 + .milliseconds(2))[responder] == [again])
    }

    @Test("transport는 16바이트 배수로 패딩되고, 받는 쪽은 IP 길이로 패딩을 뗀다")
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

    @Test("데이터를 받고 10초 동안 보낼 것이 없으면 keepalive를 보낸다")
    func keepalive() throws {
        var pair = Pair()
        try pair.establish()

        // bob은 데이터를 받았으니 10초 뒤 keepalive가 걸려 있다.
        #expect(pair.bob.nextDeadline == t0 + .seconds(10))
        // alice는 데이터를 보냈으니 15초+지터 뒤 새 핸드셰이크가 걸려 있다.
        let aliceDeadline = try #require(pair.alice.nextDeadline)
        #expect(aliceDeadline >= t0 + .seconds(15) && aliceDeadline < t0 + .seconds(15) + .milliseconds(334))

        let beforeTimeout = pair.bob.advance(to: t0 + .seconds(9))
        #expect(beforeTimeout.isEmpty)
        let keepalive = pair.bob.advance(to: t0 + .seconds(10))
        #expect(keepalive.messageTypes == [4])
        #expect(keepalive.datagrams.first?.count == TransportData.minimumSize)

        // keepalive는 IP 패킷으로 올라오지 않고, alice의 새 핸드셰이크 타이머를 푼다.
        let delivered = try pair.deliver(keepalive, from: .bob, at: t0 + .seconds(10))
        #expect(delivered[.alice] == [])
        #expect(pair.alice.nextDeadline == t0 + .seconds(540))
        let aliceLater = pair.alice.advance(to: t0 + .seconds(20))
        #expect(aliceLater.isEmpty)
    }

    @Test("데이터를 이미 답으로 보냈으면 keepalive를 보내지 않는다")
    func noKeepaliveAfterReply() throws {
        var pair = Pair()
        try pair.establish()
        let reply = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .seconds(1))
        try pair.deliver(reply, from: .bob, at: t0 + .seconds(1))
        let afterReply = pair.bob.advance(to: t0 + .seconds(10))
        #expect(afterReply.isEmpty)
    }

    @Test("응답자는 확인 전에 보낸 패킷을 대기열에 두었다가 확인 뒤 내보낸다")
    func responderReleasesQueueOnConfirmation() throws {
        var pair = Pair()
        let first = pair.packet(from: .alice)
        let initiation = try pair.alice.send(first, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)

        // bob에게는 아직 current가 없다. response를 보낸 지 5초가 안 되어 initiation도 보내지 않는다.
        let early = pair.packet(from: .bob, payload: [1, 2, 3])
        #expect(try pair.bob.send(early, to: pair.key(.alice), at: t0 + .milliseconds(1)).isEmpty)

        let delivered = try pair.deliver(response, from: .bob, at: t0 + .milliseconds(2))
        #expect(delivered[.bob] == [first])
        #expect(delivered[.alice] == [early])
    }

    @Test("세션 전 대기열은 64개이고 넘치면 오래된 것부터 버린다")
    func stagedQueueLimit() throws {
        var pair = Pair()
        let packets = (0..<70).map { pair.packet(from: .alice, payload: [UInt8($0)]) }
        var initiation: [WireGuardDevice.Output] = []
        for packet in packets {
            initiation += try pair.alice.send(packet, to: pair.key(.bob), at: t0)
        }
        // 첫 send만 initiation을 보내고 나머지는 5초 억제에 걸린다.
        #expect(initiation.messageTypes == [1])
        let delivered = try pair.deliver(initiation, from: .alice, at: t0)
        #expect(delivered[.bob] == Array(packets.suffix(64)))
    }

    @Test("send의 입력 검사")
    func sendValidation() throws {
        var pair = Pair()
        let stranger = try #require(PublicKey(rawValue: [UInt8](repeating: 9, count: 32)))
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.send([0x45], to: stranger, at: t0) }
        #expect(throws: WireGuardError.malformed) { try pair.alice.send([], to: pair.key(.bob), at: t0) }
        let tooLarge = [UInt8](repeating: 0, count: 65535 - 40 + 1)
        #expect(throws: WireGuardError.packetTooLarge) { try pair.alice.send(tooLarge, to: pair.key(.bob), at: t0) }
        // 거절한 send는 핸드셰이크를 시작하지 않는다.
        #expect(pair.alice.nextDeadline == nil)
    }

    @Test("addPeer는 기존 피어의 세션을 유지하고 AllowedIPs만 바꾼다")
    func addPeerKeepsSession() throws {
        var pair = Pair()
        try pair.establish()
        pair.bob.addPeer(pair.key(.alice), allowedIPs: [])
        let outputs = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(outputs.messageTypes == [4])
        #expect(try pair.bob.receive(outputs.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])
    }

    @Test("PublicKey 표기는 앞 8자리만")
    func publicKeyDescription() throws {
        let key = try #require(PublicKey(rawValue: [UInt8](repeating: 0xAB, count: 32)))
        #expect(key.description == "abababab…")
        #expect(PublicKey(rawValue: [UInt8](repeating: 0, count: 31)) == nil)
    }
}

@Suite("키 재료 노출")
struct SecretExposureTests {
    @Test("print·dump 출력에 비밀 키와 핸드셰이크·세션 재료가 나오지 않는다")
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
        // 피어 안의 비밀 필드는 이름조차 펼쳐지지 않는다.
        for field in ["staticstaticsecret", "pendinghandshake", "chainingkey", "keypairs", "cookie"] {
            #expect(!printed.contains(field), "\(field)")
        }
    }
}
