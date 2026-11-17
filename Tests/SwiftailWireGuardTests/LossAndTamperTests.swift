// 계약 시험 4: 유실·변조.
// response 유실 뒤 복구, 옛 response가 새 핸드셰이크를 덮지 않음, 변조된 메시지가 상태를 바꾸지 않음,
// AllowedIPs 밖 출발 주소 거부.

import CryptoKit
import Testing

@testable import SwiftailWireGuard

@Suite("유실과 변조")
struct LossAndTamperTests {
    @Test("response를 잃으면 재시도 initiation으로 복구한다")
    func recoversFromLostResponse() throws {
        var pair = Pair()
        let packet = pair.packet(from: .alice)
        let first = try pair.alice.send(packet, to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0) // response를 잃는다.

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(retry.messageTypes == [1])
        #expect(try pair.deliver(retry, from: .alice, at: retryAt)[.bob] == [packet])
    }

    @Test("옛 response는 새 핸드셰이크를 덮지 않고, 처리한 response는 다시 받지 않는다")
    func staleResponseIsIgnored() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        let staleResponse = try pair.bob.receive(first.datagrams[0], at: t0)

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        let freshResponse = try pair.bob.receive(retry.datagrams[0], at: retryAt)

        // 옛 response의 receiver index는 새 initiation을 만들 때 버려졌다.
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.receive(staleResponse.datagrams[0], at: retryAt) }
        #expect(pair.alice.peers[pair.key(.bob)]?.pendingHandshake?.localIndex == retry.datagrams[0].uint32(at: 4))

        let confirm = try pair.alice.receive(freshResponse.datagrams[0], at: retryAt)
        #expect(confirm.messageTypes == [4])
        try pair.deliver(confirm, from: .alice, at: retryAt)

        // 같은 response를 다시 받으면 거절한다. index가 이미 keypair로 바뀌었다.
        #expect(throws: WireGuardError.replayed) { try pair.alice.receive(freshResponse.datagrams[0], at: retryAt) }
    }

    @Test("같은 initiation의 재전송과 20ms 안의 두 번째 initiation은 거절한다")
    func initiationReplayAndFlood() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }

        // alice가 6초 뒤 새 initiation을 만든다. bob은 그보다 20ms 안에 initiation을 소비한 적이 있으면 거절한다.
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        var flooded = pair
        flooded.bob.peers[pair.key(.alice)]?.lastInitiationConsumed = retryAt - .milliseconds(20)
        #expect(throws: WireGuardError.replayed) { try flooded.bob.receive(retry.datagrams[0], at: retryAt) }
        #expect(try pair.bob.receive(retry.datagrams[0], at: retryAt).messageTypes == [2])
    }

    @Test("피어를 내렸다 다시 올려도 옛 initiation의 재전송은 거절하고, 더 새 것은 받는다")
    func removedPeerKeepsLastTimestamp() throws {
        var pair = Pair()
        let allowedIPs = try #require(pair.bob.peers[pair.key(.alice)]?.allowedIPs)
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)

        // 같은 키의 피어가 netmap에서 빠졌다 돌아온다.
        pair.bob.removePeer(pair.key(.alice))
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }
        pair.bob.addPeer(pair.key(.alice), allowedIPs: allowedIPs)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(try pair.bob.receive(retry.datagrams[0], at: retryAt).messageTypes == [2])
    }

    @Test("내린 피어의 timestamp는 1,024개까지만 기억한다. timestamp가 같으면 먼저 내린 것부터 잊고, 되살린 것은 표에서 뺀다")
    func retiredTimestampsAreBounded() throws {
        var pair = Pair()
        let allowedIPs = try #require(pair.bob.peers[pair.key(.alice)]?.allowedIPs)
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)
        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.retiredTimestamps.count == 1)

        // 다시 올리면 표에서 빠지고, 핸드셰이크한 적 없는 피어는 내려도 남기지 않는다.
        pair.bob.addPeer(pair.key(.alice), allowedIPs: allowedIPs)
        #expect(pair.bob.retiredTimestamps.isEmpty)
        let silent = PublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
        pair.bob.addPeer(silent, allowedIPs: [])
        pair.bob.removePeer(silent)
        #expect(pair.bob.retiredTimestamps.isEmpty)

        // alice를 내린 뒤 다른 피어 1,024개를 내리면 alice의 것이 밀려난다.
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

    @Test("표가 가득 차면 먼저 내린 것부터 잊는다. 상대가 정한 먼 미래의 timestamp가 표를 차지하지 못한다")
    func retiredTimestampsForgetFirstRetired() throws {
        var pair = Pair()
        let allowedIPs = try #require(pair.bob.peers[pair.key(.alice)]?.allowedIPs)
        // 먼 미래의 timestamp를 쓴 피어들로 표를 가득 채운다.
        for second in 0..<Int64(Constants.maxRetiredTimestamps) {
            let key = PublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
            pair.bob.addPeer(key, allowedIPs: [])
            pair.bob.peers[key]?.lastAcceptedTimestamp = TAI64N(sinceUnixEpoch: .seconds(4_000_000_000 + second))
            pair.bob.removePeer(key)
        }
        #expect(pair.bob.retiredTimestamps.count == Constants.maxRetiredTimestamps)

        // 그 뒤에 핸드셰이크하고 내린 정상 피어의 기록은 남는다. 잊히는 것은 가장 먼저 내린 것이다.
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(first.datagrams[0], at: t0)
        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.retiredTimestamps.count == Constants.maxRetiredTimestamps)
        #expect(pair.bob.retiredTimestamps.first?.timestamp == TAI64N(sinceUnixEpoch: .seconds(4_000_000_001)))

        pair.bob.addPeer(pair.key(.alice), allowedIPs: allowedIPs)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(first.datagrams[0], at: t0 + .seconds(1)) }
    }

    @Test("변조한 initiation은 거절되고 상태를 바꾸지 않는다")
    func tamperedInitiation() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        // mac2(132..<148)는 부하 상태에서만 검사하므로 제외한다. wireguard-go도 같다.
        for offset in 0..<132 {
            var tampered = initiation
            tampered[offset] ^= 0x01
            #expect(throws: WireGuardError.self) { try pair.bob.receive(tampered, at: t0) }
        }
        #expect(pair.bob.nextDeadline == nil)
        #expect(pair.bob.indexTable.isEmpty)
        // 원래 initiation은 여전히 받아들여진다(timestamp가 소비되지 않았다).
        #expect(try pair.bob.receive(initiation, at: t0).messageTypes == [2])
    }

    @Test("변조한 response는 거절되고 상태를 바꾸지 않는다")
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

    @Test("변조한 transport는 재전송 창과 next를 바꾸지 않는다")
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
        // 잘린 transport도 거절한다.
        #expect(throws: WireGuardError.self) { try pair.bob.receive(Array(transport.dropLast()), at: t0) }
        #expect(pair.keypairs(of: .bob)?.next != nil)
        #expect(pair.bob.nextDeadline == deadline)

        // 원래 transport는 받아들여지고 next를 확인한다. 같은 것을 다시 받으면 재전송이다.
        #expect(try pair.bob.receive(transport, at: t0).count == 1)
        #expect(pair.keypairs(of: .bob)?.current != nil)
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(transport, at: t0) }
    }

    @Test("출발 주소가 AllowedIPs 밖이면 거절하되 인증된 패킷으로는 센다")
    func disallowedSource() throws {
        var pair = Pair()
        try pair.establish()
        let spoofed = ipv4Packet(source: "100.64.0.9", destination: Pair.bobAddress, payload: [1])
        let outputs = try pair.alice.send(spoofed, to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.bob.receive(outputs.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])
        // 재전송 창에는 기록된다.
        #expect(throws: WireGuardError.replayed) { try pair.bob.receive(outputs.datagrams[0], at: t0 + .seconds(1)) }

        // IPv6 출발 주소도 같은 검사를 받는다.
        let v6 = ipv6Packet(source: "fd7a:115c:a1e0::1", destination: "fd7a:115c:a1e0::2", payload: [1, 2])
        let v6Outputs = try pair.alice.send(v6, to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.bob.receive(v6Outputs.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.disallowedSource, from: pair.key(.alice))])

        // IP 패킷이 아닌 평문은 malformed다.
        let garbage = try pair.alice.send([0x50, 1, 2, 3], to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.bob.receive(garbage.datagrams[0], at: t0 + .seconds(1)) == [.rejectedIPPacket(.malformed, from: pair.key(.alice))])

        // 정상 패킷은 계속 통과한다.
        let good = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(2))
        #expect(try pair.deliver(good, from: .alice, at: t0 + .seconds(2))[.bob]?.count == 1)
    }

    @Test("응답자의 next는 AllowedIPs 밖 패킷으로도 확인된다(wireguard-go와 같다)")
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

    // 교차 검토(GPT-6.1 Sol)가 찾은 결함의 회귀 시험: IP 검사에 걸린 패킷도 세션 처리는 끝까지 한다.
    @Test("응답자는 AllowedIPs 밖 패킷으로 next를 확정한 즉시 대기열을 내보낸다")
    func stagedPacketsFlushOnRejectedConfirmation() throws {
        var pair = Pair()
        let spoofed = ipv4Packet(source: "100.64.0.9", destination: Pair.bobAddress, payload: [1])
        let initiation = try pair.alice.send(spoofed, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        // 확정 전의 응답자는 새 키로 보내지 못하므로 대기열에 둔다.
        #expect(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0).isEmpty)
        let transport = try pair.alice.receive(response.datagrams[0], at: t0)

        let outputs = try pair.bob.receive(transport.datagrams[0], at: t0)
        #expect(outputs.messageTypes == [4])
        #expect(outputs.last == .rejectedIPPacket(.disallowedSource, from: pair.key(.alice)))
        #expect(try pair.alice.receive(outputs.datagrams[0], at: t0).ipPackets.count == 1)
    }

    @Test("165초를 넘긴 초기자는 AllowedIPs 밖 패킷을 받아도 rekey를 시작한다")
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

@Suite("받은 IP 패킷 해석")
struct InboundIPPacketTests {
    @Test("IPv4: total length로 패딩을 뗀다")
    func ipv4Padding() throws {
        let packet = ipv4Packet(source: "100.64.0.1", destination: "100.64.0.2", payload: [1, 2, 3])
        let parsed = try #require(InboundIPPacket(plaintext: packet + [0, 0, 0, 0, 0]))
        #expect(parsed.bytes == packet)
        #expect(parsed.source.description == "100.64.0.1")
    }

    @Test("IPv6: payload length + 40으로 패딩을 뗀다")
    func ipv6Padding() throws {
        let packet = ipv6Packet(source: "fd7a:115c:a1e0::1", destination: "fd7a:115c:a1e0::2", payload: [9])
        let parsed = try #require(InboundIPPacket(plaintext: packet + [0, 0, 0, 0, 0, 0, 0]))
        #expect(parsed.bytes == packet)
        #expect(parsed.source.description == "fd7a:115c:a1e0::1")
    }

    @Test("길이 필드가 평문 밖을 가리키거나 머리보다 짧으면 nil")
    func invalidLengths() {
        var v4 = ipv4Packet(source: "100.64.0.1", destination: "100.64.0.2", payload: [])
        #expect(InboundIPPacket(plaintext: v4) != nil)
        v4[3] = 21 // total length > 실제 길이
        #expect(InboundIPPacket(plaintext: v4) == nil)
        v4[3] = 19 // total length < 머리
        #expect(InboundIPPacket(plaintext: v4) == nil)
        #expect(InboundIPPacket(plaintext: Array(v4.prefix(19))) == nil)

        // payload length 0xFFFF + 40은 UInt16에서 넘치지만 여기서는 길이 초과로 거절한다.
        var v6 = ipv6Packet(source: "::1", destination: "::2", payload: [])
        v6[4] = 0xFF
        v6[5] = 0xFF
        #expect(InboundIPPacket(plaintext: v6) == nil)
        #expect(InboundIPPacket(plaintext: Array(v6.prefix(39))) == nil)

        #expect(InboundIPPacket(plaintext: []) == nil)
        #expect(InboundIPPacket(plaintext: [0x50] + [UInt8](repeating: 0, count: 60)) == nil)
    }
}
