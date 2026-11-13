// 계약 시험 2: 시각을 직접 넘겨 타이머와 키 교체를 시험한다. 실제 시간은 기다리지 않는다.

import Testing

@testable import SwiftailWireGuard

@Suite("타이머와 키 교체")
struct TimerTests {
    @Test("초기자는 keypair가 120초를 넘으면 보낸 뒤 rekey하고, 옛 keypair로 늦게 온 패킷도 받는다")
    func initiatorRekeysAfter120Seconds() throws {
        var pair = Pair()
        try pair.establish()
        let oldIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)

        // 120초 정각에는 아직 아니다("넘으면").
        let at120 = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(120))
        #expect(at120.messageTypes == [4])
        try pair.deliver(at120, from: .alice, at: t0 + .seconds(120))

        // bob이 옛 keypair로 보낸 패킷 하나를 잡아 둔다.
        let late = pair.packet(from: .bob, payload: [0x1A])
        let lateOutputs = try pair.bob.send(late, to: pair.key(.alice), at: t0 + .seconds(120))

        let now = t0 + .seconds(121)
        let rekey = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now)
        #expect(rekey.messageTypes == [4, 1])
        try pair.deliver(rekey, from: .alice, at: now)

        let newIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)
        #expect(newIndex != oldIndex)
        #expect(pair.keypairs(of: .alice)?.previous?.localIndex == oldIndex)

        // bob의 새 패킷은 새 index로 온다.
        let fresh = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(fresh.datagrams.first?.uint32(at: 4) == newIndex)
        try pair.deliver(fresh, from: .bob, at: now)

        // 옛 keypair(previous)로 늦게 온 패킷도 받는다.
        #expect(lateOutputs.datagrams.first?.uint32(at: 4) == oldIndex)
        #expect(try pair.deliver(lateOutputs, from: .bob, at: now)[.alice] == [late])
    }

    @Test("응답자는 시간으로 rekey하지 않고, 상대의 rekey에서 next가 확인될 때까지 current로 보낸다")
    func responderSideRekey() throws {
        var pair = Pair()
        try pair.establish()
        let oldAliceIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)

        // 응답자 bob은 120초가 지나도 initiation을 보내지 않는다.
        let now = t0 + .seconds(121)
        let bobSend = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(bobSend.messageTypes == [4])
        try pair.deliver(bobSend, from: .bob, at: now)

        // alice가 rekey한다. initiation만 bob에게 넘기고 response는 잡아 둔다.
        let rekey = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now)
        #expect(rekey.messageTypes == [4, 1])
        _ = try pair.bob.receive(rekey.datagrams[0], at: now)
        let response = try pair.bob.receive(rekey.datagrams[1], at: now)
        #expect(response.messageTypes == [2])
        #expect(pair.keypairs(of: .bob)?.next != nil)

        // 확인 전: bob은 옛 current로 보낸다(receiver = alice의 옛 index).
        let beforeConfirm = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(beforeConfirm.datagrams.first?.uint32(at: 4) == oldAliceIndex)

        // response가 alice에 닿으면 alice의 keepalive가 bob의 next를 확인한다.
        try pair.deliver(response, from: .bob, at: now)
        let newAliceIndex = try #require(pair.keypairs(of: .alice)?.current?.localIndex)
        #expect(newAliceIndex != oldAliceIndex)
        #expect(pair.keypairs(of: .bob)?.next == nil)

        let afterConfirm = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        #expect(afterConfirm.datagrams.first?.uint32(at: 4) == newAliceIndex)
        // 확인 전에 보낸 패킷도 alice의 previous로 받는다.
        try pair.deliver(beforeConfirm + afterConfirm, from: .bob, at: now)
    }

    @Test("180초가 넘은 keypair로는 받지도 보내지도 않는다")
    func rejectAfter180Seconds() throws {
        var pair = Pair()
        try pair.establish()
        let old = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .seconds(1))

        #expect(throws: WireGuardError.noSession) { try pair.alice.receive(old.datagrams[0], at: t0 + .seconds(181)) }

        // 보낼 때는 대기열에 넣고 새 핸드셰이크를 시작한다.
        let packet = pair.packet(from: .alice)
        let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0 + .seconds(181))
        #expect(outputs.messageTypes == [1])
        #expect(try pair.deliver(outputs, from: .alice, at: t0 + .seconds(181))[.bob] == [packet])
    }

    @Test("165초가 넘은 초기자는 받기만 해도 한 번 rekey한다")
    func lastMinuteRekeyOnReceive() throws {
        var pair = Pair()
        try pair.establish()
        let now = t0 + .seconds(166)
        let bobSend = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now)
        let reply = try pair.alice.receive(bobSend.datagrams[0], at: now)
        #expect(reply.messageTypes == [1])
        // 한 번만 보낸다.
        let second = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: now + .seconds(6))
        #expect(try pair.alice.receive(second.datagrams[0], at: now + .seconds(6)).messageTypes == [])
    }

    @Test("답이 없으면 5초+지터마다 새 initiation으로 재시도하고, 20번 뒤 포기한다")
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
        // 재시도마다 sender index, 임시 키, timestamp 암호문이 새 값이다.
        #expect(Set(initiations.map { $0.uint32(at: 4) }).count == 20)
        #expect(Set(initiations.map { Array($0[8..<40]) }).count == 20)

        // 포기하면 대기열을 버리고 540초 뒤 키 재료 삭제만 남는다.
        let peer = try #require(pair.alice.peers[pair.key(.bob)])
        #expect(peer.staged.isEmpty)
        let giveUp = try #require(pair.alice.nextDeadline)
        #expect(giveUp > lastSent + .seconds(5) + .seconds(534))
        _ = pair.alice.advance(to: giveUp)
        #expect(pair.alice.peers[pair.key(.bob)]?.pendingHandshake == nil)
        #expect(pair.alice.indexTable.isEmpty)
        #expect(pair.alice.nextDeadline == nil)
    }

    @Test("540초 동안 새 키가 없으면 키 재료를 지운다")
    func zeroKeyMaterialAfter540Seconds() throws {
        var pair = Pair()
        try pair.establish()
        let pending = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1))

        // bob: 10초 keepalive가 나간 뒤에는 540초 타이머만 남는다.
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

        // 지운 뒤에도 새 핸드셰이크로 다시 연결된다.
        let packet = pair.packet(from: .alice)
        let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0 + .seconds(600))
        #expect(outputs.messageTypes == [1])
        #expect(try pair.deliver(outputs, from: .alice, at: t0 + .seconds(600))[.bob] == [packet])
    }

    @Test("removePeer는 피어와 index를 지운다")
    func removePeer() throws {
        var pair = Pair()
        try pair.establish()
        let pending = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1))
        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.peers.isEmpty)
        #expect(pair.bob.indexTable.isEmpty)
        #expect(pair.bob.nextDeadline == nil)
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive(pending.datagrams[0], at: t0 + .seconds(1)) }

        // 모르는 피어의 initiation도 unknownPeer다.
        var fresh = Pair()
        fresh.bob.removePeer(fresh.key(.alice))
        let initiation = try fresh.alice.send(fresh.packet(from: .alice), to: fresh.key(.bob), at: t0)
        #expect(throws: WireGuardError.unknownPeer) { try fresh.bob.receive(initiation.datagrams[0], at: t0) }
    }

    @Test("response를 보낸 응답자는 5초 안에는 initiation을 보내지 않는다")
    func rekeyTimeoutSuppression() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        _ = try pair.bob.receive(initiation.datagrams[0], at: t0)
        #expect(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .milliseconds(4999)).isEmpty)
        #expect(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0 + .seconds(5)).messageTypes == [1])
    }
}
