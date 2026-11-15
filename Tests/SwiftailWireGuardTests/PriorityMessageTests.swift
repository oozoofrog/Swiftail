// priority message: 세션 키가 설 때마다 대기열보다 먼저 한 번 보내는 평문(Tailscale 포크 wireguard-go
// `SendPriorityMessage`, `device/receive.go`의 두 호출 자리). Tailscale은 이것으로 TSMP disco 키 광고를 보낸다.

import Foundation
import Testing

import SwiftailBase

@testable import SwiftailWireGuard

@Suite("priority message")
struct PriorityMessageTests {
    /// alice와 bob이 서로에게 보낼 priority message를 정한 장치 둘.
    private static func pair() throws -> Pair {
        var pair = Pair()
        try pair.alice.setPriorityMessage(pair.packet(from: .alice, payload: Array("alice".utf8)), for: pair.key(.bob))
        try pair.bob.setPriorityMessage(pair.packet(from: .bob, payload: Array("bob".utf8)), for: pair.key(.alice))
        return pair
    }

    @Test("시작한 쪽은 response를 받으면 priority message를 대기열보다 먼저, 응답한 쪽은 첫 transport를 받으면 보낸다")
    func sentAtEstablishmentBeforeStagedPackets() throws {
        var pair = try Self.pair()
        let first = pair.packet(from: .alice)
        let initiation = try pair.alice.send(first, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        // 응답자는 아직 확인 전이라 보내지 않는다.
        #expect(response.messageTypes == [2])

        // 시작한 쪽: priority message, 그다음 대기열의 패킷.
        let transports = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(transports.messageTypes == [4, 4])
        let priority = try pair.bob.receive(transports.datagrams[0], at: t0)
        // 응답한 쪽: 첫 transport(시작한 쪽의 priority message)로 세션을 확인하면 자기 priority message를 먼저 내고
        // 받은 패킷을 올린다.
        #expect(priority.messageTypes == [4])
        #expect(priority.ipPackets == [pair.packet(from: .alice, payload: Array("alice".utf8))])
        #expect(try pair.bob.receive(transports.datagrams[1], at: t0).ipPackets == [first])
        #expect(try pair.alice.receive(priority.datagrams[0], at: t0).ipPackets == [pair.packet(from: .bob, payload: Array("bob".utf8))])
    }

    @Test("대기열이 비어 있으면 시작한 쪽은 priority message 뒤에 keepalive도 보낸다")
    func initiatorStillSendsKeepalive() throws {
        var pair = try Self.pair()
        // alice가 받은 데이터 없이 핸드셰이크만 한다(rekey 타이머가 시작한 것과 같다).
        let outputs = try #require(pair.alice.edit(pair.key(.bob)) { device, peer in
            device.sendHandshakeInitiation(&peer, isRetry: false, at: t0)
        })
        let response = try pair.bob.receive(outputs.datagrams[0], at: t0)
        let transports = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(transports.messageTypes == [4, 4])
        // 둘째는 keepalive(빈 평문: 머리 16 + 태그 16).
        #expect(transports.datagrams[1].count == 32)
    }

    @Test("한 세션에 한 번이고, rekey로 새 세션이 서면 다시 보낸다")
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

        // 같은 세션의 데이터에는 붙지 않는다.
        let later = t0 + .seconds(1)
        record(try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: later), from: .alice, at: later))
        record(try pair.deliver(try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: later), from: .bob, at: later))
        #expect(log[.bob]?.filter { $0 == alicePriority }.count == 1)
        #expect(log[.alice]?.filter { $0 == bobPriority }.count == 1)

        // 120초가 지나 시작한 쪽이 보내면 rekey가 시작되고, 새 세션에서 양쪽이 다시 보낸다.
        let rekey = t0 + .seconds(121)
        record(try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: rekey), from: .alice, at: rekey))
        #expect(log[.bob]?.filter { $0 == alicePriority }.count == 2)
        #expect(log[.alice]?.filter { $0 == bobPriority }.count == 2)
    }

    @Test("priority message를 정하지 않았거나 지우면 보내지 않는다")
    func absentOrCleared() throws {
        var pair = try Self.pair()
        try pair.alice.setPriorityMessage(nil, for: pair.key(.bob))
        let first = pair.packet(from: .alice)
        let initiation = try pair.alice.send(first, to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        let transports = try pair.alice.receive(response.datagrams[0], at: t0)
        #expect(transports.messageTypes == [4])
        let confirmed = try pair.bob.receive(transports.datagrams[0], at: t0)
        // bob은 아직 정해 두었으므로 확인할 때 보낸다.
        #expect(confirmed.messageTypes == [4])
        #expect(confirmed.ipPackets == [first])
    }

    @Test("priority message는 데이터 송신으로 세어 답이 없으면 새 핸드셰이크 타이머를 건다")
    func countsAsData() throws {
        var pair = try Self.pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0)
        let response = try pair.bob.receive(initiation.datagrams[0], at: t0)
        _ = try pair.alice.receive(response.datagrams[0], at: t0)
        let timers = try #require(pair.alice.peers[pair.key(.bob)]).timers
        #expect(timers[.newHandshake] != nil)
    }

    @Test("입력 검사: 빈 패킷, 512바이트 초과, 모르는 피어")
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
