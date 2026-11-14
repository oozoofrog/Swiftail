// 계약 "오류와 상태": `send`·`receive`가 오류를 던지면 피어 상태(세션, 카운터, 재전송 창, 타이머, index 표)는
// 그대로다. 피어를 표 안에서 제자리로 고치므로, 오류를 던진 경로가 일부만 바꾼 채 남지 않는지 상태 전체를 비교한다.

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailWireGuard

/// 장치의 피어 상태를 비교할 수 있는 값으로 뜬 것. 키 재료는 담지 않고 해시만 담는다.
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

/// mac1을 다시 계산한 핸드셰이크 메시지(mac2는 0). mac1 검사를 지나 DH·AEAD 인증 단계에서 거절되게 한다.
private func remacked(_ message: [UInt8], for receiver: PublicKey) -> [UInt8] {
    let head = Array(message.dropLast(32))
    return head + MAC.authenticate(head, key: MAC.mac1Key(for: receiver)) + [UInt8](repeating: 0, count: 16)
}

/// index 표가 피어들이 가진 index와 같고, 피어가 표에 올려 둔 칸의 기록도 지금 칸과 같은지 본다.
private func expectIndexTableConsistent(_ device: WireGuardDevice, sourceLocation: SourceLocation = #_sourceLocation) {
    var expected: [UInt32: PublicKey] = [:]
    for (key, peer) in device.peers {
        #expect(peer.tabledIndexSlots == peer.indexSlots, sourceLocation: sourceLocation)
        for index in peer.localIndices { expected[index] = key }
    }
    #expect(device.indexTable == expected, sourceLocation: sourceLocation)
}

@Suite("실패하면 상태를 바꾸지 않는다")
struct FailureAtomicityTests {
    /// 입력을 넣어 오류가 나는지 보고, 장치의 피어 상태가 그대로인지 확인한다.
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
            Issue.record("거절되어야 하는 데이터그램이 받아들여졌다", sourceLocation: sourceLocation)
        } catch {
            if let expected { #expect(error == expected, sourceLocation: sourceLocation) }
        }
        #expect(Snapshot(device) == before, sourceLocation: sourceLocation)
    }

    @Test("세션이 선 뒤의 transport: 변조, 재전송, 모르는 index, 만료")
    func rejectedTransports() throws {
        var pair = Pair()
        try pair.establish()
        // 세션의 재전송 창과 타이머가 어느 정도 움직인 상태에서 시작한다.
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(1)).datagrams[0]
        #expect(try pair.bob.receive(first, at: t0 + .seconds(1)).ipPackets.count == 1)
        let later = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0 + .seconds(2)).datagrams[0]

        // 변조: 어느 바이트를 바꿔도 거절되고 상태는 그대로다.
        for offset in 0..<later.count {
            var tampered = later
            tampered[offset] ^= 0x01
            expectRejected(&pair.bob, tampered, at: t0 + .seconds(2))
        }
        // 이미 받은 counter의 재전송.
        expectRejected(&pair.bob, first, at: t0 + .seconds(2))
        // 모르는 receiver index.
        var unknown = later
        unknown[4] ^= 0xFF
        expectRejected(&pair.bob, unknown, at: t0 + .seconds(2))
        // 짧은 입력.
        expectRejected(&pair.bob, Array(later.prefix(31)), at: t0 + .seconds(2))
        // keypair가 만료된 뒤(`rejectAfterTime` 초과)의 정상 transport.
        expectRejected(&pair.bob, later, at: t0 + .seconds(200))

        // 거절은 정상 수신을 막지 않는다.
        #expect(try pair.bob.receive(later, at: t0 + .seconds(2)).ipPackets.count == 1)
    }

    @Test("핸드셰이크 중의 initiation·response·cookie reply: 변조, 재전송, 모르는 index")
    func rejectedHandshakeMessages() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]

        // mac2(132..<148)는 부하 상태에서만 본다.
        for offset in 0..<132 {
            var tampered = initiation
            tampered[offset] ^= 0x01
            expectRejected(&pair.bob, tampered, at: t0)
        }
        let response = try pair.bob.receive(initiation, at: t0).datagrams[0]
        // 이미 받아들인 initiation의 재전송(timestamp)과 짧은 간격의 재전송(flood).
        expectRejected(&pair.bob, initiation, at: t0 + .seconds(1), .replayed)
        expectRejected(&pair.bob, initiation, at: t0 + .milliseconds(5), .replayed)

        for offset in 0..<60 {
            var tampered = response
            tampered[offset] ^= 0x01
            expectRejected(&pair.alice, tampered, at: t0)
        }
        // 모르는 receiver를 가진 response와 cookie reply.
        var unknownResponse = response
        unknownResponse[8] ^= 0xFF
        expectRejected(&pair.alice, unknownResponse, at: t0)
        let garbageCookieReply = [3, 0, 0, 0] + (try #require(pair.alice.peers.values.first?.pendingHandshake?.localIndex)).littleEndianBytes
            + [UInt8](repeating: 7, count: 24 + 32)
        expectRejected(&pair.alice, garbageCookieReply, at: t0, .authenticationFailed)

        // response를 받아들이면 세션이 서고, 그 response의 재전송은 거절되며 상태는 그대로다.
        let transport = try pair.alice.receive(response, at: t0).datagrams[0]
        expectRejected(&pair.alice, response, at: t0 + .seconds(1), .replayed)
        // 확인 전의 next에 온 변조된 transport는 next를 current로 올리지 않는다.
        var tampered = transport
        tampered[tampered.count - 1] ^= 0x01
        expectRejected(&pair.bob, tampered, at: t0)
        #expect(try pair.bob.receive(transport, at: t0).count == 1)
    }

    @Test("응답을 기다리는 응답자에게 온 initiation: mac1만 맞춘 변조, 20ms 안의 새 initiation")
    func rejectedInitiationsWhileHandshakePending() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        // 재전송 타이머로 더 새 timestamp의 initiation을 하나 더 만든다.
        let retransmitAt = try #require(pair.alice.nextDeadline)
        let second = try #require(pair.alice.advance(to: retransmitAt).datagrams.first)
        // bob도 initiation을 보내 response를 기다리는 중이다.
        _ = try pair.bob.send(pair.packet(from: .bob), to: pair.key(.alice), at: t0)
        #expect(pair.bob.peers.values.first?.pendingHandshake != nil)

        // mac1은 맞으므로 static·timestamp 복호화까지 들어가 거절된다. 진행 중인 핸드셰이크는 그대로다.
        for offset in stride(from: 8, to: 116, by: 6) {
            var tampered = first
            tampered[offset] ^= 0x01
            expectRejected(&pair.bob, remacked(tampered, for: pair.key(.bob)), at: t0, .authenticationFailed)
        }

        #expect(try pair.bob.receive(first, at: t0).datagrams.count == 1)
        // timestamp가 더 새로워 재전송 검사는 지나지만 20ms 안이라 flood로 거절한다.
        expectRejected(&pair.bob, second, at: t0 + .milliseconds(10), .replayed)
        #expect(try pair.bob.receive(second, at: t0 + .milliseconds(30)).datagrams.count == 1)
    }

    @Test("답을 기다리는 타이머가 걸린 초기자에게 온 response: mac1만 맞춘 변조")
    func rejectedResponseWhileAwaitingReply() throws {
        var pair = Pair()
        try pair.establish()
        // 세션이 선 뒤 rekey 시각을 넘겨 보내면 데이터와 함께 새 initiation이 나간다.
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

    @Test("rekey를 거듭해도 index 표는 피어의 index와 같고, previous로 온 변조 transport는 상태를 바꾸지 않는다")
    func indexTableFollowsRotation() throws {
        var pair = Pair()
        try pair.establish()
        expectIndexTableConsistent(pair.alice)
        expectIndexTableConsistent(pair.bob)

        var now = t0
        var old: [UInt8] = []
        for _ in 0..<4 {
            // rekey 직전의 keypair로 암호화해 두고 전달하지 않은 transport.
            old = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now + .seconds(100)).datagrams[0]
            now += Constants.rekeyAfterTime + .seconds(1)
            try pair.deliver(try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: now), from: .alice, at: now)
            expectIndexTableConsistent(pair.alice)
            expectIndexTableConsistent(pair.bob)
        }

        // 그 keypair는 이제 bob의 previous 칸에 있다.
        #expect(pair.bob.peers.values.first?.keypairs.previous != nil)
        var tampered = old
        tampered[tampered.count - 1] ^= 0x01
        expectRejected(&pair.bob, tampered, at: now, .authenticationFailed)
        #expect(try pair.bob.receive(old, at: now).ipPackets.count == 1)

        // 타이머가 세션을 지운 뒤에도 표는 맞는다.
        _ = pair.alice.advance(to: now + .seconds(3600))
        _ = pair.bob.advance(to: now + .seconds(3600))
        expectIndexTableConsistent(pair.alice)
        expectIndexTableConsistent(pair.bob)

        pair.bob.removePeer(pair.key(.alice))
        #expect(pair.bob.indexTable.isEmpty)
    }

    @Test("send가 던지는 경우: 빈 패킷, 너무 큰 패킷, 모르는 피어")
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
