import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 데이터 주고받기: 양방향 전송, 지연 ACK, 재전송(RTO·fast retransmit·Karn·한도), 시퀀스 순환.
/// 계약 동작 F5, R2~R7과 시험 3·4·9.
@Suite("데이터")
struct ConnectionDataTests {
    @Test("양방향으로 200KiB씩 동시에 보내고 받은 바이트가 같다")
    func bidirectionalTransfer() throws {
        var pair = try ConnectionPair.established()
        let fromClient = patternBytes(count: 200 * 1024, seed: 1)
        let fromServer = patternBytes(count: 200 * 1024, seed: 2)
        let received = try pair.exchange(clientSends: fromClient, serverSends: fromServer)
        #expect(received.serverReceived == fromClient)
        #expect(received.clientReceived == fromServer)
        // 보내는 세그먼트의 데이터는 MSS 이하다.
        #expect(pair.clientSent.allSatisfy { $0.segment.payload.count <= 1_240 })
    }

    @Test("ISS가 2³² 근처여도 1MiB가 양방향으로 오간다(시퀀스 순환)")
    func sequenceWraparound() throws {
        var pair = try ConnectionPair.established(clientISS: 0xFFFF_F000, serverISS: 0xFFFF_FF00)
        let fromClient = patternBytes(count: 1 << 20, seed: 3)
        let fromServer = patternBytes(count: 1 << 20, seed: 4)
        let received = try pair.exchange(clientSends: fromClient, serverSends: fromServer)
        #expect(received.serverReceived == fromClient)
        #expect(received.clientReceived == fromServer)
        #expect(pair.client.sendNext == SequenceNumber(0xFFFF_F001 &+ (1 << 20)))
    }

    @Test("지연 ACK: 하나뿐인 세그먼트는 40ms 뒤에, 2×MSS가 쌓이면 곧바로")
    func delayedAcknowledgment() throws {
        var peer = try ManualPeer.established()
        #expect(peer.send(flags: [.ack], payload: patternBytes(count: 100)).segments.isEmpty)
        #expect(peer.advance(by: .milliseconds(39)).segments.isEmpty)
        let delayed = peer.advance(by: .milliseconds(1)).segments
        #expect(delayed.count == 1)
        #expect(delayed.first?.acknowledgmentNumber == peer.peerNext)

        #expect(peer.send(flags: [.ack], payload: patternBytes(count: 1_240)).segments.isEmpty)
        let immediate = peer.send(flags: [.ack], payload: patternBytes(count: 1_240)).segments
        #expect(immediate.count == 1)
        #expect(immediate.first?.acknowledgmentNumber == peer.peerNext)
        #expect(peer.connection.nextDeadline.map { $0 > peer.now + .seconds(60) } == true)
    }

    @Test("순서가 어긋난 세그먼트·빈 곳을 메우는 세그먼트에는 곧바로 ACK한다")
    func immediateAcknowledgmentOutOfOrder() throws {
        var peer = try ManualPeer.established()
        let base = peer.peerNext
        let ahead = peer.segment(sequence: base.advanced(by: 100), flags: [.ack], payload: patternBytes(count: 50))
        let gapACK = peer.receive(ahead).segments
        #expect(gapACK.count == 1)
        #expect(gapACK.first?.acknowledgmentNumber == base)
        let fill = peer.segment(sequence: base, flags: [.ack], payload: patternBytes(count: 100))
        let filledACK = peer.receive(fill).segments
        #expect(filledACK.count == 1)
        #expect(filledACK.first?.acknowledgmentNumber == base.advanced(by: 150))
    }

    @Test("묶음 안의 어긋난 세그먼트마다 receive가 ACK를 하나씩 낸다(RFC 5681 4.2)")
    func outOfOrderAcknowledgmentsPerSegment() throws {
        var peer = try ManualPeer.established()
        let base = peer.peerNext
        for index in 0..<3 {
            let segment = peer.segment(
                sequence: base.advanced(by: UInt32(200 + index * 100)), flags: [.ack], payload: patternBytes(count: 50))
            let acknowledgments = peer.connection.receive(segment, at: peer.now).segments
            #expect(acknowledgments.count == 1)
            #expect(acknowledgments.first?.acknowledgmentNumber == base)
        }
        // 상대는 중복 ACK 셋을 받아 fast retransmit을 한다. 묶음 끝의 advance에는 남은 ACK가 없다.
        #expect(peer.connection.advance(to: peer.now).segments.isEmpty)
        let fill = peer.segment(sequence: base, flags: [.ack], payload: patternBytes(count: 200))
        let filled = peer.connection.receive(fill, at: peer.now).segments
        #expect(filled.count == 1)
        #expect(filled.first?.acknowledgmentNumber == base.advanced(by: 250))
    }

    @Test("묶음 안의 순서대로 온 데이터는 2×MSS마다 ACK 하나로 합쳐지고 나머지는 40ms 뒤에(MUST-58·59)")
    func inOrderAcknowledgmentsCoalescePerTwoSegments() throws {
        var peer = try ManualPeer.established()
        let base = peer.peerNext
        var acknowledged: [SequenceNumber] = []
        for index in 0..<5 {
            let segment = peer.segment(
                sequence: base.advanced(by: UInt32(index * 1_240)), flags: [.ack], payload: patternBytes(count: 1_240))
            acknowledged += peer.connection.receive(segment, at: peer.now).segments.map(\.acknowledgmentNumber)
        }
        #expect(acknowledged == [base.advanced(by: 2 * 1_240), base.advanced(by: 4 * 1_240)])
        #expect(peer.connection.advance(to: peer.now).segments.isEmpty)
        let delayed = peer.connection.advance(to: peer.now + .milliseconds(40)).segments
        #expect(delayed.map(\.acknowledgmentNumber) == [base.advanced(by: 5 * 1_240)])
    }

    @Test("나가는 데이터가 있으면 ACK는 거기에 실린다")
    func piggybackedAcknowledgment() throws {
        var peer = try ManualPeer.established()
        _ = peer.connection.receive(
            peer.segment(flags: [.ack], payload: patternBytes(count: 10)), at: peer.now)
        peer.peerNext = peer.peerNext.advanced(by: 10)
        let (accepted, outputs) = peer.connection.write(patternBytes(count: 20)[...], at: peer.now)
        #expect(accepted == 20)
        #expect(outputs.segments.count == 1)
        #expect(outputs.segments.first?.acknowledgmentNumber == peer.peerNext)
        #expect(peer.connection.advance(to: peer.now + .milliseconds(40)).segments.isEmpty)
    }

    @Test("RTO가 만료되면 SND.UNA부터 다시 보낸다(200ms, 이어서 두 배)")
    func retransmissionTimeout() throws {
        var pair = try ConnectionPair.established()
        var dropped = false
        pair.drop = { side, segment in
            guard side == .client, !segment.payload.isEmpty, !dropped else { return false }
            dropped = true
            return true
        }
        let sentAt = pair.now
        // 뒤따르는 세그먼트는 둘이라 중복 ACK가 둘뿐이다(셋이면 fast retransmit이 RTO보다 먼저 다시 보낸다).
        let data = patternBytes(count: 3 * 1_240)
        _ = pair.write(data, from: .client)
        try pair.deliver()
        #expect(pair.server.readableByteCount == 0)
        try pair.run(for: .seconds(1))
        #expect(pair.read(.server) == data)
        let copies = pair.clientSent.filter { $0.segment.sequenceNumber == SequenceNumber(1_001) && !$0.segment.payload.isEmpty }
        #expect(copies.map { $0.at - sentAt } == [.zero, .milliseconds(200)])
    }

    @Test("중복 ACK 셋에 fast retransmit한다. RTO를 기다리지 않는다")
    func fastRetransmit() throws {
        var pair = try ConnectionPair.established()
        pair.batched = false
        var dropped = false
        pair.drop = { side, segment in
            guard side == .client, !segment.payload.isEmpty, !dropped else { return false }
            dropped = true
            return true
        }
        let data = patternBytes(count: 8 * 1_240)
        _ = pair.write(data, from: .client)
        try pair.deliver()
        #expect(pair.read(.server) == data)
        let copies = pair.clientSent.filter { $0.segment.sequenceNumber == SequenceNumber(1_001) && !$0.segment.payload.isEmpty }
        #expect(copies.count == 2)
        #expect(copies.allSatisfy { $0.at == copies[0].at })
        // full ACK 뒤 cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS) = min(4960, 2480)
        #expect(pair.client.congestionWindow == 2 * 1_240)
    }

    @Test("창이 바뀐 ACK는 중복 ACK가 아니다(RFC 5681 2). 같은 창이면 셋째에 fast retransmit")
    func duplicateAcknowledgmentRequiresSameWindow() throws {
        var peer = try ManualPeer.established()
        _ = peer.connection.write(patternBytes(count: 5 * 1_240)[...], at: peer.now)
        let unacknowledged = peer.connection.sendUnacknowledged
        var retransmissions = 0
        for window: UInt16 in [30_000, 30_001, 30_002, 30_003] {
            retransmissions += peer.receive(
                peer.segment(acknowledgment: unacknowledged, flags: [.ack], window: window)
            ).segments.filter { $0.sequenceNumber == unacknowledged }.count
        }
        #expect(retransmissions == 0)
        for _ in 0..<3 {
            retransmissions += peer.receive(
                peer.segment(acknowledgment: unacknowledged, flags: [.ack], window: 30_003)
            ).segments.filter { $0.sequenceNumber == unacknowledged }.count
        }
        #expect(retransmissions == 1)
    }

    @Test("Karn: 재전송한 세그먼트의 ACK로 RTT를 재지 않아 물러난 RTO가 남는다")
    func karn() throws {
        var pair = try ConnectionPair.established()
        var dropped = false
        pair.drop = { side, segment in
            guard side == .client, !segment.payload.isEmpty, !dropped else { return false }
            dropped = true
            return true
        }
        #expect(pair.client.retransmissionTimeout == .milliseconds(200))
        _ = pair.write(patternBytes(count: 100), from: .client)
        try pair.run(for: .milliseconds(300))
        #expect(pair.server.readableByteCount == 100)
        #expect(pair.client.retransmissionTimeout == .milliseconds(400))
        #expect(pair.client.roundTripSample == nil)
    }

    @Test("확인 없이 15번 다시 보내면 .timedOut. RTO 상한 120초로 924.6초에 끝난다")
    func dataRetransmissionLimit() throws {
        var pair = try ConnectionPair.established()
        pair.drop = { side, _ in side == .client }
        let start = pair.now
        _ = pair.write(patternBytes(count: 100), from: .client)
        try pair.run(for: .seconds(1_000))
        let dataSegments = pair.clientSent.filter { !$0.segment.payload.isEmpty }
        #expect(dataSegments.count == 16)
        #expect(pair.clientEvents.last == .closed(.timedOut))
        let lastRetransmission = try #require(dataSegments.last).at - start
        #expect(lastRetransmission == .milliseconds(804_600))
        #expect(pair.client.state == .closed)
    }

    @Test("유휴가 RTO보다 길었으면 cwnd를 초기 창으로 줄인다(RFC 5681 4.1)")
    func restartAfterIdle() throws {
        var pair = try ConnectionPair.established()
        _ = try pair.exchange(clientSends: patternBytes(count: 100_000), serverSends: [])
        #expect(pair.client.congestionWindow > 12_400)
        try pair.run(for: .seconds(5))
        _ = pair.write(patternBytes(count: 10), from: .client)
        #expect(pair.client.congestionWindow == 12_400)
    }

    @Test(".readable은 읽을 것이 없다가 생길 때, .writable은 버퍼가 찼다가 자리가 날 때 나온다")
    func readableAndWritableEvents() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 100), from: .client)
        _ = pair.write(patternBytes(count: 100), from: .client)
        try pair.deliver()
        try pair.run(for: .milliseconds(100))
        #expect(pair.serverEvents.filter { $0 == .readable }.count == 1)
        let big = patternBytes(count: 300 * 1024)
        let accepted = pair.write(big, from: .client)
        #expect(accepted == 256 * 1024)
        #expect(!pair.clientEvents.contains(.writable))
        try pair.run(for: .milliseconds(100))
        #expect(pair.clientEvents.contains(.writable))
    }
}
