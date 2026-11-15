import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 받는 쪽 SACK: SACK-Permitted 협상과 ACK에 싣는 SACK 블록(RFC 2018 2·4·7, 계약 동작 T3·T4·T5, F5 아래 "SACK 블록").
@Suite("받는 쪽 SACK")
struct ConnectionSACKTests {
    /// 상대가 보내는 데이터 세그먼트 하나의 크기(RFC 2018 7의 예와 같다).
    private static let segmentSize = 500

    /// 수동 열기로 맺어진 연결. 상대의 SYN에 SACK-Permitted를 실을지 고른다. 상대의 첫 데이터 번호는 5000이고(RFC 2018 7),
    /// 상대가 광고하는 창 필드는 `window`(shift 3)다.
    private func passivePeer(permitsSACK: Bool, window: UInt16 = 8_192) throws -> ManualPeer {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server,
            sequenceNumber: SequenceNumber(4_999), flags: [.syn], window: 65_535,
            maximumSegmentSize: 1_240, windowScale: 3, sackPermitted: permitsSACK)
        let (connection, outputs) = try TCPConnection.accept(
            syn.roundTripped(), initialSequenceNumber: SequenceNumber(70_000), at: start)
        let synAck = try #require(outputs.segments.first)
        #expect(synAck.sackPermitted == permitsSACK, "SYN-ACK의 SACK-Permitted는 상대 SYN을 따른다")
        #expect(try synAck.roundTripped() == synAck)
        var peer = ManualPeer(connection: connection, now: start, peerNext: SequenceNumber(5_000))
        peer.peerWindow = window
        let established = peer.send(flags: [.ack])
        #expect(established.events == [.established])
        return peer
    }

    /// 상대가 `index`번째(0부터) 500바이트 세그먼트를 보낸다. 번호는 `5000 + 500 × index`다(RFC 2018 7).
    private func dataSegment(_ peer: ManualPeer, index: Int) -> TCPSegment {
        peer.segment(
            sequence: SequenceNumber(5_000).advanced(by: UInt32(index * Self.segmentSize)), flags: [.ack],
            payload: patternBytes(count: Self.segmentSize, seed: UInt8(index)))
    }

    /// 세그먼트를 넣고 그 출력의 마지막 ACK를 IP 패킷으로 만들었다가 다시 해석해 돌려준다(코덱도 함께 거친다).
    private func acknowledgment(
        after segment: TCPSegment, into peer: inout ManualPeer
    ) throws -> TCPSegment {
        let outputs = peer.receive(try segment.roundTripped())
        return try #require(outputs.segments.last).roundTripped()
    }

    private func blocks(_ pairs: [(UInt32, UInt32)]) -> [TCPSegment.SACKBlock] {
        pairs.map { TCPSegment.SACKBlock(leftEdge: SequenceNumber($0.0), rightEdge: SequenceNumber($0.1)) }
    }

    // MARK: - 협상

    @Test("능동 열기: SYN은 늘 SACK-Permitted를 싣고, 다시 보낸 SYN도 같다. SYN-ACK에 있을 때만 블록을 보낸다", arguments: [true, false])
    func activeNegotiation(peerPermits: Bool) throws {
        let start = ContinuousClock.now
        let opened = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(10_000),
            at: start)
        var connection = opened.connection
        let syn = try #require(opened.outputs.segments.first)
        #expect(syn.sackPermitted)
        #expect(syn.maximumSegmentSize == 1_240 && syn.windowScale == 3)
        #expect(syn.ipPacket().map { $0.count } == 20 + 20 + 12, "옵션 12바이트: MSS 4 + SACK-Permitted 4 + Window Scale 4")
        let retransmitted = try #require(connection.advance(to: start + .seconds(1)).segments.first)
        #expect(retransmitted == syn)

        let synAck = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(4_999),
            acknowledgmentNumber: SequenceNumber(10_001), flags: [.syn, .ack], window: 65_535,
            maximumSegmentSize: 1_240, windowScale: 3, sackPermitted: peerPermits)
        _ = connection.receive(try synAck.roundTripped(), at: start + .seconds(2))
        #expect(connection.state == .established)
        #expect(connection.peerPermitsSACK == peerPermits)

        // 빈 곳 너머의 데이터: 상대가 허용했을 때만 SACK이 실린다.
        let outOfOrder = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(5_500),
            acknowledgmentNumber: SequenceNumber(10_001), flags: [.ack], window: 8_192, payload: patternBytes(count: 500))
        let ack = try #require(connection.receive(outOfOrder, at: start + .seconds(2)).segments.last)
        #expect(ack.acknowledgmentNumber == SequenceNumber(5_000))
        #expect(ack.sackBlocks == (peerPermits ? blocks([(5_500, 6_000)]) : []))
    }

    @Test("수동 열기: 상대 SYN에 SACK-Permitted가 있을 때만 SYN-ACK(다시 보낸 것도)에 싣는다", arguments: [true, false])
    func passiveNegotiation(peerPermits: Bool) throws {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(4_999),
            flags: [.syn], window: 65_535, maximumSegmentSize: 1_240, windowScale: 3, sackPermitted: peerPermits)
        let accepted = try TCPConnection.accept(
            syn.roundTripped(), initialSequenceNumber: SequenceNumber(70_000), at: start)
        var connection = accepted.connection
        let synAck = try #require(accepted.outputs.segments.first)
        #expect(synAck.sackPermitted == peerPermits)
        #expect(connection.peerPermitsSACK == peerPermits)
        let retransmitted = try #require(connection.advance(to: start + .seconds(1)).segments.first)
        #expect(retransmitted == synAck)
    }

    @Test("Swift 연결 둘을 맞붙이면 양쪽 모두 SACK을 쓴다")
    func bothSidesNegotiate() throws {
        let pair = try ConnectionPair.established()
        #expect(pair.client.peerPermitsSACK)
        #expect(pair.server.peerPermitsSACK)
    }

    @Test("상대가 SACK-Permitted를 보내지 않았으면 빈 곳이 여럿이어도 어떤 ACK에도 블록을 싣지 않는다")
    func neverWithoutPermission() throws {
        var peer = try passivePeer(permitsSACK: false)
        var sent: [TCPSegment] = []
        for index in [1, 3, 5, 7, 2] {
            sent += peer.receive(try dataSegment(peer, index: index).roundTripped()).segments
        }
        // 데이터를 보내게 해 데이터에 실린 ACK도 본다.
        sent += peer.connection.write(patternBytes(count: 4_000)[...], at: peer.now).outputs.segments
        sent += peer.advance(by: .seconds(1)).segments
        #expect(!sent.isEmpty)
        #expect(sent.allSatisfy { $0.sackBlocks.isEmpty })
        #expect(sent.map(\.payload.count).max() == 1_240, "SACK이 없으면 데이터 세그먼트는 MSS를 꽉 채운다")
        #expect(try sent.allSatisfy { try $0.roundTripped().sackBlocks.isEmpty })
    }

    // MARK: - 블록 순서 (RFC 2018 7)

    @Test("RFC 2018 7 Case 1: 앞의 4개만 받으면 ACK 7000에 SACK이 없다")
    func rfcCase1() throws {
        var peer = try passivePeer(permitsSACK: true)
        var sent: [TCPSegment] = []
        for index in 0..<4 {
            sent += peer.receive(try dataSegment(peer, index: index).roundTripped()).segments
        }
        // 순서대로 온 2000바이트(2×MSS 미만)의 ACK는 지연 ACK 기한에 나간다.
        sent += peer.advance(by: .milliseconds(40)).segments
        #expect(sent.allSatisfy { $0.sackBlocks.isEmpty })
        let ack = try #require(sent.last).roundTripped()
        #expect(ack.acknowledgmentNumber == SequenceNumber(7_000))
        #expect(ack.sackBlocks.isEmpty)
    }

    @Test("RFC 2018 7 Case 2: 첫 세그먼트를 잃으면 뒤의 7개마다 ACK 5000과 블록 하나가 자란다")
    func rfcCase2() throws {
        var peer = try passivePeer(permitsSACK: true)
        for index in 1..<8 {
            let ack = try acknowledgment(after: dataSegment(peer, index: index), into: &peer)
            #expect(ack.acknowledgmentNumber == SequenceNumber(5_000), "세그먼트 \(5_000 + 500 * index)")
            #expect(ack.sackBlocks == blocks([(5_500, UInt32(6_000 + 500 * (index - 1)))]), "세그먼트 \(5_000 + 500 * index)")
        }
    }

    @Test("RFC 2018 7 Case 3: 2·4·6·8번째를 잃고, 4번째와 2번째가 늦게 온다. 첫 블록은 이 ACK를 일으킨 세그먼트의 구간이다")
    func rfcCase3() throws {
        var peer = try passivePeer(permitsSACK: true)
        // 5000: 순서대로라 SACK이 없다(ACK는 지연 ACK 기한에 나간다).
        _ = peer.receive(try dataSegment(peer, index: 0).roundTripped())
        #expect(peer.connection.receiveNext == SequenceNumber(5_500))

        let table: [(index: Int, expected: [(UInt32, UInt32)])] = [
            (2, [(6_000, 6_500)]),
            (4, [(7_000, 7_500), (6_000, 6_500)]),
            (6, [(8_000, 8_500), (7_000, 7_500), (6_000, 6_500)]),
        ]
        for row in table {
            let ack = try acknowledgment(after: dataSegment(peer, index: row.index), into: &peer)
            #expect(ack.acknowledgmentNumber == SequenceNumber(5_500), "세그먼트 \(5_000 + 500 * row.index)")
            #expect(ack.sackBlocks == blocks(row.expected), "세그먼트 \(5_000 + 500 * row.index)")
        }

        // 4번째(6500)가 늦게 온다: 6000–7500이 합쳐져 첫 블록이 되고, 그 부분 집합인 옛 블록은 다시 나오지 않는다.
        let fourth = try acknowledgment(after: dataSegment(peer, index: 3), into: &peer)
        #expect(fourth.acknowledgmentNumber == SequenceNumber(5_500))
        #expect(fourth.sackBlocks == blocks([(6_000, 7_500), (8_000, 8_500)]))

        // 2번째(5500)가 온다: ACK가 7500으로 나아가고(첫 블록 규칙의 예외) 남은 블록 하나다.
        let second = try acknowledgment(after: dataSegment(peer, index: 1), into: &peer)
        #expect(second.acknowledgmentNumber == SequenceNumber(7_500))
        #expect(second.sackBlocks == blocks([(8_000, 8_500)]))

        // 마지막 빈 곳(7500)이 메워지면 SACK이 사라진다.
        let filled = try acknowledgment(after: dataSegment(peer, index: 5), into: &peer)
        #expect(filled.acknowledgmentNumber == SequenceNumber(8_500))
        #expect(filled.sackBlocks.isEmpty)
    }

    @Test("이미 받아 둔 구간 안의 세그먼트가 다시 오면 그 구간이 첫 블록이 된다")
    func duplicateMovesBlockFirst() throws {
        var peer = try passivePeer(permitsSACK: true)
        _ = peer.receive(try dataSegment(peer, index: 2).roundTripped())
        _ = peer.receive(try dataSegment(peer, index: 4).roundTripped())
        let again = try acknowledgment(after: dataSegment(peer, index: 2), into: &peer)
        #expect(again.sackBlocks == blocks([(6_000, 6_500), (7_000, 7_500)]))
    }

    // MARK: - 한도와 데이터에 실린 ACK

    @Test("빈 곳 너머의 구간이 6개여도 블록은 최근 것 4개다(옵션 공간 40바이트, RFC 2018 3)")
    func atMostFourBlocks() throws {
        var peer = try passivePeer(permitsSACK: true)
        var last: TCPSegment?
        for index in [1, 3, 5, 7, 9, 11] {
            last = try acknowledgment(after: dataSegment(peer, index: index), into: &peer)
        }
        let ack = try #require(last)
        #expect(ack.sackBlocks == blocks([(10_500, 11_000), (9_500, 10_000), (8_500, 9_000), (7_500, 8_000)]))
        #expect(ack.ipPacket().map { $0.count } == 20 + 20 + 36)
        #expect(peer.connection.receiveBuffer.outOfOrderRangeCount == 6)
    }

    @Test("데이터에 실린 ACK에도 SACK이 실리고, 그만큼 데이터를 줄여 IP 패킷이 1280바이트를 넘지 않는다", arguments: [1, 4])
    func dataSegmentsCarrySACK(gaps: Int) throws {
        var peer = try passivePeer(permitsSACK: true, window: 65_535)
        // 응용이 큰 데이터를 쓴다. 빈 곳이 없으니 세그먼트는 MSS를 꽉 채운다.
        let written = peer.connection.write(patternBytes(count: 100_000)[...], at: peer.now)
        let first = written.outputs.segments.filter { !$0.payload.isEmpty }
        #expect(!first.isEmpty)
        #expect(first.allSatisfy { $0.payload.count == 1_240 && $0.sackBlocks.isEmpty })

        // 빈 곳 너머의 데이터를 받는 사이에, 상대가 앞의 세그먼트를 확인해 cwnd가 열린다.
        var carried: [TCPSegment] = []
        for gap in 0..<gaps {
            let acknowledgment = peer.connection.sendUnacknowledged.advanced(by: 1_240)
            let segment = peer.segment(
                sequence: SequenceNumber(5_000).advanced(by: UInt32((2 * gap + 1) * Self.segmentSize)),
                acknowledgment: acknowledgment, flags: [.ack], payload: patternBytes(count: Self.segmentSize))
            carried += peer.receive(try segment.roundTripped()).segments.filter { !$0.payload.isEmpty }
        }
        let limit = 1_240 - (4 + 8 * gaps)
        let last = try #require(carried.last)
        #expect(last.sackBlocks.count == gaps)
        #expect(last.payload.count == limit, "SACK 블록 \(gaps)개: 데이터 \(limit)바이트")
        for segment in carried {
            #expect(!segment.sackBlocks.isEmpty)
            #expect(segment.payload.count <= 1_240 - TCPSegment.sackOptionLength(blockCount: segment.sackBlocks.count))
            let packet = try #require(segment.ipPacket())
            #expect(packet.count <= 1_280, "IP 패킷 \(packet.count)바이트")
            #expect(try TCPSegment(parsingIPPacket: packet) == segment)
        }
    }

    /// 고치기 전에는 ACK를 처리하는 자리에서 곧바로 다시 보내, 같은 세그먼트에 실려 온 데이터가 받는 버퍼에 들어가기 전의 블록을
    /// 실었다.
    @Test("partial ACK에 데이터가 함께 오면, 그 ACK가 일으킨 재전송의 첫 블록은 방금 받은 데이터의 구간이다")
    func retransmissionCarriesBlockOfTriggeringSegment() throws {
        var peer = try passivePeer(permitsSACK: true)
        _ = peer.connection.write(patternBytes(count: 8 * 1_240)[...], at: peer.now)
        let unacknowledged = peer.connection.sendUnacknowledged

        // 받는 쪽에 빈 곳 너머의 구간 하나([6000, 6500))를 만든다. 이 쪽 데이터는 확인하지 않는다.
        let ahead = peer.segment(
            sequence: SequenceNumber(6_000), acknowledgment: unacknowledged, flags: [.ack],
            payload: patternBytes(count: Self.segmentSize))
        _ = peer.connection.receive(ahead, at: peer.now)
        // 중복 ACK 셋으로 fast recovery에 들어간다.
        for _ in 0..<3 {
            _ = peer.connection.receive(peer.segment(acknowledgment: unacknowledged, flags: [.ack]), at: peer.now)
        }

        // 첫 세그먼트만 확인하는 partial ACK가 새 구간 [7000, 7500)의 데이터를 싣고 온다.
        let partial = peer.segment(
            sequence: SequenceNumber(7_000), acknowledgment: unacknowledged.advanced(by: 1_240), flags: [.ack],
            payload: patternBytes(count: Self.segmentSize))
        let outputs = peer.connection.receive(partial, at: peer.now)
        let retransmission = try #require(outputs.segments.first { !$0.payload.isEmpty })
        #expect(retransmission.sequenceNumber == unacknowledged.advanced(by: 1_240))
        #expect(retransmission.sackBlocks == blocks([(7_000, 7_500), (6_000, 6_500)]))
        // 블록 둘(옵션 20바이트)만큼 데이터를 줄여 1280바이트를 넘지 않는다.
        #expect(retransmission.payload.count == 1_240 - 20)
        #expect(try #require(retransmission.ipPacket()).count <= 1_280)
    }

    @Test("Swift 연결 둘 사이에서 세그먼트를 잃어도 SACK이 실린 세그먼트가 1280바이트를 넘지 않고 데이터가 다 간다")
    func pairWithLossStaysWithinMTU() throws {
        var pair = try ConnectionPair.established()
        var dropped = 0
        pair.drop = { _, segment in
            guard !segment.payload.isEmpty else { return false }
            dropped += 1
            return dropped % 7 == 3
        }
        let clientData = patternBytes(count: 200_000, seed: 1)
        let serverData = patternBytes(count: 200_000, seed: 2)
        let received = try pair.exchange(clientSends: clientData, serverSends: serverData)
        #expect(received.serverReceived == clientData)
        #expect(received.clientReceived == serverData)
        let all = (pair.clientSent + pair.serverSent).map(\.segment)
        #expect(all.contains { !$0.sackBlocks.isEmpty && !$0.payload.isEmpty }, "데이터에 실린 SACK이 한 번은 나와야 한다")
        for segment in all {
            let packet = try #require(segment.ipPacket())
            #expect(packet.count <= 1_280)
        }
    }
}
