import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 연결 종료 통계(계약 "연결 종료 통계 로그"): 손실 없는 전송, RTO 한 번, fast retransmit 한 번, 받은 SACK 옵션의 수,
/// 스택의 `.closed`에 실리는 값.
@Suite("연결 종료 통계")
struct ConnectionStatisticsTests {
    /// 맞붙인 연결의 첫 데이터 세그먼트(번호 1001)만 한 번 잃게 한다.
    private func dropFirstDataSegment(_ pair: inout ConnectionPair) {
        var dropped = false
        pair.drop = { side, segment in
            guard side == .client, !segment.payload.isEmpty, !dropped else { return false }
            dropped = true
            return true
        }
    }

    @Test("손실 없는 전송: 보낸 바이트만 세고 다시 보낸 것·손실 신호는 0이다")
    func lossless() throws {
        var pair = try ConnectionPair.established()
        let data = patternBytes(count: 100 * 1_024)
        let (_, received) = try pair.exchange(clientSends: data, serverSends: [])
        #expect(received == data)
        let statistics = pair.client.statistics
        #expect(statistics.sentBytes == data.count)
        #expect(statistics.retransmittedBytes == 0)
        #expect(statistics.retransmissionTimeouts == 0)
        #expect(statistics.fastRetransmits == 0)
        #expect(statistics.partialAcknowledgmentRetransmits == 0)
        #expect(statistics.duplicateAcknowledgments == 0)
        #expect(statistics.acknowledgmentsWithSACK == 0)
        #expect(statistics.slowStartThresholdReductions == 0)
        #expect(statistics.sackPermitted)
        #expect(statistics.maximumCongestionWindow > NewRenoCongestionControl.initialWindow(maximumSegmentSize: 1_240))
        // 받기만 한 쪽은 보낸 것이 없다.
        #expect(pair.server.statistics.sentBytes == 0)
        #expect(pair.server.statistics.maximumCongestionWindow
            == NewRenoCongestionControl.initialWindow(maximumSegmentSize: 1_240))
    }

    @Test("RTO 한 번: SACK 실린 ACK 둘 뒤 만료, 한 세그먼트를 다시 보낸다")
    func retransmissionTimeout() throws {
        var pair = try ConnectionPair.established()
        dropFirstDataSegment(&pair)
        // 뒤따르는 세그먼트가 둘이라 SACK 실린 ACK도 둘이다(fast retransmit에 못 미친다). 그 가운데 첫째는 직전에 받은
        // ACK(SYN-ACK, 창 확장 전의 창 필드)와 창이 달라 중복 ACK가 아니다(RFC 5681 2). 그래서 중복 ACK는 하나다.
        let data = patternBytes(count: 3 * 1_240)
        _ = pair.write(data, from: .client)
        try pair.run(for: .seconds(1))
        #expect(pair.read(.server) == data)
        let statistics = pair.client.statistics
        #expect(statistics.sentBytes == data.count)
        #expect(statistics.retransmittedBytes == 1_240)
        #expect(statistics.retransmissionTimeouts == 1)
        #expect(statistics.fastRetransmits == 0)
        #expect(statistics.duplicateAcknowledgments == 1)
        #expect(statistics.acknowledgmentsWithSACK == 2)
        #expect(statistics.slowStartThresholdReductions == 1)
    }

    @Test("fast retransmit 한 번: SACK 실린 ACK 일곱, 중복 ACK 여섯(첫째는 창이 달라 빠진다), RTO 없음")
    func fastRetransmit() throws {
        var pair = try ConnectionPair.established()
        pair.batched = false
        dropFirstDataSegment(&pair)
        let data = patternBytes(count: 8 * 1_240)
        _ = pair.write(data, from: .client)
        try pair.deliver()
        #expect(pair.read(.server) == data)
        let statistics = pair.client.statistics
        #expect(statistics.sentBytes == data.count)
        #expect(statistics.retransmittedBytes == 1_240)
        #expect(statistics.retransmissionTimeouts == 0)
        #expect(statistics.fastRetransmits == 1)
        #expect(statistics.partialAcknowledgmentRetransmits == 0)
        #expect(statistics.duplicateAcknowledgments == 6)
        #expect(statistics.acknowledgmentsWithSACK == 7)
        #expect(statistics.slowStartThresholdReductions == 1)
    }

    @Test("SACK 옵션이 실린 ACK를 센다. SACK을 협상하지 않았어도 온 것은 센다")
    func receivedSACKOptions() throws {
        var peer = try ManualPeer.established()
        #expect(!peer.connection.statistics.sackPermitted)
        _ = peer.connection.write(patternBytes(count: 4 * 1_240)[...], at: peer.now)
        let unacknowledged = peer.connection.sendUnacknowledged
        let block = TCPSegment.SACKBlock(
            leftEdge: unacknowledged.advanced(by: 1_240), rightEdge: unacknowledged.advanced(by: 2_480))
        var withSACK = peer.segment(acknowledgment: unacknowledged, flags: [.ack])
        withSACK.sackBlocks = [block]
        _ = peer.receive(try withSACK.roundTripped())
        _ = peer.receive(try withSACK.roundTripped())
        _ = peer.receive(try peer.segment(acknowledgment: unacknowledged, flags: [.ack]).roundTripped())
        #expect(peer.connection.statistics.acknowledgmentsWithSACK == 2)
        #expect(peer.connection.statistics.duplicateAcknowledgments == 3)
        #expect(peer.connection.statistics.fastRetransmits == 1)
    }

    @Test("스택의 .closed는 끝날 때의 통계를 싣는다")
    func stackReportsStatistics() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        #expect(pair.write(patternBytes(count: 5_000), to: ids.client, from: .client) == 5_000)
        try pair.deliver()
        let events = pair.client.abort(ids.client, at: pair.now).events
        guard case .closed(ids.client, .aborted, let statistics) = events.last else {
            Issue.record("끝난 사건이 없다: \(events)")
            return
        }
        #expect(statistics.sentBytes == 5_000)
        #expect(statistics.retransmittedBytes == 0)
        #expect(statistics.sackPermitted)
    }
}
