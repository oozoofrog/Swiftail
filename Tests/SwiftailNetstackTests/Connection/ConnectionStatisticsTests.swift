import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Connection close statistics (contract "Connection Close Statistics Log"): a lossless transfer, one RTO, one fast retransmit, the count of received SACK options,
/// and the values carried by the stack's `.closed`.
@Suite("Connection close statistics")
struct ConnectionStatisticsTests {
    /// Drops only the first data segment (sequence number 1001) of the connected pair once.
    private func dropFirstDataSegment(_ pair: inout ConnectionPair) {
        var dropped = false
        pair.drop = { side, segment in
            guard side == .client, !segment.payload.isEmpty, !dropped else { return false }
            dropped = true
            return true
        }
    }

    @Test("Lossless transfer: counts only sent bytes, with zero retransmissions and loss signals")
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
        // The receive-only side sent nothing.
        #expect(pair.server.statistics.sentBytes == 0)
        #expect(pair.server.statistics.maximumCongestionWindow
            == NewRenoCongestionControl.initialWindow(maximumSegmentSize: 1_240))
    }

    @Test("One RTO: expiration after two ACKs carrying SACK, with one segment retransmitted")
    func retransmissionTimeout() throws {
        var pair = try ConnectionPair.established()
        dropFirstDataSegment(&pair)
        // Two segments follow, so there are two ACKs carrying SACK (too few for fast retransmit). The first has a different window from the immediately preceding
        // ACK (SYN-ACK, unscaled window field), so it is not a duplicate ACK (RFC 5681 2). That leaves one duplicate ACK.
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

    @Test("One fast retransmit: seven ACKs carrying SACK, six duplicate ACKs (the first is excluded because its window differs), and no RTO")
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

    @Test("Counts ACKs carrying a SACK option, even when SACK was not negotiated")
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

    @Test("The stack's .closed carries statistics at the time the connection ends")
    func stackReportsStatistics() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        #expect(pair.write(patternBytes(count: 5_000), to: ids.client, from: .client) == 5_000)
        try pair.deliver()
        let events = pair.client.abort(ids.client, at: pair.now).events
        guard case .closed(ids.client, .aborted, let statistics) = events.last else {
            Issue.record("No close event: \(events)")
            return
        }
        #expect(statistics.sentBytes == 5_000)
        #expect(statistics.retransmittedBytes == 0)
        #expect(statistics.sackPermitted)
    }
}
