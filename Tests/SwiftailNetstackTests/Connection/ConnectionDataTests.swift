import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Data exchange: bidirectional transfer, delayed ACKs, retransmission (RTO, fast retransmit, Karn, limit), and sequence wraparound.
/// Contract behaviors F5, R2~R7, and tests 3·4·9.
@Suite("Data")
struct ConnectionDataTests {
    @Test("Simultaneously sends 200KiB in each direction and receives matching bytes")
    func bidirectionalTransfer() throws {
        var pair = try ConnectionPair.established()
        let fromClient = patternBytes(count: 200 * 1024, seed: 1)
        let fromServer = patternBytes(count: 200 * 1024, seed: 2)
        let received = try pair.exchange(clientSends: fromClient, serverSends: fromServer)
        #expect(received.serverReceived == fromClient)
        #expect(received.clientReceived == fromServer)
        // The data in a sent segment is at most MSS.
        #expect(pair.clientSent.allSatisfy { $0.segment.payload.count <= 1_240 })
    }

    @Test("Transfers 1MiB in each direction even with ISS near 2³² (sequence wraparound)")
    func sequenceWraparound() throws {
        var pair = try ConnectionPair.established(clientISS: 0xFFFF_F000, serverISS: 0xFFFF_FF00)
        let fromClient = patternBytes(count: 1 << 20, seed: 3)
        let fromServer = patternBytes(count: 1 << 20, seed: 4)
        let received = try pair.exchange(clientSends: fromClient, serverSends: fromServer)
        #expect(received.serverReceived == fromClient)
        #expect(received.clientReceived == fromServer)
        #expect(pair.client.sendNext == SequenceNumber(0xFFFF_F001 &+ (1 << 20)))
    }

    @Test("Delayed ACK: after 40ms for a lone segment, immediately once 2×MSS accumulates")
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

    @Test("Immediately acknowledges out-of-order segments and segments that fill a gap")
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

    @Test("receive emits one ACK for each out-of-order segment in a batch (RFC 5681 4.2)")
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
        // The peer receives three duplicate ACKs and performs fast retransmit. advance at the end of the batch has no ACK left.
        #expect(peer.connection.advance(to: peer.now).segments.isEmpty)
        let fill = peer.segment(sequence: base, flags: [.ack], payload: patternBytes(count: 200))
        let filled = peer.connection.receive(fill, at: peer.now).segments
        #expect(filled.count == 1)
        #expect(filled.first?.acknowledgmentNumber == base.advanced(by: 250))
    }

    @Test("In-order data in a batch is acknowledged once per 2×MSS, with the remainder acknowledged after 40ms (MUST-58·59)")
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

    @Test("Piggybacks the ACK when there is outgoing data")
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

    @Test("Retransmits from SND.UNA when RTO expires (200ms, then doubles)")
    func retransmissionTimeout() throws {
        var pair = try ConnectionPair.established()
        var dropped = false
        pair.drop = { side, segment in
            guard side == .client, !segment.payload.isEmpty, !dropped else { return false }
            dropped = true
            return true
        }
        let sentAt = pair.now
        // Only two segments follow, so there are only two duplicate ACKs (three would trigger fast retransmit before RTO).
        let data = patternBytes(count: 3 * 1_240)
        _ = pair.write(data, from: .client)
        try pair.deliver()
        #expect(pair.server.readableByteCount == 0)
        try pair.run(for: .seconds(1))
        #expect(pair.read(.server) == data)
        let copies = pair.clientSent.filter { $0.segment.sequenceNumber == SequenceNumber(1_001) && !$0.segment.payload.isEmpty }
        #expect(copies.map { $0.at - sentAt } == [.zero, .milliseconds(200)])
    }

    @Test("Three duplicate ACKs trigger fast retransmit without waiting for RTO")
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
        // After a full ACK, cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS) = min(4960, 2480)
        #expect(pair.client.congestionWindow == 2 * 1_240)
    }

    @Test("An ACK with a changed window is not a duplicate ACK (RFC 5681 2). With the same window, the third triggers fast retransmit")
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

    @Test("Karn: ACKs for retransmitted segments do not provide RTT samples, so the backed-off RTO remains")
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

    @Test("After 15 retransmissions without acknowledgment, yields .timedOut. With the 120-second RTO cap, it ends at 924.6 seconds")
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

    @Test("If idle longer than RTO, reduces cwnd to the initial window (RFC 5681 4.1)")
    func restartAfterIdle() throws {
        var pair = try ConnectionPair.established()
        _ = try pair.exchange(clientSends: patternBytes(count: 100_000), serverSends: [])
        #expect(pair.client.congestionWindow > 12_400)
        try pair.run(for: .seconds(5))
        _ = pair.write(patternBytes(count: 10), from: .client)
        #expect(pair.client.congestionWindow == 12_400)
    }

    @Test("Emits .readable when data first becomes available to read and .writable when space opens in a previously full buffer")
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
