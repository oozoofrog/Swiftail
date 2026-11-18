import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Receiver SACK: SACK-Permitted negotiation and SACK blocks carried in ACKs (RFC 2018 2·4·7, contract behaviors T3·T4·T5, "SACK Blocks" under F5).
@Suite("Receiver SACK")
struct ConnectionSACKTests {
    /// Size of one data segment from the peer (as in the RFC 2018 7 example).
    private static let segmentSize = 500

    /// A connection established by passive open. Chooses whether to include SACK-Permitted in the peer's SYN. The peer's first data sequence number is 5000 (RFC 2018 7),
    /// and its advertised window field is `window` (shift 3).
    private func passivePeer(permitsSACK: Bool, window: UInt16 = 8_192) throws -> ManualPeer {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server,
            sequenceNumber: SequenceNumber(4_999), flags: [.syn], window: 65_535,
            maximumSegmentSize: 1_240, windowScale: 3, sackPermitted: permitsSACK)
        let (connection, outputs) = try TCPConnection.accept(
            syn.roundTripped(), initialSequenceNumber: SequenceNumber(70_000), at: start)
        let synAck = try #require(outputs.segments.first)
        #expect(synAck.sackPermitted == permitsSACK, "The SYN-ACK's SACK-Permitted follows the peer's SYN")
        #expect(try synAck.roundTripped() == synAck)
        var peer = ManualPeer(connection: connection, now: start, peerNext: SequenceNumber(5_000))
        peer.peerWindow = window
        let established = peer.send(flags: [.ack])
        #expect(established.events == [.established])
        return peer
    }

    /// The peer sends the 500-byte segment at `index` (starting at 0). Its sequence number is `5000 + 500 × index` (RFC 2018 7).
    private func dataSegment(_ peer: ManualPeer, index: Int) -> TCPSegment {
        peer.segment(
            sequence: SequenceNumber(5_000).advanced(by: UInt32(index * Self.segmentSize)), flags: [.ack],
            payload: patternBytes(count: Self.segmentSize, seed: UInt8(index)))
    }

    /// Feeds a segment and returns the last ACK in its output after turning it into an IP packet and parsing it again (also exercises the codec).
    private func acknowledgment(
        after segment: TCPSegment, into peer: inout ManualPeer
    ) throws -> TCPSegment {
        let outputs = peer.receive(try segment.roundTripped())
        return try #require(outputs.segments.last).roundTripped()
    }

    private func blocks(_ pairs: [(UInt32, UInt32)]) -> [TCPSegment.SACKBlock] {
        pairs.map { TCPSegment.SACKBlock(leftEdge: SequenceNumber($0.0), rightEdge: SequenceNumber($0.1)) }
    }

    // MARK: - Negotiation

    @Test("Active open: SYN always carries SACK-Permitted, including retransmissions. Sends blocks only if SYN-ACK carries it", arguments: [true, false])
    func activeNegotiation(peerPermits: Bool) throws {
        let start = ContinuousClock.now
        let opened = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(10_000),
            at: start)
        var connection = opened.connection
        let syn = try #require(opened.outputs.segments.first)
        #expect(syn.sackPermitted)
        #expect(syn.maximumSegmentSize == 1_240 && syn.windowScale == 3)
        #expect(syn.ipPacket().map { $0.count } == 20 + 20 + 12, "12 bytes of options: MSS 4 + SACK-Permitted 4 + Window Scale 4")
        let retransmitted = try #require(connection.advance(to: start + .seconds(1)).segments.first)
        #expect(retransmitted == syn)

        let synAck = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(4_999),
            acknowledgmentNumber: SequenceNumber(10_001), flags: [.syn, .ack], window: 65_535,
            maximumSegmentSize: 1_240, windowScale: 3, sackPermitted: peerPermits)
        _ = connection.receive(try synAck.roundTripped(), at: start + .seconds(2))
        #expect(connection.state == .established)
        #expect(connection.peerPermitsSACK == peerPermits)

        // Data beyond a gap: carries SACK only if the peer permitted it.
        let outOfOrder = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(5_500),
            acknowledgmentNumber: SequenceNumber(10_001), flags: [.ack], window: 8_192, payload: patternBytes(count: 500))
        let ack = try #require(connection.receive(outOfOrder, at: start + .seconds(2)).segments.last)
        #expect(ack.acknowledgmentNumber == SequenceNumber(5_000))
        #expect(ack.sackBlocks == (peerPermits ? blocks([(5_500, 6_000)]) : []))
    }

    @Test("Passive open: includes SACK-Permitted in SYN-ACK (including retransmissions) only if the peer's SYN carries it", arguments: [true, false])
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

    @Test("Both sides use SACK when two Swift connections are paired")
    func bothSidesNegotiate() throws {
        let pair = try ConnectionPair.established()
        #expect(pair.client.peerPermitsSACK)
        #expect(pair.server.peerPermitsSACK)
    }

    @Test("If the peer did not send SACK-Permitted, no ACK carries blocks even with several gaps")
    func neverWithoutPermission() throws {
        var peer = try passivePeer(permitsSACK: false)
        var sent: [TCPSegment] = []
        for index in [1, 3, 5, 7, 2] {
            sent += peer.receive(try dataSegment(peer, index: index).roundTripped()).segments
        }
        // Make it send data and check the piggybacked ACK as well.
        sent += peer.connection.write(patternBytes(count: 4_000)[...], at: peer.now).outputs.segments
        sent += peer.advance(by: .seconds(1)).segments
        #expect(!sent.isEmpty)
        #expect(sent.allSatisfy { $0.sackBlocks.isEmpty })
        #expect(sent.map(\.payload.count).max() == 1_240, "Without SACK, data segments fill the MSS")
        #expect(try sent.allSatisfy { try $0.roundTripped().sackBlocks.isEmpty })
    }

    // MARK: - Block order (RFC 2018 7)

    @Test("RFC 2018 7 Case 1: receiving only the first 4 segments produces ACK 7000 without SACK")
    func rfcCase1() throws {
        var peer = try passivePeer(permitsSACK: true)
        var sent: [TCPSegment] = []
        for index in 0..<4 {
            sent += peer.receive(try dataSegment(peer, index: index).roundTripped()).segments
        }
        // The ACK for 2000 in-order bytes (less than 2×MSS) goes out at the delayed ACK deadline.
        sent += peer.advance(by: .milliseconds(40)).segments
        #expect(sent.allSatisfy { $0.sackBlocks.isEmpty })
        let ack = try #require(sent.last).roundTripped()
        #expect(ack.acknowledgmentNumber == SequenceNumber(7_000))
        #expect(ack.sackBlocks.isEmpty)
    }

    @Test("RFC 2018 7 Case 2: losing the first segment produces ACK 5000 and one growing block for each of the following 7 segments")
    func rfcCase2() throws {
        var peer = try passivePeer(permitsSACK: true)
        for index in 1..<8 {
            let ack = try acknowledgment(after: dataSegment(peer, index: index), into: &peer)
            #expect(ack.acknowledgmentNumber == SequenceNumber(5_000), "Segment \(5_000 + 500 * index)")
            #expect(ack.sackBlocks == blocks([(5_500, UInt32(6_000 + 500 * (index - 1)))]), "Segment \(5_000 + 500 * index)")
        }
    }

    @Test("RFC 2018 7 Case 3: segments 2·4·6·8 are lost, and the 4th and 2nd arrive late. The first block is the range of the segment that triggered this ACK")
    func rfcCase3() throws {
        var peer = try passivePeer(permitsSACK: true)
        // 5000: in order, so no SACK (the ACK goes out at the delayed ACK deadline).
        _ = peer.receive(try dataSegment(peer, index: 0).roundTripped())
        #expect(peer.connection.receiveNext == SequenceNumber(5_500))

        let table: [(index: Int, expected: [(UInt32, UInt32)])] = [
            (2, [(6_000, 6_500)]),
            (4, [(7_000, 7_500), (6_000, 6_500)]),
            (6, [(8_000, 8_500), (7_000, 7_500), (6_000, 6_500)]),
        ]
        for row in table {
            let ack = try acknowledgment(after: dataSegment(peer, index: row.index), into: &peer)
            #expect(ack.acknowledgmentNumber == SequenceNumber(5_500), "Segment \(5_000 + 500 * row.index)")
            #expect(ack.sackBlocks == blocks(row.expected), "Segment \(5_000 + 500 * row.index)")
        }

        // The 4th segment (6500) arrives late: 6000–7500 merges into the first block, and old blocks that are subsets do not appear again.
        let fourth = try acknowledgment(after: dataSegment(peer, index: 3), into: &peer)
        #expect(fourth.acknowledgmentNumber == SequenceNumber(5_500))
        #expect(fourth.sackBlocks == blocks([(6_000, 7_500), (8_000, 8_500)]))

        // The 2nd segment (5500) arrives: the ACK advances to 7500 (an exception to the first-block rule), with one block remaining.
        let second = try acknowledgment(after: dataSegment(peer, index: 1), into: &peer)
        #expect(second.acknowledgmentNumber == SequenceNumber(7_500))
        #expect(second.sackBlocks == blocks([(8_000, 8_500)]))

        // SACK disappears when the last gap (7500) is filled.
        let filled = try acknowledgment(after: dataSegment(peer, index: 5), into: &peer)
        #expect(filled.acknowledgmentNumber == SequenceNumber(8_500))
        #expect(filled.sackBlocks.isEmpty)
    }

    @Test("When a segment within an already received range arrives again, that range becomes the first block")
    func duplicateMovesBlockFirst() throws {
        var peer = try passivePeer(permitsSACK: true)
        _ = peer.receive(try dataSegment(peer, index: 2).roundTripped())
        _ = peer.receive(try dataSegment(peer, index: 4).roundTripped())
        let again = try acknowledgment(after: dataSegment(peer, index: 2), into: &peer)
        #expect(again.sackBlocks == blocks([(6_000, 6_500), (7_000, 7_500)]))
    }

    // MARK: - Limits and piggybacked ACKs

    @Test("Even with 6 ranges beyond a gap, uses the 4 most recent blocks (40 bytes of option space, RFC 2018 3)")
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

    @Test("A piggybacked ACK also carries SACK and reduces the data accordingly so the IP packet stays within 1280 bytes", arguments: [1, 4])
    func dataSegmentsCarrySACK(gaps: Int) throws {
        var peer = try passivePeer(permitsSACK: true, window: 65_535)
        // The application writes a large payload. There is no gap, so segments fill the MSS.
        let written = peer.connection.write(patternBytes(count: 100_000)[...], at: peer.now)
        let first = written.outputs.segments.filter { !$0.payload.isEmpty }
        #expect(!first.isEmpty)
        #expect(first.allSatisfy { $0.payload.count == 1_240 && $0.sackBlocks.isEmpty })

        // While data arrives beyond a gap, the peer acknowledges earlier segments and opens cwnd.
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
        #expect(last.payload.count == limit, "\(gaps) SACK blocks: \(limit) bytes of data")
        for segment in carried {
            #expect(!segment.sackBlocks.isEmpty)
            #expect(segment.payload.count <= 1_240 - TCPSegment.sackOptionLength(blockCount: segment.sackBlocks.count))
            let packet = try #require(segment.ipPacket())
            #expect(packet.count <= 1_280, "IP packet of \(packet.count) bytes")
            #expect(try TCPSegment(parsingIPPacket: packet) == segment)
        }
    }

    /// Before the fix, the ACK handler retransmitted immediately, carrying the blocks from before the receive buffer took in the data arriving in the same segment
    /// as the ACK.
    @Test("When data arrives with a partial ACK, the retransmission triggered by that ACK uses the new data's range as the first block")
    func retransmissionCarriesBlockOfTriggeringSegment() throws {
        var peer = try passivePeer(permitsSACK: true)
        _ = peer.connection.write(patternBytes(count: 8 * 1_240)[...], at: peer.now)
        let unacknowledged = peer.connection.sendUnacknowledged

        // Create one range beyond a gap ([6000, 6500)) at the receiver. Do not acknowledge this side's data.
        let ahead = peer.segment(
            sequence: SequenceNumber(6_000), acknowledgment: unacknowledged, flags: [.ack],
            payload: patternBytes(count: Self.segmentSize))
        _ = peer.connection.receive(ahead, at: peer.now)
        // Three duplicate ACKs enter fast recovery.
        for _ in 0..<3 {
            _ = peer.connection.receive(peer.segment(acknowledgment: unacknowledged, flags: [.ack]), at: peer.now)
        }

        // A partial ACK acknowledging only the first segment carries data for the new range [7000, 7500).
        let partial = peer.segment(
            sequence: SequenceNumber(7_000), acknowledgment: unacknowledged.advanced(by: 1_240), flags: [.ack],
            payload: patternBytes(count: Self.segmentSize))
        let outputs = peer.connection.receive(partial, at: peer.now)
        let retransmission = try #require(outputs.segments.first { !$0.payload.isEmpty })
        #expect(retransmission.sequenceNumber == unacknowledged.advanced(by: 1_240))
        #expect(retransmission.sackBlocks == blocks([(7_000, 7_500), (6_000, 6_500)]))
        // Reduce the payload to allow two blocks (20 bytes of options) without exceeding 1280 bytes.
        #expect(retransmission.payload.count == 1_240 - 20)
        #expect(try #require(retransmission.ipPacket()).count <= 1_280)
    }

    @Test("Even with segment loss between two Swift connections, segments carrying SACK stay within 1280 bytes and all data arrives")
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
        #expect(all.contains { !$0.sackBlocks.isEmpty && !$0.payload.isEmpty }, "A piggybacked SACK must appear at least once")
        for segment in all {
            let packet = try #require(segment.ipPacket())
            #expect(packet.count <= 1_280)
        }
    }
}
