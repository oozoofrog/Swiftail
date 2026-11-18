import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Transfers spanning more than a full sequence number cycle (contract test 6, 4GiB in F4). After establishment, no code should compare against ISS or IRS,
/// and long-lived sequence numbers (SND.WL1·WL2, `recover`, advertised window edge) must not drift more than 2³¹ away and reverse their ordering.
/// The peer sends only handcrafted ACKs and data without building IP packets, so the test runs quickly.
@Suite("Long transfers")
struct ConnectionLongTransferTests {
    /// Slightly more than 2³² (4GiB + 1MiB).
    static let transferLength = (1 << 32) + (1 << 20)

    @Test("Sender: after sending more than 4GiB, sequence numbers and bytes are correct and cwnd has not decreased")
    func sendBeyondSequenceSpace() throws {
        var peer = try ManualPeer.established(iss: 0xFFFF_0000, windowScale: 7, ackWindow: 2_048)
        let chunk = patternBytes(count: 1 << 16)
        var expected = peer.connection.sendNext
        var sentCount = 0
        var writtenCount = 0
        var outputs: [TCPConnection.Output] = []
        while sentCount < Self.transferLength {
            if writtenCount < Self.transferLength, peer.connection.writableByteCount >= chunk.count {
                let (accepted, written) = peer.connection.write(chunk[...], at: peer.now)
                writtenCount += accepted
                outputs += written
            }
            for segment in outputs.segments {
                guard segment.sequenceNumber == expected,
                    segment.payload.first == chunk[sentCount % chunk.count],
                    segment.payload.last == chunk[(sentCount + segment.payload.count - 1) % chunk.count]
                else {
                    Issue.record("Incorrect segment after \(sentCount) bytes: \(segment.sequenceNumber) ≠ \(expected)")
                    return
                }
                expected = expected.advanced(by: UInt32(segment.payload.count))
                sentCount += segment.payload.count
            }
            peer.now = peer.now + .milliseconds(1)
            outputs = peer.connection.receive(
                peer.segment(acknowledgment: peer.connection.sendNext, flags: [.ack], window: 2_048), at: peer.now)
        }
        #expect(peer.connection.state == .established)
        #expect(peer.connection.sendNext == SequenceNumber(0xFFFF_0001).advanced(by: UInt32(truncatingIfNeeded: sentCount)))
        #expect(peer.connection.congestionWindow > 256 * 1024)
        // Acknowledged through the end.
        #expect(peer.connection.sendUnacknowledged == peer.connection.sendNext)
    }

    @Test("Receiver: more than 4GiB can be read in order, and the peer keeps making progress while sending only within the advertised window")
    func receiveBeyondSequenceSpace() throws {
        var peer = try ManualPeer.established(peerISS: 0xFFFF_8000, windowScale: 7)
        let segmentLength = 1_240
        let pattern = patternBytes(count: segmentLength * 211)
        var sentCount = 0
        var readCount = 0
        // The right edge seen by the peer: last ACK received + (window << 3). Initially 65,535 from the SYN-ACK (unscaled).
        var windowEnd = peer.peerNext.advanced(by: 65_535)
        func note(_ outputs: [TCPConnection.Output]) {
            for segment in outputs.segments {
                windowEnd = segment.acknowledgmentNumber.advanced(by: UInt32(segment.window) << 3)
            }
        }
        while readCount < Self.transferLength {
            var progressed = false
            while sentCount < Self.transferLength,
                peer.peerNext.advanced(by: UInt32(segmentLength)).precedesOrEquals(windowEnd)
            {
                let offset = sentCount % pattern.count
                note(peer.send(flags: [.ack], payload: Array(pattern[offset..<offset + segmentLength])))
                sentCount += segmentLength
                progressed = true
            }
            let (bytes, outputs) = peer.connection.read(upTo: .max, at: peer.now)
            note(outputs)
            if !bytes.isEmpty {
                guard bytes.first == pattern[readCount % pattern.count],
                    bytes.last == pattern[(readCount + bytes.count - 1) % pattern.count]
                else {
                    Issue.record("Incorrect bytes read at \(readCount) bytes")
                    return
                }
                readCount += bytes.count
                progressed = true
            }
            guard progressed else {
                Issue.record("Stalled at \(readCount) bytes")
                return
            }
            peer.now = peer.now + .milliseconds(1)
            note(peer.connection.advance(to: peer.now))
        }
        #expect(peer.connection.receiveNext == peer.peerNext)
        #expect(peer.connection.state == .established)
    }
}
