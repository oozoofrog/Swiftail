import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Sequence checks, the three RFC 5961 checks, challenge ACK rate limiting, and arbitrary segments.
/// Contract behaviors T2, X1~X4, and tests 4·5.
@Suite("Incoming segment checks")
struct ConnectionInputCheckTests {
    /// A pure ACK sent by the connection: `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`.
    private func isAcknowledgment(_ segment: TCPSegment?, of peer: ManualPeer) -> Bool {
        guard let segment else { return false }
        return segment.flags == [.ack] && segment.payload.isEmpty
            && segment.sequenceNumber == peer.connection.sendNext
            && segment.acknowledgmentNumber == peer.connection.receiveNext
    }

    @Test("Four cells of the acceptability table (window 0 and window > 0, length 0 and > 0)")
    func acceptabilityTable() throws {
        var peer = try ManualPeer.established()
        let next = peer.peerNext
        // Length 0, window > 0: accept if RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND (no response).
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 10), flags: [.ack])).isEmpty)
        // Before the window, reject and send an ACK.
        #expect(isAcknowledgment(peer.receive(peer.segment(sequence: next.advanced(by: .max), flags: [.ack])).segments.first, of: peer))
        // Length > 0, window > 0: accept if the last byte is inside the window (trim the leading portion).
        let straddling = peer.segment(
            sequence: next.advanced(by: UInt32.max - 4), flags: [.ack], payload: patternBytes(count: 10))
        _ = peer.receive(straddling)
        #expect(peer.connection.receiveNext == next.advanced(by: 5))
        #expect(peer.connection.read(upTo: .max, at: peer.now).bytes == Array(patternBytes(count: 10)[5...]))
        peer.peerNext = next.advanced(by: 5)

        // Zero window: fill the 256KiB receive buffer (the peer's SYN has Window Scale, so shift 3 advertises the entire buffer).
        var zero = try ManualPeer.established(windowScale: 7)
        for _ in 0..<(256 * 1024 / 1_024) {
            zero.send(flags: [.ack], payload: patternBytes(count: 1_024))
        }
        #expect(zero.connection.readableByteCount == 256 * 1024)
        // Length 0, window 0: accept only SEG.SEQ = RCV.NXT.
        #expect(zero.receive(zero.segment(flags: [.ack])).isEmpty)
        #expect(zero.receive(zero.segment(sequence: zero.peerNext.advanced(by: 1), flags: [.ack])).segments.count == 1)
        // Length > 0, window 0: reject. If it starts at RCV.NXT, discard the data, inspect the ACK, and reply.
        let probe = zero.receive(zero.segment(flags: [.ack], payload: [9]))
        #expect(probe.segments.first?.window == 0)
        #expect(probe.segments.first?.acknowledgmentNumber == zero.peerNext)
        #expect(zero.connection.readableByteCount == 256 * 1024)
    }

    @Test("Trims bytes beyond the advertised right edge")
    func trimsBeyondAdvertisedWindow() throws {
        var peer = try ManualPeer.established()
        // The peer's SYN has no Window Scale, so the advertised window is 65,535.
        let large = patternBytes(count: 70_000)
        peer.send(flags: [.ack], payload: large)
        #expect(peer.connection.readableByteCount == 65_535)
    }

    @Test("RST: silently drops one outside the window, aborts at RCV.NXT, and sends a challenge ACK for other values inside the window")
    func resetChecks() throws {
        var peer = try ManualPeer.established()
        let next = peer.peerNext
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 1_000_000), flags: [.rst])).isEmpty)
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: .max), flags: [.rst])).isEmpty)
        let challenge = peer.receive(peer.segment(sequence: next.advanced(by: 1), flags: [.rst]))
        #expect(challenge.segments.count == 1)
        #expect(isAcknowledgment(challenge.segments.first, of: peer))
        #expect(peer.connection.state == .established)
        #expect(peer.receive(peer.segment(sequence: next, flags: [.rst])) == [.event(.closed(.reset))])
    }

    @Test("In a synchronized state, sends a challenge ACK for SYN regardless of its sequence number and drops it")
    func synchronizeInSynchronizedState() throws {
        var peer = try ManualPeer.established()
        for offset: UInt32 in [0, 100, 5_000_000] {
            let outputs = peer.receive(
                peer.segment(sequence: peer.peerNext.advanced(by: offset), flags: [.syn, .ack]))
            #expect(outputs.segments.count == 1)
            #expect(isAcknowledgment(outputs.segments.first, of: peer))
            #expect(peer.connection.state == .established)
        }
    }

    @Test("Drops an ACK outside SND.UNA − MAX.SND.WND .. SND.NXT and replies with an ACK. Inside that range, accepts data even with an old ACK")
    func acknowledgmentRange() throws {
        var peer = try ManualPeer.established(ackWindow: 1_000)
        let sendNext = peer.connection.sendNext
        let ahead = peer.segment(
            acknowledgment: sendNext.advanced(by: 1), flags: [.ack], payload: patternBytes(count: 10))
        let outputs = peer.receive(ahead)
        #expect(outputs.segments.count == 1)
        #expect(peer.connection.readableByteCount == 0)
        // MAX.SND.WND is 65,535 (the SYN window).
        let tooOld = peer.segment(
            acknowledgment: sendNext.advanced(by: UInt32.max - 65_535), flags: [.ack], payload: patternBytes(count: 10))
        #expect(peer.receive(tooOld).segments.count == 1)
        #expect(peer.connection.readableByteCount == 0)
        let old = peer.segment(
            acknowledgment: sendNext.advanced(by: UInt32.max - 100), flags: [.ack], payload: patternBytes(count: 10))
        _ = peer.receive(old)
        #expect(peer.connection.readableByteCount == 10)
        #expect(peer.connection.sendWindow == 1_000)
    }

    @Test("Allows up to 10 challenge ACKs per 5 seconds. ACKs for data-free, out-of-window segments share the limit")
    func challengeRateLimit() throws {
        var peer = try ManualPeer.established()
        let next = peer.peerNext
        var acknowledgments = 0
        for _ in 0..<11 {
            acknowledgments += peer.receive(peer.segment(sequence: next.advanced(by: 7), flags: [.rst])).segments.count
        }
        #expect(acknowledgments == 10)
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 9_999_999), flags: [.ack])).segments.isEmpty)
        // Always reply to an out-of-window segment carrying data.
        let withData = peer.segment(sequence: next.advanced(by: 9_999_999), flags: [.ack], payload: [1])
        #expect(peer.receive(withData).segments.count == 1)
        _ = peer.advance(by: .seconds(5))
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 7), flags: [.syn])).segments.count == 1)
    }

    @Test("Drops and acknowledges a pure ACK with SEG.ACK > SND.NXT (SND.UNA on the data side stays unchanged)")
    func acknowledgmentBeyondSendNext() throws {
        var peer = try ManualPeer.established()
        _ = peer.connection.write(patternBytes(count: 100)[...], at: peer.now)
        let unacknowledged = peer.connection.sendUnacknowledged
        let outputs = peer.receive(
            peer.segment(acknowledgment: peer.connection.sendNext.advanced(by: 50), flags: [.ack]))
        #expect(outputs.segments.count == 1)
        #expect(peer.connection.sendUnacknowledged == unacknowledged)
    }

    @Test("Accepts 20,000 arbitrary segments without crashing, and after advance the deadline is later than now")
    func randomSegments() throws {
        var generator = SplitMix(seed: 0x5EED_CAFE)
        for round in 0..<20 {
            var peer = try ManualPeer.established(
                windowScale: round.isMultiple(of: 2) ? 14 : nil, ackWindow: UInt16(truncatingIfNeeded: generator.next()))
            var synSent = TCPConnection.connect(
                from: ConnectionHosts.server, to: ConnectionHosts.client,
                initialSequenceNumber: SequenceNumber(UInt32(truncatingIfNeeded: generator.next())), at: peer.now
            ).connection
            for _ in 0..<1_000 {
                let near = Bool.random(using: &generator)
                let base = near ? peer.peerNext : SequenceNumber(UInt32(truncatingIfNeeded: generator.next()))
                let ackBase = near ? peer.connection.sendNext : SequenceNumber(UInt32(truncatingIfNeeded: generator.next()))
                let segment = TCPSegment(
                    source: ConnectionHosts.client, destination: ConnectionHosts.server,
                    sequenceNumber: base.advanced(by: UInt32(truncatingIfNeeded: Int.random(in: -3_000...70_000, using: &generator))),
                    acknowledgmentNumber: ackBase.advanced(by: UInt32(truncatingIfNeeded: Int.random(in: -70_000...3_000, using: &generator))),
                    flags: TCPSegment.Flags(rawValue: UInt8.random(in: 0...31, using: &generator)),
                    window: UInt16.random(in: 0...UInt16.max, using: &generator),
                    maximumSegmentSize: Bool.random(using: &generator) ? UInt16.random(in: 0...2_000, using: &generator) : nil,
                    windowScale: Bool.random(using: &generator) ? UInt8.random(in: 0...20, using: &generator) : nil,
                    payload: patternBytes(count: Int.random(in: 0...1_500, using: &generator)))
                _ = peer.connection.receive(segment, at: peer.now)
                _ = synSent.receive(segment, at: peer.now)
                if Int.random(in: 0..<10, using: &generator) == 0 {
                    _ = peer.connection.write(patternBytes(count: Int.random(in: 0...5_000, using: &generator))[...], at: peer.now)
                }
                if Int.random(in: 0..<20, using: &generator) == 0 {
                    _ = peer.connection.read(upTo: Int.random(in: 0...100_000, using: &generator), at: peer.now)
                }
                peer.now = peer.now + .milliseconds(Int.random(in: 0...3_000, using: &generator))
                _ = peer.connection.advance(to: peer.now)
                _ = synSent.advance(to: peer.now)
                if let deadline = peer.connection.nextDeadline { #expect(deadline > peer.now) }
                if let deadline = synSent.nextDeadline { #expect(deadline > peer.now) }
                #expect(peer.connection.readableByteCount <= 256 * 1024)
                #expect(peer.connection.unacknowledgedSendByteCount <= 256 * 1024)
            }
        }
    }
}

/// Deterministic random numbers from a seed (SplitMix64).
struct SplitMix: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
