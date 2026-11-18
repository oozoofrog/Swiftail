import SwiftailNetstack
import Testing

/// Contract T2·X2~4 and tests 4·5·10. Expected values follow the TCP notes 4.2 and RFC 5961 3.2·4.2·5.2.
@Suite("Independent connection input edge cases")
struct ConnectionInputScenarioTests {
    @Test("Ignores out-of-window RST, challenges another in-window RST, and resets on an exact RST", arguments: [0, 1, 2])
    func resetValidation(_ position: Int) throws {
        var peer = try ScriptedTCPPeer()
        let sequence = peer.peerStart.advanced(by: position == 0 ? 1_000_000 : position == 1 ? 1 : 0)
        let output = peer.receive(peer.segment(sequence: sequence, flags: .rst))
        if position == 2 {
            #expect(peer.connection.state == .closed)
            #expect(output.contains(.event(.closed(.reset))))
            #expect(peer.connection.nextDeadline == nil)
        } else {
            #expect(peer.connection.state == .established)
            #expect(output.scenarioSegments.count == (position == 0 ? 0 : 1))
        }
    }

    @Test("SYN in a synchronized state receives a challenge ACK regardless of sequence number", arguments: [UInt32(0), 1, 1_000_000, 0xFFFF_FFFF])
    func synchronizeInjection(_ offset: UInt32) throws {
        var peer = try ScriptedTCPPeer()
        let output = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: offset), flags: .syn)).scenarioSegments
        #expect(peer.connection.state == .established)
        #expect(output.count == 1)
        #expect(output.first?.flags == .ack)
        #expect(output.first?.acknowledgmentNumber == peer.peerStart)
    }

    @Test("Does not process the data or FIN of an ACK outside the range", arguments: [false, true])
    func invalidAcknowledgmentPrecedesDataAndFinish(_ tooOld: Bool) throws {
        var peer = try ScriptedTCPPeer()
        let acknowledgment = tooOld ? peer.localStart.advanced(by: UInt32.max - 1_000_000) : peer.localStart.advanced(by: 1)
        let output = peer.receive(peer.segment(acknowledgment: acknowledgment, flags: [.ack, .fin], payload: [7]))
        #expect(peer.connection.state == .established)
        #expect(peer.connection.receiveNext == peer.peerStart)
        #expect(peer.connection.readableByteCount == 0)
        #expect(!peer.connection.hasReceivedEndOfStream)
        #expect(output.scenarioSegments.first?.flags == .ack)
    }

    @Test("Allows 10 challenge ACKs in 5 seconds and allows them again in the next interval")
    func challengeAcknowledgmentRateLimit() throws {
        var peer = try ScriptedTCPPeer()
        let rst = peer.segment(sequence: peer.peerStart.advanced(by: 1), flags: .rst)
        var count = 0
        for _ in 0..<11 { count += peer.receive(rst).scenarioSegments.count }
        #expect(count == 10)
        peer.now = peer.now.advanced(by: .seconds(5))
        #expect(peer.receive(rst).scenarioSegments.count == 1)
        #expect(peer.connection.state == .established)
    }

    @Test("An invalid ACK in SYN-SENT or SYN-RECEIVED gets an RST with that ACK number")
    func openingRejectsInvalidAcknowledgments() throws {
        let peer = try ScriptedTCPPeer()
        var active = TCPConnection.connect(from: peer.local, to: peer.remote,
                                           initialSequenceNumber: SequenceNumber(10_000), at: peer.now).connection
        let badACK = peer.segment(acknowledgment: SequenceNumber(10_002))
        let reset = active.receive(badACK, at: peer.now).scenarioSegments
        #expect(reset.first?.sequenceNumber == badACK.acknowledgmentNumber)
        #expect(reset.first?.flags == .rst)
        #expect(active.state == .synSent)
        let syn = peer.segment(sequence: SequenceNumber(90_000), flags: .syn)
        var passive = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(10_000), at: peer.now).connection
        let passiveReset = passive.receive(badACK, at: peer.now).scenarioSegments
        #expect(passiveReset.first?.sequenceNumber == badACK.acknowledgmentNumber)
        #expect(passiveReset.first?.flags == .rst)
        #expect(passive.state == .synReceived)
    }

    @Test("WL1 and WL2: old SEQ and ACK values do not update the window")
    func windowUpdateOrdering() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 2), window: 100))
        #expect(peer.connection.sendWindow == 800)
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 1), window: 200))
        #expect(peer.connection.sendWindow == 800)
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 3),
                                     acknowledgment: peer.localStart.advanced(by: UInt32.max), window: 300))
        #expect(peer.connection.sendWindow == 800)
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 2), window: 400))
        #expect(peer.connection.sendWindow == 3200)
    }

    @Test("Sends no new data beyond the shrunken window and resumes when it reopens")
    func shrinkingWindowStopsNewData() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment())
        let bytes = scenarioBytes(20 * 1240)
        let first = peer.connection.write(bytes[...], at: peer.now).outputs.scenarioSegments
        #expect(first.reduce(0) { $0 + $1.payload.count } == 12_400)
        let highest = peer.connection.sendNext
        _ = peer.receive(peer.segment(window: 1))
        #expect(peer.connection.sendNext == highest)
        peer.now = peer.now.advanced(by: .milliseconds(199))
        #expect(peer.connection.advance(to: peer.now).scenarioSegments.isEmpty)
        let ack = peer.localStart.advanced(by: 12_400)
        let resumed = peer.receive(peer.segment(acknowledgment: ack, window: 32_768)).scenarioSegments
        #expect(resumed.first?.sequenceNumber == highest)
        #expect(resumed.reduce(0) { $0 + $1.payload.count } == 12_400)
    }

    @Test("Without Window Scale negotiation the window is 16 bits, and the SYN window remains unscaled even when negotiated", arguments: [false, true])
    func windowScaleNegotiation(_ negotiated: Bool) throws {
        var peer = try ScriptedTCPPeer(window: 100, scale: negotiated ? 3 : nil)
        #expect(peer.connection.sendWindow == 100)
        _ = peer.receive(peer.segment(window: 100))
        #expect(peer.connection.sendWindow == (negotiated ? 800 : 100))
    }

    @Test("MSS 63 is rejected on both active and passive opens")
    func rejectsTooSmallMaximumSegmentSize() throws {
        let peer = try ScriptedTCPPeer()
        let syn = TCPSegment(source: peer.remote, destination: peer.local, sequenceNumber: SequenceNumber(90_000),
                             flags: .syn, window: 100, maximumSegmentSize: 63)
        do {
            _ = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(10_000), at: peer.now)
            Issue.record("Contract X9: A SYN with MSS 63 must be rejected")
        } catch {
            // Avoid a pattern directly on the catch clause. Swift 6.3 SILGen stalls on catch patterns with typed throws.
            guard case .unacceptableMaximumSegmentSize(let reset) = error else { throw error }
            #expect(reset.flags == [.rst, .ack])
            #expect(reset.acknowledgmentNumber == peer.peerStart)
        }
        var active = TCPConnection.connect(from: peer.local, to: peer.remote,
                                           initialSequenceNumber: SequenceNumber(10_000), at: peer.now).connection
        var synAck = syn
        synAck.flags = [.syn, .ack]
        synAck.acknowledgmentNumber = peer.localStart
        let output = active.receive(synAck, at: peer.now)
        #expect(output.contains(.event(.closed(.refused))))
        #expect(output.scenarioSegments.first?.flags.contains(.rst) == true)
        #expect(active.state == .closed)
    }

    @Test("Trims the portion overlapping the left of the receive window and does not read duplicates")
    func leftOverlapIsClipped() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(payload: [0, 1, 2, 3]))
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 2), payload: [9, 9, 4, 5]))
        #expect(peer.connection.read(upTo: 100, at: peer.now).bytes == [0, 1, 2, 3, 4, 5])
    }

    @Test("Four receive window cases and right-edge trimming")
    func segmentAcceptabilityAndRightClipping() throws {
        var peer = try ScriptedTCPPeer()
        // The third ACK advertised a window of 32768 with shift 3, so the right edge is 256KiB (contract F1·F2).
        let edge = peer.peerStart.advanced(by: 262_144)
        let outside = peer.receive(peer.segment(sequence: edge, payload: [9]))
        #expect(outside.scenarioSegments.first?.acknowledgmentNumber == peer.peerStart)
        #expect(peer.connection.readableByteCount == 0)
        _ = peer.receive(peer.segment(sequence: edge.advanced(by: UInt32.max), payload: [7, 8]))
        let prefix = [UInt8](repeating: 1, count: 262_143)
        for offset in stride(from: 0, to: prefix.count, by: 1240) {
            _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(offset)),
                                         payload: Array(prefix[offset..<min(offset + 1240, prefix.count)])))
        }
        let read = peer.connection.read(upTo: 262_144, at: peer.now).bytes
        #expect(read == prefix + [7])

        peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment())
        #expect(peer.connection.state == .established)
        // Fill up to 256KiB, inserting only within the right edge advertised in the ACK.
        var offset = 0
        while offset < 262_144 {
            let count = min(1240, 262_144 - offset)
            _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(offset)),
                                         payload: [UInt8](repeating: 1, count: count)))
            offset += count
        }
        #expect(peer.connection.readableByteCount == 262_144)
        let receiveNext = peer.connection.receiveNext
        #expect(peer.receive(peer.segment(sequence: receiveNext)).scenarioSegments.isEmpty)
        let dataAtZero = peer.receive(peer.segment(sequence: receiveNext, payload: [8]))
        #expect(dataAtZero.scenarioSegments.first?.window == 0)
        #expect(peer.connection.receiveNext == receiveNext)
        let outsideAtZero = peer.receive(peer.segment(sequence: receiveNext.advanced(by: 1)))
        #expect(outsideAtZero.scenarioSegments.first?.acknowledgmentNumber == receiveNext)
        let resetAtZero = peer.receive(peer.segment(sequence: receiveNext, flags: .rst))
        #expect(resetAtZero.contains(.event(.closed(.reset))))
        #expect(peer.connection.readableByteCount == 0)
        #expect(peer.connection.nextDeadline == nil)
    }

    @Test("Front, back, interior, and full overlaps preserve the first bytes received", arguments: [0, 1, 2, 3])
    func outOfOrderOverlapsKeepFirstBytes(_ overlap: Int) throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 4), payload: [4, 5, 6, 7]))
        let ranges = [(2, 4), (6, 4), (5, 2), (2, 8)]
        let (offset, count) = ranges[overlap]
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(offset)),
                                     payload: [UInt8](repeating: 99, count: count)))
        _ = peer.receive(peer.segment(payload: [0, 1, 2, 3]))
        let expected: [[UInt8]] = [[0, 1, 99, 99, 4, 5, 6, 7], [0, 1, 2, 3, 4, 5, 6, 7, 99, 99],
                                   [0, 1, 2, 3, 4, 5, 6, 7], [0, 1, 99, 99, 4, 5, 6, 7, 99, 99]]
        #expect(peer.connection.read(upTo: 100, at: peer.now).bytes == expected[overlap])
    }

    @Test("Drops the 33rd disjoint range but allows a gap to be filled")
    func outOfOrderRangeLimit() throws {
        var peer = try ScriptedTCPPeer()
        for index in 1...33 {
            _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(index * 2)), payload: [UInt8(index)]))
        }
        for index in 0..<66 where index % 2 != 0 || index == 0 {
            _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(index)), payload: [0]))
        }
        #expect(peer.connection.receiveNext == peer.peerStart.advanced(by: 66))
        #expect(peer.connection.readableByteCount == 66)
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 66), payload: [33]))
        #expect(peer.connection.receiveNext == peer.peerStart.advanced(by: 67))
    }

    @Test("A FIN that arrives early beyond a gap is consumed once the gap is filled")
    func outOfOrderFinishIsConsumedAfterGap() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 3), flags: [.ack, .fin]))
        #expect(!peer.connection.hasReceivedEndOfStream)
        let output = peer.receive(peer.segment(payload: [1, 2, 3]))
        #expect(peer.connection.read(upTo: 10, at: peer.now).bytes == [1, 2, 3])
        let consumedFinish = peer.connection.hasReceivedEndOfStream
        let reportedFinish = output.contains(.event(.endOfStream))
        let enteredCloseWait = peer.connection.state == .closeWait
        // Contract T2 and RFC 9293 3.10.7.4 SHLD-31: Filling the gap yields EOF without retransmitting FIN.
        #expect(consumedFinish && reportedFinish && enteredCloseWait)
    }

    @Test("Even with 10,000 one-byte ranges, the read bytes are a prefix of the original")
    func tinySegmentFlood() throws {
        var peer = try ScriptedTCPPeer()
        for index in stride(from: 9999, through: 1, by: -2) {
            _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(index)), payload: [UInt8(truncatingIfNeeded: index)]))
        }
        var received = [UInt8]()
        for index in 0..<10_000 {
            _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: UInt32(index)), payload: [UInt8(truncatingIfNeeded: index)]))
            received += peer.connection.read(upTo: 10_000, at: peer.now).bytes
            #expect(peer.connection.readableByteCount <= 262_144)
        }
        #expect(received == (0..<10_000).map { UInt8(truncatingIfNeeded: $0) })
    }

    @Test("Valid data arrives intact after arbitrary out-of-window, ACK, RST, and SYN injections with a fixed seed", arguments: [UInt64(1), 42, 0x5EED])
    func randomizedHostileSegments(_ seed: UInt64) throws {
        var link = try LinkSimulator(seed: seed)
        try link.open()
        let client = try link.connection(.client)
        let server = try link.connection(.server)
        var state = seed
        for index in 0..<512 {
            state = state &* 6_364_136_223_846_793_005 &+ 1
            let kind = index % 4
            let offset = UInt32(truncatingIfNeeded: state >> 32) % 1000 + 1
            let segment = TCPSegment(source: server.localEndpoint, destination: client.localEndpoint,
                                     sequenceNumber: client.receiveNext.advanced(by: kind == 0 ? 1_000_000 + offset : offset),
                                     acknowledgmentNumber: kind == 3 ? client.sendNext.advanced(by: offset) : client.sendUnacknowledged,
                                     flags: kind == 1 ? .rst : kind == 2 ? .syn : .ack,
                                     window: UInt16(truncatingIfNeeded: state), payload: kind == 0 || kind == 3 ? [99] : [])
            link.inject(segment, from: .server)
            try link.advance(by: .milliseconds(1))
            #expect(try link.connection(.client).state == .established, "seed=\(seed), input=\(index)")
            #expect(try link.connection(.client).readableByteCount == 0)
            #expect(try link.connection(.client).sendWindow == client.sendWindow)
        }
        let payload = scenarioBytes(1240)
        #expect(try link.write(payload[...], from: .server) == payload.count)
        try link.run(for: .seconds(2), until: { $0.connections[0]?.readableByteCount == payload.count })
        #expect(try link.read(from: .client) == payload)
    }
}
