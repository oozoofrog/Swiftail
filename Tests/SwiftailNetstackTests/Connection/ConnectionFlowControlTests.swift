import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Flow control: zero windows and probes, sender and receiver SWS avoidance, 200ms override, window update rules, and shrinking windows.
/// Contract behaviors F3·F7·F8·F9, X5·X9, and test 9.
@Suite("Flow control")
struct ConnectionFlowControlTests {
    @Test("If the receiver does not read, the sender stalls at 256KiB and resumes when the receiver reads")
    func receiverBackpressure() throws {
        var pair = try ConnectionPair.established()
        let data = patternBytes(count: 600 * 1024)
        var offset = pair.write(data, from: .client)
        try pair.run(for: .seconds(2))
        #expect(pair.server.readableByteCount == 256 * 1024)
        #expect(pair.client.sendWindow == 0)
        #expect(pair.client.state == .established)
        var received: [UInt8] = []
        while received.count < data.count {
            received += pair.read(.server)
            if offset < data.count { offset += pair.write(Array(data[offset...]), from: .client) }
            try pair.run(for: .milliseconds(50))
        }
        #expect(received == data)
    }

    @Test("Zero-window probe: 1 byte at <SEQ=SND.UNA−1> after RTO, with intervals doubling. Continues if the peer replies and sends when the window opens")
    func zeroWindowProbes() throws {
        var peer = try ManualPeer.established(ackWindow: 0)
        let start = peer.now
        let (accepted, outputs) = peer.connection.write(patternBytes(count: 1_000)[...], at: peer.now)
        #expect(accepted == 1_000)
        #expect(outputs.segments.isEmpty)
        #expect(peer.connection.nextDeadline == start + .milliseconds(200))
        var probeTimes: [Duration] = []
        for _ in 0..<4 {
            let deadline = try #require(peer.connection.nextDeadline)
            peer.now = deadline
            let probe = try #require(peer.connection.advance(to: deadline).segments.first)
            #expect(probe.sequenceNumber == peer.connection.sendUnacknowledged.advanced(by: .max))
            #expect(probe.payload == [0])
            probeTimes.append(deadline - start)
            // The peer's reply still advertises a zero window.
            #expect(peer.receive(peer.segment(flags: [.ack], window: 0)).segments.isEmpty)
        }
        #expect(probeTimes == [200, 600, 1_400, 3_000].map { Duration.milliseconds($0) })
        let opened = peer.receive(peer.segment(flags: [.ack], window: 5_000))
        #expect(opened.segments.map(\.payload.count) == [1_000])
        #expect(peer.connection.state == .established)
    }

    @Test("After 15 probes without any ACK, yields .timedOut. The interval is capped at 60 seconds")
    func zeroWindowProbeLimit() throws {
        var peer = try ManualPeer.established(ackWindow: 0)
        let start = peer.now
        _ = peer.connection.write(patternBytes(count: 10)[...], at: peer.now)
        var probeTimes: [Duration] = []
        var closedAt: Duration?
        while let deadline = peer.connection.nextDeadline {
            let outputs = peer.connection.advance(to: deadline)
            if !outputs.segments.isEmpty { probeTimes.append(deadline - start) }
            if outputs.events == [.closed(.timedOut)] { closedAt = deadline - start }
        }
        #expect(probeTimes.count == 15)
        // 0.2, 0.6, 1.4, 3.0, 6.2, 12.6, 25.4, 51.0, 102.2, then every 60 seconds
        #expect(Array(probeTimes.prefix(8)) == [200, 600, 1_400, 3_000, 6_200, 12_600, 25_400, 51_000].map { Duration.milliseconds($0) })
        #expect(probeTimes.last == .milliseconds(462_200))
        #expect(closedAt == .milliseconds(522_200))
    }

    @Test("Sender SWS avoidance: waits with a small window, then sends what the window allows after 200ms. Sends immediately if D =< U")
    func senderSillyWindowAvoidance() throws {
        var peer = try ManualPeer.established()
        // MAX(SND.WND) is 65,535. Shrink the window to 1,000.
        _ = peer.receive(peer.segment(flags: [.ack], window: 1_000))
        #expect(peer.connection.sendWindow == 1_000)
        let start = peer.now
        let (_, outputs) = peer.connection.write(patternBytes(count: 5_000)[...], at: peer.now)
        #expect(outputs.segments.isEmpty)
        #expect(peer.advance(by: .milliseconds(199)).segments.isEmpty)
        let forced = peer.advance(by: .milliseconds(1)).segments
        #expect(forced.map(\.payload.count) == [1_000])
        #expect(peer.now - start == .milliseconds(200))

        var small = try ManualPeer.established()
        _ = small.receive(small.segment(flags: [.ack], window: 1_000))
        let (_, immediate) = small.connection.write(patternBytes(count: 600)[...], at: small.now)
        #expect(immediate.segments.map(\.payload.count) == [600])
    }

    @Test("Receiver SWS avoidance: sends a window update ACK only after reading opens at least one MSS of space")
    func receiverSillyWindowAvoidance() throws {
        var peer = try ManualPeer.established(windowScale: 7)
        for _ in 0..<(256 * 1024 / 1_024) {
            peer.send(flags: [.ack], payload: patternBytes(count: 1_024))
        }
        _ = peer.advance(by: .milliseconds(40))
        let (first, quiet) = peer.connection.read(upTo: 1_000, at: peer.now)
        #expect(first.count == 1_000)
        #expect(quiet.segments.isEmpty)
        // The outgoing ACK (a reply to a zero-window probe) also keeps the window at 0 because 1,000 bytes is below the MSS threshold.
        let probeAnswer = peer.receive(peer.segment(flags: [.ack], payload: [0]))
        #expect(probeAnswer.segments.map(\.window) == [0])
        let (second, update) = peer.connection.read(upTo: 300, at: peer.now)
        #expect(second.count == 300)
        let segment = try #require(update.segments.first)
        // The window opened by 1,300 bytes and advertises 162 (1,296 bytes) after shifting down by 3.
        #expect(segment.window == 162)
        #expect(segment.acknowledgmentNumber == peer.peerNext)
    }

    /// A connection holding `unread` unread bytes (window scale shift 3). The advertised remaining window is 256KiB − `unread`.
    private static func peer(holding unread: Int) throws -> ManualPeer {
        var peer = try ManualPeer.established(windowScale: 7)
        for _ in 0..<(unread / 1_024) {
            peer.send(flags: [.ack], payload: patternBytes(count: 1_024))
        }
        _ = peer.advance(by: .milliseconds(40))
        return peer
    }

    @Test("Window update: reading does not send a pure ACK if the advertised remaining window exceeds half the buffer (just above the boundary)")
    func noWindowUpdateWhileRemainingWindowAboveHalf() throws {
        // Holding 127KiB leaves a window of 129KiB (> 128KiB).
        var peer = try Self.peer(holding: 127 * 1_024)
        #expect(peer.connection.advertisedWindowEnd.distance(from: peer.connection.receiveNext) == 129 * 1_024)
        let (bytes, outputs) = peer.connection.read(upTo: 64 * 1_024, at: peer.now)
        #expect(bytes.count == 64 * 1_024)
        #expect(outputs.segments.isEmpty)
        // The ACK for the next data carries the new window (immediately if 2×MSS accumulates).
        peer.send(flags: [.ack], payload: patternBytes(count: 1_240))
        let acknowledgment = peer.send(flags: [.ack], payload: patternBytes(count: 1_240)).segments
        #expect(acknowledgment.count == 1)
        #expect(acknowledgment.first?.acknowledgmentNumber == peer.peerNext)
        // The buffer holds 127KiB − 64KiB + 2,480 bytes. The remaining window is the buffer minus that amount, shifted down by 3.
        let held = 127 * 1_024 - 64 * 1_024 + 2_480
        #expect(acknowledgment.first.map { Int($0.window) << 3 } == ((256 * 1_024 - held) >> 3) << 3)
    }

    @Test("Window update: when the advertised remaining window is at most half the buffer, sends a pure ACK as soon as reading reaches the threshold (just below the boundary)")
    func windowUpdateWhenRemainingWindowAtMostHalf() throws {
        // Holding 129KiB leaves a window of 127KiB (=< 128KiB).
        var peer = try Self.peer(holding: 129 * 1_024)
        let (small, quiet) = peer.connection.read(upTo: 1_000, at: peer.now)
        #expect(small.count == 1_000)
        // 1,000 bytes is below the SWS avoidance threshold (MSS 1,240).
        #expect(quiet.segments.isEmpty)
        let (more, update) = peer.connection.read(upTo: 1_000, at: peer.now)
        #expect(more.count == 1_000)
        let segment = try #require(update.segments.first)
        #expect(segment.payload.isEmpty)
        #expect(segment.acknowledgmentNumber == peer.peerNext)
        #expect(Int(segment.window) << 3 == ((256 * 1_024 - (129 * 1_024 - 2_000)) >> 3) << 3)
    }

    /// When a gap used to pin the window edge, the window stayed at 0 here, so the peer's zero-window probes continued even after the app read everything.
    @Test("Reading opens the window even with a gap, so the connection does not get stuck at a window that scales down to 0")
    func windowOpensWhileReceiveGap() throws {
        // Fill the buffer (256KiB) except for 2 bytes, then skip 1 byte and receive the last 1 byte. The remaining 2-byte window becomes 0 at shift 3.
        var peer = try Self.peer(holding: 255 * 1_024)
        peer.send(flags: [.ack], payload: patternBytes(count: 1_022))
        let base = peer.peerNext
        let ahead = peer.segment(sequence: base.advanced(by: 1), flags: [.ack], payload: [7])
        let duplicate = try #require(peer.connection.receive(ahead, at: peer.now).segments.first)
        #expect(duplicate.acknowledgmentNumber == base)
        #expect(duplicate.window == 0)

        let (bytes, outputs) = peer.connection.read(upTo: 256 * 1_024, at: peer.now)
        #expect(bytes.count == 256 * 1_024 - 2)
        let update = try #require(outputs.segments.first)
        #expect(update.payload.isEmpty)
        #expect(update.acknowledgmentNumber == base)
        #expect(update.window > 0)

        // Once the gap is filled, reading reaches the byte that arrived earlier.
        let fill = peer.segment(sequence: base, flags: [.ack], payload: [6])
        _ = peer.connection.receive(fill, at: peer.now)
        #expect(peer.connection.read(upTo: 10, at: peer.now).0 == [6, 7])
    }

    @Test("Window update: a large transfer does not stall even if the application reads in small amounts")
    func smallReadsDoNotStallTransfer() throws {
        var pair = try ConnectionPair.established()
        let data = patternBytes(count: 2 * 1_024 * 1_024)
        let start = pair.now
        var offset = pair.write(data, from: .client)
        var received: [UInt8] = []
        while received.count < data.count {
            received += pair.read(.server, upTo: 1_000)
            if offset < data.count { offset += pair.write(Array(data[offset...]), from: .client) }
            try pair.run(for: .milliseconds(1))
            try #require(pair.now - start < .seconds(10), "Transfer stalled: \(received.count) bytes")
        }
        #expect(received == data)
        // Reading 1,000 bytes every 1ms takes about 2.1 seconds for 2MiB. It would take longer if the window closed and waited for probes or override.
        #expect(pair.now - start < .milliseconds(2_300))
        #expect(!pair.clientSent.contains { $0.segment.payload == [0] })
    }

    @Test("Window update: old ACKs and segments with an earlier SEQ (WL1) leave the window unchanged")
    func windowUpdateRules() throws {
        var peer = try ManualPeer.established(ackWindow: 10_000)
        _ = peer.connection.write(patternBytes(count: 2_000)[...], at: peer.now)
        let sendNext = peer.connection.sendNext
        _ = peer.receive(peer.segment(acknowledgment: sendNext, flags: [.ack], window: 20_000))
        #expect(peer.connection.sendWindow == 20_000)
        // Earlier SEQ: data overlapping the window's left edge. Accept it, but leave the window unchanged because it precedes SND.WL1.
        let older = peer.segment(
            sequence: peer.peerNext.advanced(by: UInt32.max - 9), acknowledgment: sendNext, flags: [.ack],
            payload: patternBytes(count: 20), window: 1)
        _ = peer.receive(older)
        #expect(peer.connection.readableByteCount == 10)
        #expect(peer.connection.sendWindow == 20_000)
        peer.peerNext = peer.peerNext.advanced(by: 10)
        // An old ACK (before SND.UNA) also leaves the window unchanged.
        _ = peer.receive(peer.segment(acknowledgment: sendNext.advanced(by: UInt32.max - 99), flags: [.ack], window: 3))
        #expect(peer.connection.sendWindow == 20_000)
    }

    @Test("Shrinking window: sends no new data if the usable window is negative (MUST-34)")
    func shrinkingWindow() throws {
        var peer = try ManualPeer.established(ackWindow: 10_000)
        let (_, first) = peer.connection.write(patternBytes(count: 5_000)[...], at: peer.now)
        #expect(first.segments.map(\.payload.count).reduce(0, +) == 5_000)
        _ = peer.receive(peer.segment(acknowledgment: peer.connection.sendUnacknowledged, flags: [.ack], window: 1_000))
        let (_, second) = peer.connection.write(patternBytes(count: 3_000)[...], at: peer.now)
        #expect(second.segments.isEmpty)
    }
}
