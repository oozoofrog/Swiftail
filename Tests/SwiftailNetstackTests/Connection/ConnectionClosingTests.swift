import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// All closing orders, RST, TIME-WAIT, FIN-WAIT-2 linger, and keep-alive. Contract behaviors T6·T7·T8 and test 3.
@Suite("Closing")
struct ConnectionClosingTests {
    @Test("One side closes first: FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT for 60 seconds, while the peer goes through CLOSE-WAIT → LAST-ACK → closed")
    func activeCloseFirst() throws {
        var pair = try ConnectionPair.established()
        pair.finishWriting(.client)
        #expect(pair.client.state == .finWait1)
        try pair.deliver()
        #expect(pair.client.state == .finWait2)
        #expect(pair.server.state == .closeWait)
        #expect(pair.serverEvents == [.established, .endOfStream])
        pair.finishWriting(.server)
        #expect(pair.server.state == .lastAck)
        try pair.deliver()
        #expect(pair.client.state == .timeWait)
        #expect(pair.serverEvents.last == .closed(.finished))
        #expect(pair.clientEvents == [.established, .endOfStream])
        let timeWaitStart = pair.now
        #expect(pair.client.nextDeadline == timeWaitStart + .seconds(60))
        try pair.run(for: .seconds(60))
        #expect(pair.clientEvents.last == .closed(.finished))
    }

    @Test("Simultaneous close: both sides pass through CLOSING into TIME-WAIT")
    func simultaneousClose() throws {
        var pair = try ConnectionPair.established()
        pair.finishWriting(.client)
        pair.finishWriting(.server)
        try pair.deliver()
        #expect(pair.client.state == .timeWait)
        #expect(pair.server.state == .timeWait)
        try pair.run(for: .seconds(61))
        #expect(pair.client.state == .closed)
        #expect(pair.server.state == .closed)
    }

    @Test("Data in the opposite direction continues to completion after a half-close")
    func halfCloseThenReverseData() throws {
        var pair = try ConnectionPair.established()
        pair.finishWriting(.client)
        try pair.deliver()
        let data = patternBytes(count: 300 * 1024)
        let received = try pair.exchange(clientSends: [], serverSends: data)
        #expect(received.clientReceived == data)
        #expect(pair.client.state == .finWait2)
        pair.finishWriting(.server)
        try pair.deliver()
        #expect(pair.server.state == .closed)
        #expect(pair.client.state == .timeWait)
    }

    @Test("All data before FIN is readable, and EOF is detected after reading it")
    func dataBeforeFIN() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 3_000), from: .client)
        pair.finishWriting(.client)
        try pair.deliver()
        #expect(pair.server.hasReceivedEndOfStream)
        #expect(pair.read(.server) == patternBytes(count: 3_000))
        #expect(pair.serverEvents == [.established, .readable, .endOfStream])
    }

    @Test("A FIN preceded by a gap is acknowledged immediately but not consumed. Filling the gap consumes it without retransmission")
    func finAfterGapIsConsumedWhenGapFills() throws {
        var peer = try ManualPeer.established()
        let base = peer.peerNext
        let finAhead = peer.segment(
            sequence: base.advanced(by: 100), flags: [.ack, .fin], payload: patternBytes(count: 50))
        let outputs = peer.receive(finAhead)
        #expect(outputs.events.isEmpty)
        #expect(outputs.segments.first?.acknowledgmentNumber == base)
        #expect(peer.connection.state == .established)
        #expect(!peer.connection.hasReceivedEndOfStream)
        // Filling the gap continues through the recorded FIN (RFC 9293 3.10.7.4 SHLD-31). The FIN sequence number is base + 150.
        let filled = peer.receive(peer.segment(sequence: base, flags: [.ack], payload: patternBytes(count: 100)))
        #expect(filled.events.contains(.endOfStream))
        #expect(peer.connection.hasReceivedEndOfStream)
        #expect(peer.connection.state == .closeWait)
        #expect(peer.connection.receiveNext == base.advanced(by: 151))
        #expect(filled.segments.last?.acknowledgmentNumber == base.advanced(by: 151))
    }

    @Test("close with unread data immediately sends RST, and the peer gets .reset")
    func closeWithUnreadData() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 100), from: .server)
        try pair.deliver()
        let sendNext = pair.client.sendNext
        pair.close(.client)
        #expect(pair.clientEvents.last == .closed(.aborted))
        let reset = try #require(pair.toServer.last)
        #expect(reset.flags == [.rst])
        #expect(reset.sequenceNumber == sendNext)
        try pair.deliver()
        #expect(pair.serverEvents.last == .closed(.reset))
    }

    @Test("Data arriving after close ends the connection with RST (SHLD-3). It is accepted after finishWriting alone")
    func dataAfterClose() throws {
        var pair = try ConnectionPair.established()
        pair.close(.client)
        try pair.deliver()
        #expect(pair.client.state == .finWait2)
        _ = pair.write(patternBytes(count: 10), from: .server)
        try pair.deliver()
        #expect(pair.clientEvents.last == .closed(.aborted))
        #expect(pair.serverEvents.last == .closed(.reset))

        var halfClosed = try ConnectionPair.established()
        halfClosed.finishWriting(.client)
        try halfClosed.deliver()
        _ = halfClosed.write(patternBytes(count: 10), from: .server)
        try halfClosed.deliver()
        #expect(halfClosed.read(.client) == patternBytes(count: 10))
    }

    @Test("abort: <SEQ=SND.NXT><CTL=RST>, the peer ends with .reset and clears its buffers")
    func abort() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 100), from: .client)
        try pair.deliver()
        _ = pair.write(patternBytes(count: 100), from: .server)
        let outputs = pair.client.abort()
        #expect(outputs.segments.map(\.flags) == [[.rst]])
        #expect(outputs.segments.first?.sequenceNumber == pair.client.sendNext)
        #expect(outputs.events == [.closed(.aborted)])
        pair.collect(outputs, from: .client)
        pair.toClient = []
        try pair.deliver()
        #expect(pair.serverEvents.last == .closed(.reset))
        #expect(pair.server.readableByteCount == 0)
        #expect(pair.server.nextDeadline == nil)
        // A closed connection emits nothing.
        #expect(pair.client.abort().isEmpty)
        #expect(pair.client.write(patternBytes(count: 1)[...], at: pair.now).accepted == 0)
    }

    @Test("Acknowledges a retransmitted FIN in TIME-WAIT and restarts the 60-second timer")
    func timeWaitRestartsOnRetransmittedFIN() throws {
        var pair = try ConnectionPair.established()
        pair.finishWriting(.client)
        try pair.deliver()
        pair.finishWriting(.server)
        let serverFIN = try #require(pair.toClient.last)
        try pair.deliver()
        #expect(pair.client.state == .timeWait)
        try pair.run(for: .seconds(30))
        let outputs = pair.client.receive(serverFIN, at: pair.now) + pair.client.advance(to: pair.now)
        let acknowledgment = try #require(outputs.segments.first)
        #expect(acknowledgment.flags == [.ack])
        #expect(acknowledgment.acknowledgmentNumber == serverFIN.sequenceNumber.advanced(by: 1))
        #expect(pair.client.nextDeadline == pair.now + .seconds(60))
        try pair.run(for: .seconds(59))
        #expect(pair.client.state == .timeWait)
        try pair.run(for: .seconds(1))
        #expect(pair.client.state == .closed)
    }

    @Test("TIME-WAIT is capped at 240 seconds from entry (2MSL), even when a retransmitted FIN restarts the timer")
    func timeWaitLifetimeCap() throws {
        var pair = try ConnectionPair.established()
        pair.finishWriting(.client)
        try pair.deliver()
        pair.finishWriting(.server)
        let serverFIN = try #require(pair.toClient.last)
        try pair.deliver()
        let entered = pair.now
        #expect(pair.client.state == .timeWait)
        for second in [59, 118, 177, 236] {
            pair.now = entered + .seconds(second)
            let outputs = pair.client.receive(serverFIN, at: pair.now) + pair.client.advance(to: pair.now)
            #expect(outputs.segments.map(\.flags) == [[.ack]])
        }
        #expect(pair.client.nextDeadline == entered + .seconds(240))
        _ = pair.client.advance(to: entered + .seconds(240) - .milliseconds(1))
        #expect(pair.client.state == .timeWait)
        _ = pair.client.advance(to: entered + .seconds(240))
        #expect(pair.client.state == .closed)
    }

    @Test("An RST at RCV.NXT ends TIME-WAIT, and out-of-window data gets an ACK")
    func timeWaitOtherSegments() throws {
        var pair = try ConnectionPair.established()
        pair.finishWriting(.client)
        try pair.deliver()
        pair.finishWriting(.server)
        try pair.deliver()
        let receiveNext = pair.client.receiveNext
        let stray = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client,
            sequenceNumber: receiveNext.advanced(by: 1_000_000), acknowledgmentNumber: pair.client.sendNext,
            flags: [.ack], window: 100, payload: [1, 2, 3])
        #expect((pair.client.receive(stray, at: pair.now) + pair.client.advance(to: pair.now)).segments.count == 1)
        let reset = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: receiveNext,
            flags: [.rst])
        #expect(pair.client.receive(reset, at: pair.now) == [.event(.closed(.reset))])
    }

    @Test("A connection closed with close yields .timedOut if no FIN arrives in FIN-WAIT-2 within 60 seconds. With only finishWriting, there is no deadline")
    func finWait2Linger() throws {
        var closing = try ConnectionPair.established()
        closing.close(.client)
        try closing.deliver()
        #expect(closing.client.state == .finWait2)
        try closing.run(for: .seconds(59))
        #expect(closing.client.state == .finWait2)
        try closing.run(for: .seconds(1))
        #expect(closing.clientEvents.last == .closed(.timedOut))

        var halfClosed = try ConnectionPair.established()
        halfClosed.finishWriting(.client)
        try halfClosed.deliver()
        try halfClosed.run(for: .seconds(120))
        #expect(halfClosed.client.state == .finWait2)
        #expect(halfClosed.client.nextDeadline == halfClosed.now - .seconds(120) + .seconds(7_200))
    }

    @Test("Keep-alive: <SEQ=SND.NXT−1> after 2 hours, another 2 hours after a reply, and .timedOut after 9 unanswered probes")
    func keepalive() throws {
        var pair = try ConnectionPair.established()
        let start = pair.now
        try pair.run(for: .seconds(7_200) - .milliseconds(1))
        #expect(pair.clientSent.count == 2)
        try pair.run(for: .milliseconds(1))
        // The peer's probe also arrives at the same time (its reply is an ACK with SEQ=SND.NXT), so the first segment at this time is the probe.
        let probe = try #require(pair.clientSent.first { $0.at == start + .seconds(7_200) }?.segment)
        #expect(probe.flags == [.ack])
        #expect(probe.payload.isEmpty)
        #expect(probe.sequenceNumber == pair.client.sendNext.advanced(by: .max))
        #expect(pair.client.state == .established)

        // A responding peer leaves the connection intact.
        try pair.run(for: .seconds(3_600))
        #expect(pair.client.state == .established)

        // A peer that does not respond.
        var silent = try ConnectionPair.established()
        silent.drop = { side, _ in side == .server }
        let silentStart = silent.now
        try silent.run(for: .seconds(7_200 + 9 * 75 + 1))
        let probes = silent.clientSent.dropFirst(2)
        #expect(probes.count == 9)
        #expect(probes.first.map { $0.at - silentStart } == .seconds(7_200))
        #expect(silent.clientEvents.last == .closed(.timedOut))
    }
}
