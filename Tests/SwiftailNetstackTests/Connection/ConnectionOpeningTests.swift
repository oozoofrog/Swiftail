import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Connection establishment: active and passive opens, MSS and window scaling negotiation, refusal, and SYN and SYN-ACK retransmission.
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors T3·T4·T5, F2, R3·R4, X9, and tests 3·4.
@Suite("Connection establishment")
struct ConnectionOpeningTests {
    @Test("Active open SYN: MSS 1240, Window Scale 3, unscaled window, ISS")
    func activeSynchronize() throws {
        let (connection, outputs) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(77),
            at: .now)
        let syn = try #require(outputs.segments.first)
        #expect(outputs.count == 1)
        #expect(syn.flags == [.syn])
        #expect(syn.sequenceNumber == SequenceNumber(77))
        #expect(syn.maximumSegmentSize == 1_240)
        #expect(syn.windowScale == 3)
        #expect(syn.window == 65_535)
        #expect(connection.state == .synSent)
        #expect(try syn.roundTripped() == syn)
    }

    @Test("IPv6 MSS is 1220 (1280 − 40 − 20)")
    func ipv6SegmentSize() throws {
        var pair = try ConnectionPair.established(client: ConnectionHosts.client6, server: ConnectionHosts.server6)
        #expect(pair.clientSent[0].segment.maximumSegmentSize == 1_220)
        #expect(pair.client.sendMaximumSegmentSize == 1_220)
        #expect(pair.server.sendMaximumSegmentSize == 1_220)
        let data = patternBytes(count: 5_000)
        _ = pair.write(data, from: .client)
        #expect(pair.toServer.allSatisfy { $0.payload.count <= 1_220 })
        try pair.run(for: .seconds(1))
        #expect(pair.read(.server) == data)
    }

    @Test("Passive and active opens establish and each side emits .established once")
    func handshake() throws {
        let pair = try ConnectionPair.established()
        #expect(pair.clientEvents == [.established])
        #expect(pair.serverEvents == [.established])
        let synAck = pair.serverSent[0].segment
        #expect(synAck.flags == [.syn, .ack])
        #expect(synAck.acknowledgmentNumber == SequenceNumber(1_001))
        #expect(synAck.sequenceNumber == SequenceNumber(900_000))
        #expect(synAck.windowScale == 3)
        #expect(synAck.maximumSegmentSize == 1_240)
        // The final ACK is one pure ACK.
        let finalACK = pair.clientSent[1].segment
        #expect(finalACK.flags == [.ack])
        #expect(finalACK.sequenceNumber == SequenceNumber(1_001))
        #expect(finalACK.acknowledgmentNumber == SequenceNumber(900_001))
        #expect(pair.clientSent.count == 2)
        #expect(pair.serverSent.count == 1)
    }

    @Test("If the peer SYN has no Window Scale, omits it from SYN-ACK and uses a shift of 0 on both sides")
    func windowScaleRequiresBothSides() throws {
        var peer = try ManualPeer.established(windowScale: nil, ackWindow: 40_000)
        #expect(peer.connection.offersWindowScale == false)
        #expect(peer.connection.receiveWindowShift == 0)
        #expect(peer.connection.sendWindow == 40_000)
        // The advertised window cannot exceed 65,535 (256KiB buffer, shift 0).
        let outputs = peer.send(flags: [.ack, .psh], payload: patternBytes(count: 3_000))
        let ack = try #require(outputs.segments.last)
        #expect(ack.acknowledgmentNumber == peer.peerNext)
        #expect(ack.window == 65_535)
    }

    @Test("The SYN window field is unscaled. Subsequent windows are read with the peer shift, which is capped at 14")
    func windowScaleApplication() throws {
        let peer = try ManualPeer.established(windowScale: 7, synWindow: 1_000, ackWindow: 2)
        #expect(peer.connection.sendWindow == 2 << 7)
        #expect(peer.connection.maximumSendWindow == 1_000)

        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(1),
            flags: [.syn], window: 1_000, maximumSegmentSize: 1_240, windowScale: 20)
        var (connection, outputs) = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(9), at: start)
        #expect(connection.sendWindow == 1_000)
        #expect(outputs.segments.first?.windowScale == 3)
        let ack = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(2),
            acknowledgmentNumber: SequenceNumber(10), flags: [.ack], window: 1)
        outputs = connection.receive(ack, at: start)
        #expect(outputs.events == [.established])
        #expect(connection.sendWindow == 1 << 14)
    }

    @Test("Advertised window: after establishment, shifts the 256KiB buffer down by 3 for the window field")
    func advertisedScaledWindow() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 100), from: .client)
        let segment = try #require(pair.toServer.first)
        // 256KiB >> 3 = 32768
        #expect(segment.window == 32_768)
    }

    @Test("If the peer MSS is below 64, a passive open replies to the SYN with RST,ACK and creates no connection")
    func passiveRejectsSmallSegmentSize() throws {
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(500),
            flags: [.syn], window: 1_000, maximumSegmentSize: 63)
        #expect(throws: TCPConnection.AcceptError.self) {
            _ = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(1), at: .now)
        }
        do {
            _ = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(1), at: .now)
        } catch {
            guard case .unacceptableMaximumSegmentSize(let reset) = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(reset.flags == [.rst, .ack])
            #expect(reset.sequenceNumber == SequenceNumber(0))
            #expect(reset.acknowledgmentNumber == SequenceNumber(501))
            #expect(reset.source == ConnectionHosts.server)
            #expect(reset.destination == ConnectionHosts.client)
        }
        var accepted = syn
        accepted.maximumSegmentSize = 64
        let (connection, _) = try TCPConnection.accept(accepted, initialSequenceNumber: SequenceNumber(1), at: .now)
        #expect(connection.sendMaximumSegmentSize == 64)
    }

    @Test("Segments with ACK or RST cannot be used for a passive open")
    func acceptRequiresInitialSynchronize() {
        let synAck = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(5),
            flags: [.syn, .ack])
        #expect(throws: TCPConnection.AcceptError.notInitialSYN) {
            _ = try TCPConnection.accept(synAck, initialSequenceNumber: SequenceNumber(1), at: .now)
        }
    }

    @Test("Uses the IPv4 default of 536 when the MSS option is absent")
    func defaultPeerSegmentSize() throws {
        let peer = try ManualPeer.established(maximumSegmentSize: nil)
        #expect(peer.connection.sendMaximumSegmentSize == 536)
    }

    @Test("Active open: a SYN-ACK with MSS below 64 triggers RST and .refused")
    func activeRejectsSmallSegmentSize() throws {
        let start = ContinuousClock.now
        var (client, _) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: start)
        let synAck = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(7),
            acknowledgmentNumber: SequenceNumber(101), flags: [.syn, .ack], window: 1_000, maximumSegmentSize: 10)
        let outputs = client.receive(synAck, at: start)
        #expect(outputs.segments == [
            TCPSegment(
                source: ConnectionHosts.client, destination: ConnectionHosts.server,
                sequenceNumber: SequenceNumber(101), flags: [.rst])
        ])
        #expect(outputs.events == [.closed(.refused)])
        #expect(client.state == .closed)
        #expect(client.nextDeadline == nil)
    }

    @Test("Refusal: an RST acknowledging SYN yields .refused. Drops RST without ACK")
    func refused() {
        let start = ContinuousClock.now
        var (client, _) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: start)
        func reset(_ flags: TCPSegment.Flags, ack: UInt32) -> TCPSegment {
            TCPSegment(
                source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(0),
                acknowledgmentNumber: SequenceNumber(ack), flags: flags)
        }
        #expect(client.receive(reset([.rst], ack: 0), at: start).isEmpty)
        #expect(client.receive(reset([.rst, .ack], ack: 100), at: start).isEmpty)
        #expect(client.state == .synSent)
        #expect(client.receive(reset([.rst, .ack], ack: 101), at: start).events == [.closed(.refused)])
        #expect(client.state == .closed)
    }

    @Test("SYN-SENT: an invalid ACK gets <SEQ=SEG.ACK><CTL=RST>, and a SYN without ACK (simultaneous open) is dropped")
    func synSentBadAcknowledgment() {
        let start = ContinuousClock.now
        var (client, _) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: start)
        let wrong = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(7),
            acknowledgmentNumber: SequenceNumber(5_000), flags: [.syn, .ack], window: 1_000)
        let outputs = client.receive(wrong, at: start)
        #expect(outputs.segments.map(\.flags) == [[.rst]])
        #expect(outputs.segments.first?.sequenceNumber == SequenceNumber(5_000))
        let simultaneous = TCPSegment(
            source: ConnectionHosts.server, destination: ConnectionHosts.client, sequenceNumber: SequenceNumber(7),
            flags: [.syn], window: 1_000)
        #expect(client.receive(simultaneous, at: start).isEmpty)
        #expect(client.state == .synSent)
    }

    @Test("SYN-RECEIVED: an invalid ACK gets <SEQ=SEG.ACK><CTL=RST>")
    func synReceivedBadAcknowledgment() throws {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(500),
            flags: [.syn], window: 1_000, maximumSegmentSize: 1_240)
        var (server, _) = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(9_000), at: start)
        for wrongACK: UInt32 in [9_000, 9_002, 1] {
            let ack = TCPSegment(
                source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(501),
                acknowledgmentNumber: SequenceNumber(wrongACK), flags: [.ack], window: 1_000)
            let outputs = server.receive(ack, at: start)
            #expect(outputs.segments.map(\.flags) == [[.rst]])
            #expect(outputs.segments.first?.sequenceNumber == SequenceNumber(wrongACK))
            #expect(server.state == .synReceived)
        }
    }

    @Test("SYN-RECEIVED: an RST at RCV.NXT ends silently (.reset), and another in-window value gets a challenge ACK")
    func synReceivedReset() throws {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(500),
            flags: [.syn], window: 1_000, maximumSegmentSize: 1_240)
        var (server, _) = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(9_000), at: start)
        func reset(_ sequence: UInt32) -> TCPSegment {
            TCPSegment(
                source: ConnectionHosts.client, destination: ConnectionHosts.server,
                sequenceNumber: SequenceNumber(sequence), flags: [.rst])
        }
        var outputs = server.receive(reset(600), at: start) + server.advance(to: start)
        #expect(outputs.segments.map(\.flags) == [[.ack]])
        #expect(outputs.segments.first?.acknowledgmentNumber == SequenceNumber(501))
        outputs = server.receive(reset(501), at: start)
        #expect(outputs == [.event(.closed(.reset))])
    }

    @Test("Retransmits SYN at 1·3·7·15·31·63·127 seconds and yields .timedOut at 247 seconds")
    func synchronizeRetransmissions() throws {
        let start = ContinuousClock.now
        var (client, outputs) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: start)
        var times: [Duration] = [.zero]
        var closedAt: Duration?
        let first = try #require(outputs.segments.first)
        while let deadline = client.nextDeadline {
            outputs = client.advance(to: deadline)
            for segment in outputs.segments {
                #expect(segment == first)
                times.append(deadline - start)
            }
            if outputs.events.contains(.closed(.timedOut)) { closedAt = deadline - start }
        }
        #expect(times == [0, 1, 3, 7, 15, 31, 63, 127].map { Duration.seconds($0) })
        #expect(closedAt == .seconds(247))
    }

    @Test("Also retransmits SYN-ACK 7 times and ends at 247 seconds")
    func synchronizeAcknowledgmentRetransmissions() throws {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(500),
            flags: [.syn], window: 1_000, maximumSegmentSize: 1_240)
        var (server, outputs) = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(9_000), at: start)
        var times: [Duration] = [.zero]
        var closedAt: Duration?
        while let deadline = server.nextDeadline {
            outputs = server.advance(to: deadline)
            for segment in outputs.segments {
                #expect(segment.flags == [.syn, .ack])
                times.append(deadline - start)
            }
            if outputs.events.contains(.closed(.timedOut)) { closedAt = deadline - start }
        }
        #expect(times == [0, 1, 3, 7, 15, 31, 63, 127].map { Duration.seconds($0) })
        #expect(closedAt == .seconds(247))
    }

    @Test("After establishment, a connection that retransmitted SYN uses a 3-second RTO (RFC 6298 5.7). Without retransmission, the handshake RTT is the sample")
    func timeoutAfterSynchronizeRetransmission() throws {
        let start = ContinuousClock.now
        var (client, _) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: start)
        let retransmitted = try #require(client.advance(to: start + .seconds(1)).segments.first)
        let arrival = start + .seconds(1) + .milliseconds(5)
        let (server, synAck) = try TCPConnection.accept(
            retransmitted, initialSequenceNumber: SequenceNumber(9), at: arrival)
        _ = client.receive(try #require(synAck.segments.first), at: arrival + .milliseconds(5))
        #expect(client.state == .established)
        #expect(client.retransmissionTimeout == .seconds(3))
        // The server did not retransmit SYN-ACK. The 10ms round-trip sample gives RTO = 10 + 4·5 = 30ms → 200ms floor.
        var acceptedServer = server
        _ = acceptedServer.receive(
            TCPSegment(
                source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(101),
                acknowledgmentNumber: SequenceNumber(10), flags: [.ack], window: 1_000),
            at: arrival + .milliseconds(10))
        #expect(acceptedServer.state == .established)
        #expect(acceptedServer.retransmissionTimeout == .milliseconds(200))
    }

    @Test("abort and close in SYN-SENT send nothing")
    func abortWhileConnecting() {
        var (client, _) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: .now)
        #expect(client.abort() == [.event(.closed(.aborted))])
        #expect(client.nextDeadline == nil)
        var (other, _) = TCPConnection.connect(
            from: ConnectionHosts.client, to: ConnectionHosts.server, initialSequenceNumber: SequenceNumber(100),
            at: .now)
        #expect(other.close(at: .now) == [.event(.closed(.aborted))])
    }

    @Test("Data written before establishment goes out after establishment")
    func writeBeforeEstablished() throws {
        var pair = try ConnectionPair.opened()
        #expect(pair.write(patternBytes(count: 10), from: .client) == 10)
        #expect(pair.toServer.isEmpty)
        try pair.deliver()
        #expect(pair.read(.server) == patternBytes(count: 10))
    }
}
