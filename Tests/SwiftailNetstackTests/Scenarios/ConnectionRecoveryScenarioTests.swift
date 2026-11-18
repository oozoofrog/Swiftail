import SwiftailNetstack
import Testing

/// Expected times are computed from contract R1·R3·R4·F5·F7·F8 and RFC 6298 §5.
@Suite("Independent connection recovery")
struct ConnectionRecoveryScenarioTests {
    @Test("Recovers after 1 second from the loss of one SYN, SYN-ACK, or third ACK", arguments: [0, 1, 2])
    func handshakeLoss(_ lostLeg: Int) throws {
        var client = LinkSimulator.Policy()
        var server = LinkSimulator.Policy()
        if lostLeg == 0 { client.droppedOrdinals = [1] }
        if lostLeg == 1 { server.droppedOrdinals = [1] }
        if lostLeg == 2 { client.droppedOrdinals = [2] }
        var link = try LinkSimulator(seed: 100 + UInt64(lostLeg), clientPolicy: client, serverPolicy: server)
        try link.open()
        #expect(link.elapsed == .milliseconds(1_003))
        #expect(link.droppedCounts.reduce(0, +) == 1)
        if lostLeg == 0 || lostLeg == 1 {
            #expect(try link.connection(.client).retransmissionTimeout >= .seconds(3))
        }
        print("Recovery handshake leg=\(lostLeg), seed=\(link.seed): \(link.elapsed)")
    }

    @Test("SYN retransmits at 1·3·7·15·31·63·127 seconds and ends at 247 seconds")
    func synchronizeBackoffAndLimit() throws {
        let policy = LinkSimulator.Policy(lossPercent: 100)
        var link = try LinkSimulator(seed: 110, clientPolicy: policy)
        try link.run(for: .seconds(248), until: { $0.connections[0]?.state == .closed })
        #expect(link.transmissions.map(\.time) == [0, 1, 3, 7, 15, 31, 63, 127].map { .seconds($0) })
        #expect(link.elapsed == .seconds(247))
        #expect(link.events[0].contains(.closed(.timedOut)))
        #expect(try link.connection(.client).nextDeadline == nil)
    }

    @Test("Loss of the first data or the window's last segment retransmits at the 200ms RTO after ACK progress", arguments: [1, 10])
    func dataAndTailLoss(_ segmentCount: Int) throws {
        var link = try LinkSimulator(seed: 120 + UInt64(segmentCount))
        try link.open()
        let start = link.elapsed
        let first = try link.connection(.client).sendNext
        let lostSequence = first.advanced(by: UInt32((segmentCount - 1) * 1240))
        link.policies[0].rules = [.init(matches: { !$0.payload.isEmpty && $0.sequenceNumber == lostSequence })]
        let bytes = scenarioBytes(segmentCount * 1240)
        #expect(try link.write(bytes[...], from: .client) == bytes.count)
        try link.run(for: .seconds(2), until: { $0.connections[0]?.unacknowledgedSendByteCount == 0 })
        let lost = link.transmissions.filter { $0.side == .client && $0.segment.sequenceNumber == lostSequence && !$0.segment.payload.isEmpty }
        #expect(lost.count == 2)
        let retransmission = try #require(lost.last)
        // With ten segments, the last ACK for the first nine (the ninth, falling short of 2×MSS) is the 40ms delayed ACK in F5, so RTO restarts at 42ms.
        let timerStart = segmentCount == 1 ? start : start + .milliseconds(42)
        #expect(retransmission.time - timerStart == .milliseconds(200))
        #expect(link.elapsed - start == .milliseconds(segmentCount == 1 ? 242 : 284))
        #expect(try link.read(from: .server).elementsEqual(bytes))
        print("Recovery data segments=\(segmentCount), seed=\(link.seed): retransmit=\(retransmission.time - start), ACK=\(link.elapsed - start)")
    }

    @Test("Recovers from loss of FIN or its ACK with a retransmission at 200ms and an immediate ACK", arguments: [false, true])
    func finishLoss(_ losesAcknowledgment: Bool) throws {
        var link = try LinkSimulator(seed: losesAcknowledgment ? 132 : 131)
        try link.open()
        let start = link.elapsed
        if losesAcknowledgment {
            link.policies[1].rules = [.init(matches: { $0.flags == .ack && $0.payload.isEmpty })]
        } else {
            link.policies[0].rules = [.init(matches: { $0.flags.contains(.fin) })]
        }
        try link.finish(.client)
        try link.run(for: .seconds(2), until: { $0.connections[0]?.state == .finWait2 })
        #expect(link.elapsed - start == .milliseconds(202))
        #expect(link.events[1].filter { $0 == .endOfStream }.count == 1)
        try link.finish(.server)
        try link.run(for: .seconds(62), until: { $0.connections.allSatisfy { $0?.state == .closed } })
        #expect(link.connections.allSatisfy { $0?.nextDeadline == nil })
        print("Recovery FIN ackLoss=\(losesAcknowledgment), seed=\(link.seed): 0.202 seconds")
    }

    @Test("For a lost final FIN ACK, sends an ACK in TIME-WAIT and restarts the 60-second timer")
    func lastFinishAcknowledgmentLoss() throws {
        var link = try LinkSimulator(seed: 133)
        try link.open()
        try link.finish(.client)
        try link.run(for: .seconds(1), until: { $0.connections[1]?.hasReceivedEndOfStream == true })
        link.policies[0].rules = [.init(matches: { $0.flags == .ack && $0.payload.isEmpty })]
        let start = link.elapsed
        try link.finish(.server)
        try link.run(for: .seconds(62), until: { $0.connections.allSatisfy { $0?.state == .closed } })
        let finishes = link.transmissions.filter { $0.side == .server && $0.segment.flags.contains(.fin) }
        #expect(finishes.map { $0.time - start } == [.zero, .milliseconds(200)])
        #expect(link.elapsed - start == .milliseconds(60_201))
        #expect(link.events.allSatisfy { $0.contains(.closed(.finished)) })
        print("Recovery lastFINACK seed=133: retransmission=0.2 seconds, CLOSED=\(link.elapsed - start)")
    }

    @Test("If RTO exceeds TIME-WAIT, loss of the final ACK ends at the retransmission limit")
    func lastAcknowledgmentLossWithLongRetransmissionTimeout() throws {
        var link = try LinkSimulator(seed: 134)
        try link.open()
        link.policies[1].rules = [.init(occurrences: Set(1...10), matches: { !$0.payload.isEmpty })]
        #expect(try link.write([7][...], from: .server) == 1)
        try link.run(for: .seconds(300), until: { $0.connections[1]?.unacknowledgedSendByteCount == 0 })
        #expect(try link.read(from: .client) == [7])
        #expect(try link.connection(.server).retransmissionTimeout == .seconds(120))
        try link.finish(.client)
        try link.run(for: .seconds(1), until: { $0.connections[1]?.hasReceivedEndOfStream == true })
        link.policies[0].rules = [.init(matches: { $0.flags == .ack && $0.payload.isEmpty })]
        let start = link.elapsed
        try link.finish(.server)
        // T6 is 60 seconds, R1 is at most 120 seconds, and R4 allows 15 retransmissions. A normal close cannot be forced for every loss.
        try link.run(for: .seconds(2_000), stallLimit: .seconds(2_000),
                     until: { $0.connections.allSatisfy { $0?.state == .closed } })
        #expect(link.elapsed - start == .seconds(1_920))
        #expect(link.events[0].contains(.closed(.finished)))
        #expect(link.events[1].contains(.closed(.timedOut)))
        #expect(link.connections.allSatisfy { $0?.nextDeadline == nil })
        print("Close longRTO seed=134: 1920 seconds after final ACK loss, client=finished, server=timedOut")
    }

    @Test("Delayed ACK at 40ms, immediate ACK at two MSS or when a gap is filled")
    func delayedAndImmediateAcknowledgments() throws {
        var peer = try ScriptedTCPPeer()
        let first = peer.segment(payload: scenarioBytes(1240))
        #expect(peer.connection.receive(first, at: peer.now).scenarioSegments.isEmpty)
        #expect(peer.connection.nextDeadline == peer.now.advanced(by: .milliseconds(40)))
        #expect(peer.connection.advance(to: peer.now.advanced(by: .milliseconds(39))).scenarioSegments.isEmpty)
        #expect(peer.connection.advance(to: peer.now.advanced(by: .milliseconds(40))).scenarioSegments.count == 1)

        peer = try ScriptedTCPPeer()
        _ = peer.connection.receive(first, at: peer.now)
        let second = peer.segment(sequence: peer.peerStart.advanced(by: 1240), payload: scenarioBytes(1240))
        // An immediate ACK appears in the receive output for that segment (F5, 2026-11-15).
        #expect(peer.connection.receive(second, at: peer.now).scenarioSegments.map(\.acknowledgmentNumber)
            == [peer.peerStart.advanced(by: 2480)])
        #expect(peer.connection.advance(to: peer.now).scenarioSegments.isEmpty)

        peer = try ScriptedTCPPeer()
        #expect(peer.receive(second).scenarioSegments.first?.acknowledgmentNumber == peer.peerStart)
        #expect(peer.receive(first).scenarioSegments.first?.acknowledgmentNumber == peer.peerStart.advanced(by: 2480))
    }

    @Test("A small but nonzero window sends after the 200ms SWS override")
    func sillyWindowOverride() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(window: 1))
        let result = peer.connection.write(scenarioBytes(1240)[...], at: peer.now)
        #expect(result.accepted == 1240)
        #expect(result.outputs.scenarioSegments.isEmpty)
        #expect(peer.connection.nextDeadline == peer.now.advanced(by: .milliseconds(200)))
        #expect(peer.connection.advance(to: peer.now.advanced(by: .milliseconds(199))).scenarioSegments.isEmpty)
        let sent = peer.connection.advance(to: peer.now.advanced(by: .milliseconds(200))).scenarioSegments
        #expect(sent.map { $0.payload.count } == [8])
    }

    @Test("The third duplicate ACK triggers fast retransmit before RTO, and a partial ACK retransmits the next loss")
    func fastRetransmitAndPartialAcknowledgment() throws {
        var peer = try ScriptedTCPPeer()
        // The SYN window is unscaled. First advertise a scaled window with a data ACK (RFC 7323 2.2).
        _ = peer.receive(peer.segment())
        let original = peer.connection.write(scenarioBytes(10 * 1240)[...], at: peer.now).outputs.scenarioSegments
        #expect(original.count == 10)
        for index in 1...3 {
            peer.now = peer.now.advanced(by: .milliseconds(1))
            let output = peer.receive(peer.segment()).scenarioSegments
            if index < 3 { #expect(output.isEmpty) }
            else {
                #expect(output.first?.sequenceNumber == peer.localStart)
                #expect(output.first?.payload == original.first?.payload)
            }
        }
        #expect(peer.origin.duration(to: peer.now) < .milliseconds(200))
        let partial = peer.localStart.advanced(by: 1240)
        let output = peer.receive(peer.segment(acknowledgment: partial)).scenarioSegments
        #expect(output.first?.sequenceNumber == partial)
        #expect(output.first?.payload == original[1].payload)
        #expect(peer.connection.nextDeadline == peer.now.advanced(by: .milliseconds(200)))
        _ = peer.receive(peer.segment(acknowledgment: peer.localStart.advanced(by: 12_400)))
        #expect(peer.connection.unacknowledgedSendByteCount == 0)
    }

    @Test("ACKs that carry data or change the window do not count toward three duplicate ACKs", arguments: [false, true])
    func nonDuplicateAcknowledgmentsDoNotRetransmit(_ carriesData: Bool) throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment())
        _ = peer.connection.write(scenarioBytes(4 * 1240)[...], at: peer.now)
        for index in 1...3 {
            let acknowledgment = peer.segment(sequence: peer.peerStart.advanced(by: carriesData ? UInt32(index - 1) : 0),
                                               window: carriesData ? nil : UInt16(32_768 - index),
                                               payload: carriesData ? [UInt8(index)] : [])
            #expect(peer.receive(acknowledgment).scenarioSegments.allSatisfy { $0.payload.isEmpty })
        }
        let sent = peer.connection.advance(to: peer.now.advanced(by: .milliseconds(200))).scenarioSegments
        #expect(sent.first(where: { !$0.payload.isEmpty })?.sequenceNumber == peer.localStart)
    }

    @Test("The first persist probe recovers from a lost window update ACK")
    func lostWindowUpdate() throws {
        var link = try blockedLink(seed: 140)
        let start = link.elapsed
        let rto = try link.connection(.client).retransmissionTimeout
        link.policies[1].rules = [.init(matches: { $0.flags == .ack && $0.window > 0 && $0.payload.isEmpty })]
        #expect(try link.read(from: .server, upTo: 1240).count == 1240)
        try link.run(for: .seconds(2), until: { $0.connections[1]?.readableByteCount == 262_144 })
        let probe = try #require(link.transmissions.first { $0.side == .client && $0.time > start && $0.segment.payload.count == 1 })
        #expect(probe.time - start == rto)
        #expect(link.elapsed - start == rto + .milliseconds(3))
        print("Recovery windowUpdate seed=140: probe=\(probe.time - start), data=\(link.elapsed - start)")
    }

    @Test("Losing one zero-window probe reply doubles the interval to the next probe")
    func lostZeroWindowProbeReply() throws {
        var link = try blockedLink(seed: 141)
        let start = link.elapsed
        let rto = try link.connection(.client).retransmissionTimeout
        link.policies[1].rules = [.init(matches: { $0.flags == .ack && $0.window == 0 && $0.payload.isEmpty })]
        try link.advance(by: rto * 3 + .milliseconds(3))
        let probes = link.transmissions.filter { $0.side == .client && $0.time > start && $0.segment.payload.count == 1 }
        #expect(probes.prefix(2).map { $0.time - start } == [rto, rto * 3])
        #expect(try link.connection(.client).state == .established)
        #expect(link.droppedCounts[1] == 1)
        print("Recovery probeReply seed=141: \(probes.prefix(2).map { $0.time - start })")
    }

    private func blockedLink(seed: UInt64) throws -> LinkSimulator {
        var link = try LinkSimulator(seed: seed)
        try link.open()
        let bytes = scenarioBytes(524_288)
        var accepted = 0
        try link.run(for: .seconds(10), application: { link in
            if accepted < bytes.count, try link.connection(.client).writableByteCount > 0 {
                accepted += try link.write(bytes[accepted...], from: .client)
            }
        }, until: { $0.connections[1]?.readableByteCount == 262_144 && $0.connections[0]?.sendWindow == 0 })
        return link
    }
}
