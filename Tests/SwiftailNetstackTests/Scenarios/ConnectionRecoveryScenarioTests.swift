import SwiftailNetstack
import Testing

/// 기대 시각은 계약 R1·R3·R4·F5·F7·F8과 RFC 6298 5절에서 계산한다.
@Suite("독립 연결 회복")
struct ConnectionRecoveryScenarioTests {
    @Test("SYN·SYN-ACK·셋째 ACK 하나의 손실은 1초 뒤 회복", arguments: [0, 1, 2])
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
        print("회복 handshake leg=\(lostLeg), seed=\(link.seed): \(link.elapsed)")
    }

    @Test("SYN 재전송은 1·3·7·15·31·63·127초, 247초에 종료")
    func synchronizeBackoffAndLimit() throws {
        let policy = LinkSimulator.Policy(lossPercent: 100)
        var link = try LinkSimulator(seed: 110, clientPolicy: policy)
        try link.run(for: .seconds(248), until: { $0.connections[0]?.state == .closed })
        #expect(link.transmissions.map(\.time) == [0, 1, 3, 7, 15, 31, 63, 127].map { .seconds($0) })
        #expect(link.elapsed == .seconds(247))
        #expect(link.events[0].contains(.closed(.timedOut)))
        #expect(try link.connection(.client).nextDeadline == nil)
    }

    @Test("첫 데이터·창 끝 손실은 ACK 진행 뒤 RTO 200ms에 재전송", arguments: [1, 10])
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
        // 열 개면 앞 아홉 개의 ACK 가운데 마지막(아홉째, 2×MSS에 못 미침)이 F5의 40ms 지연 ACK라 RTO가 42ms에 다시 걸린다.
        let timerStart = segmentCount == 1 ? start : start + .milliseconds(42)
        #expect(retransmission.time - timerStart == .milliseconds(200))
        #expect(link.elapsed - start == .milliseconds(segmentCount == 1 ? 242 : 284))
        #expect(try link.read(from: .server).elementsEqual(bytes))
        print("회복 data segments=\(segmentCount), seed=\(link.seed): retransmit=\(retransmission.time - start), ACK=\(link.elapsed - start)")
    }

    @Test("FIN·FIN의 ACK 손실은 200ms 재전송과 즉시 ACK로 회복", arguments: [false, true])
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
        print("회복 FIN ackLoss=\(losesAcknowledgment), seed=\(link.seed): 0.202 seconds")
    }

    @Test("마지막 FIN ACK 손실은 TIME-WAIT에서 ACK하고 60초를 다시 잰다")
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
        print("회복 lastFINACK seed=133: 재전송=0.2 seconds, CLOSED=\(link.elapsed - start)")
    }

    @Test("TIME-WAIT보다 긴 RTO에서 마지막 ACK 손실은 재전송 한도 뒤 종료한다")
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
        // T6은 60초, R1은 최대 120초, R4는 재전송 15회다. 정상 종료를 모든 손실에 강제할 수 없다.
        try link.run(for: .seconds(2_000), stallLimit: .seconds(2_000),
                     until: { $0.connections.allSatisfy { $0?.state == .closed } })
        #expect(link.elapsed - start == .seconds(1_920))
        #expect(link.events[0].contains(.closed(.finished)))
        #expect(link.events[1].contains(.closed(.timedOut)))
        #expect(link.connections.allSatisfy { $0?.nextDeadline == nil })
        print("종료 longRTO seed=134: 마지막 ACK 손실 뒤 1920 seconds, client=finished, server=timedOut")
    }

    @Test("지연 ACK는 40ms, 두 MSS 또는 빈 곳 메우기는 같은 시각")
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
        // 곧바로 보낼 ACK는 그 세그먼트의 receive 출력으로 나온다(F5, 2026-11-15).
        #expect(peer.connection.receive(second, at: peer.now).scenarioSegments.map(\.acknowledgmentNumber)
            == [peer.peerStart.advanced(by: 2480)])
        #expect(peer.connection.advance(to: peer.now).scenarioSegments.isEmpty)

        peer = try ScriptedTCPPeer()
        #expect(peer.receive(second).scenarioSegments.first?.acknowledgmentNumber == peer.peerStart)
        #expect(peer.receive(first).scenarioSegments.first?.acknowledgmentNumber == peer.peerStart.advanced(by: 2480))
    }

    @Test("작지만 0이 아닌 창은 SWS override 200ms 뒤에 보낸다")
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

    @Test("중복 ACK 셋째에서 RTO 전에 fast retransmit, partial ACK에서 다음 손실 재전송")
    func fastRetransmitAndPartialAcknowledgment() throws {
        var peer = try ScriptedTCPPeer()
        // SYN의 창은 확장하지 않는다. 데이터 ACK로 확장 창을 먼저 광고한다(RFC 7323 2.2).
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

    @Test("데이터·창 변경 ACK는 중복 ACK 세 개에 포함하지 않는다", arguments: [false, true])
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

    @Test("창 갱신 ACK 손실은 첫 persist 탐침으로 회복한다")
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
        print("회복 windowUpdate seed=140: probe=\(probe.time - start), data=\(link.elapsed - start)")
    }

    @Test("0 창 탐침 답 하나를 잃으면 다음 탐침은 2배 간격")
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
        print("회복 probeReply seed=141: \(probes.prefix(2).map { $0.time - start })")
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
