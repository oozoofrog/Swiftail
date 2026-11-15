import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 흐름 제어: 0 창과 탐침, 보내는 쪽·받는 쪽 SWS 회피, override 200ms, 창 갱신 규칙, 줄어드는 창.
/// 계약 동작 F3·F7·F8·F9, X5·X9와 시험 9.
@Suite("흐름 제어")
struct ConnectionFlowControlTests {
    @Test("받는 쪽이 읽지 않으면 보내는 쪽은 256KiB에서 멈추고, 읽으면 이어 간다")
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

    @Test("0 창 탐침: RTO 뒤에 <SEQ=SND.UNA−1> 1바이트, 간격은 두 배씩. 상대가 답하면 이어 가고, 창이 열리면 보낸다")
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
            // 상대의 답: 창은 여전히 0.
            #expect(peer.receive(peer.segment(flags: [.ack], window: 0)).segments.isEmpty)
        }
        #expect(probeTimes == [200, 600, 1_400, 3_000].map { Duration.milliseconds($0) })
        let opened = peer.receive(peer.segment(flags: [.ack], window: 5_000))
        #expect(opened.segments.map(\.payload.count) == [1_000])
        #expect(peer.connection.state == .established)
    }

    @Test("아무 ACK 없이 탐침 15번이면 .timedOut. 간격은 60초에서 멈춘다")
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
        // 0.2, 0.6, 1.4, 3.0, 6.2, 12.6, 25.4, 51.0, 102.2, 그 뒤로 60초씩
        #expect(Array(probeTimes.prefix(8)) == [200, 600, 1_400, 3_000, 6_200, 12_600, 25_400, 51_000].map { Duration.milliseconds($0) })
        #expect(probeTimes.last == .milliseconds(462_200))
        #expect(closedAt == .milliseconds(522_200))
    }

    @Test("보내는 쪽 SWS 회피: 작은 창에서는 기다리다 200ms 뒤 창이 허락하는 만큼 보낸다. D =< U면 곧바로")
    func senderSillyWindowAvoidance() throws {
        var peer = try ManualPeer.established()
        // MAX(SND.WND)는 65,535. 창을 1,000으로 줄인다.
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

    @Test("받는 쪽 SWS 회피: 읽어서 MSS 이상 열려야 창 갱신 ACK를 보낸다")
    func receiverSillyWindowAvoidance() throws {
        var peer = try ManualPeer.established(windowScale: 7)
        for _ in 0..<(256 * 1024 / 1_024) {
            peer.send(flags: [.ack], payload: patternBytes(count: 1_024))
        }
        _ = peer.advance(by: .milliseconds(40))
        let (first, quiet) = peer.connection.read(upTo: 1_000, at: peer.now)
        #expect(first.count == 1_000)
        #expect(quiet.segments.isEmpty)
        // 이때 나가는 ACK(창 0에 온 탐침의 답)도 창을 0으로 둔다: 1,000바이트는 MSS 문턱 아래다.
        let probeAnswer = peer.receive(peer.segment(flags: [.ack], payload: [0]))
        #expect(probeAnswer.segments.map(\.window) == [0])
        let (second, update) = peer.connection.read(upTo: 300, at: peer.now)
        #expect(second.count == 300)
        let segment = try #require(update.segments.first)
        // 1,300바이트가 열렸고 shift 3으로 내린 162(1,296바이트)를 광고한다.
        #expect(segment.window == 162)
        #expect(segment.acknowledgmentNumber == peer.peerNext)
    }

    /// 읽지 않은 `unread`바이트를 받아 둔 연결(창 확장 shift 3). 광고한 남은 창은 256KiB − `unread`다.
    private static func peer(holding unread: Int) throws -> ManualPeer {
        var peer = try ManualPeer.established(windowScale: 7)
        for _ in 0..<(unread / 1_024) {
            peer.send(flags: [.ack], payload: patternBytes(count: 1_024))
        }
        _ = peer.advance(by: .milliseconds(40))
        return peer
    }

    @Test("창 갱신: 광고한 남은 창이 버퍼의 절반보다 크면 읽어도 순수 ACK를 내지 않는다(경계 바로 위)")
    func noWindowUpdateWhileRemainingWindowAboveHalf() throws {
        // 127KiB를 쥐면 남은 창은 129KiB(> 128KiB)다.
        var peer = try Self.peer(holding: 127 * 1_024)
        #expect(peer.connection.advertisedWindowEnd.distance(from: peer.connection.receiveNext) == 129 * 1_024)
        let (bytes, outputs) = peer.connection.read(upTo: 64 * 1_024, at: peer.now)
        #expect(bytes.count == 64 * 1_024)
        #expect(outputs.segments.isEmpty)
        // 새 창은 다음 데이터의 ACK가 싣는다(2×MSS가 쌓이면 곧바로).
        peer.send(flags: [.ack], payload: patternBytes(count: 1_240))
        let acknowledgment = peer.send(flags: [.ack], payload: patternBytes(count: 1_240)).segments
        #expect(acknowledgment.count == 1)
        #expect(acknowledgment.first?.acknowledgmentNumber == peer.peerNext)
        // 쥔 것은 127KiB − 64KiB + 2,480바이트다. 남은 창은 그만큼 뺀 값을 shift 3으로 내린 것이다.
        let held = 127 * 1_024 - 64 * 1_024 + 2_480
        #expect(acknowledgment.first.map { Int($0.window) << 3 } == ((256 * 1_024 - held) >> 3) << 3)
    }

    @Test("창 갱신: 광고한 남은 창이 버퍼의 절반 이하면 문턱만큼 읽는 즉시 순수 ACK를 보낸다(경계 바로 아래)")
    func windowUpdateWhenRemainingWindowAtMostHalf() throws {
        // 129KiB를 쥐면 남은 창은 127KiB(=< 128KiB)다.
        var peer = try Self.peer(holding: 129 * 1_024)
        let (small, quiet) = peer.connection.read(upTo: 1_000, at: peer.now)
        #expect(small.count == 1_000)
        // 1,000바이트는 SWS 회피의 문턱(MSS 1,240) 아래다.
        #expect(quiet.segments.isEmpty)
        let (more, update) = peer.connection.read(upTo: 1_000, at: peer.now)
        #expect(more.count == 1_000)
        let segment = try #require(update.segments.first)
        #expect(segment.payload.isEmpty)
        #expect(segment.acknowledgmentNumber == peer.peerNext)
        #expect(Int(segment.window) << 3 == ((256 * 1_024 - (129 * 1_024 - 2_000)) >> 3) << 3)
    }

    /// 빈 곳이 있는 동안 창의 끝을 고정하던 때는 여기서 창이 0으로 남아, 앱이 다 읽어도 상대의 0 창 탐침이 끝나지 않았다.
    @Test("빈 곳이 있어도 읽으면 창이 열린다: shift로 내려 0이 된 창에 갇히지 않는다")
    func windowOpensWhileReceiveGap() throws {
        // 버퍼(256KiB)를 2바이트만 남기고 채운 뒤 1바이트를 건너뛴 마지막 1바이트를 받는다. 남은 창 2바이트는 shift 3에서 0이다.
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

        // 빈 곳이 메워지면 먼저 온 바이트까지 읽힌다.
        let fill = peer.segment(sequence: base, flags: [.ack], payload: [6])
        _ = peer.connection.receive(fill, at: peer.now)
        #expect(peer.connection.read(upTo: 10, at: peer.now).0 == [6, 7])
    }

    @Test("창 갱신: 응용이 조금씩 읽어도 큰 전송이 멈추지 않는다")
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
            try #require(pair.now - start < .seconds(10), "전송이 멈췄다: \(received.count)바이트")
        }
        #expect(received == data)
        // 1ms마다 1,000바이트를 읽으므로 2MiB는 약 2.1초다. 창이 닫혀 탐침·override를 기다렸다면 더 걸린다.
        #expect(pair.now - start < .milliseconds(2_300))
        #expect(!pair.clientSent.contains { $0.segment.payload == [0] })
    }

    @Test("창 갱신: 오래된 ACK와 앞선 SEQ(WL1)의 세그먼트는 창을 바꾸지 않는다")
    func windowUpdateRules() throws {
        var peer = try ManualPeer.established(ackWindow: 10_000)
        _ = peer.connection.write(patternBytes(count: 2_000)[...], at: peer.now)
        let sendNext = peer.connection.sendNext
        _ = peer.receive(peer.segment(acknowledgment: sendNext, flags: [.ack], window: 20_000))
        #expect(peer.connection.sendWindow == 20_000)
        // 앞선 SEQ: 창 왼쪽에 걸친 데이터. 받아들이지만 SND.WL1보다 앞이라 창은 그대로다.
        let older = peer.segment(
            sequence: peer.peerNext.advanced(by: UInt32.max - 9), acknowledgment: sendNext, flags: [.ack],
            payload: patternBytes(count: 20), window: 1)
        _ = peer.receive(older)
        #expect(peer.connection.readableByteCount == 10)
        #expect(peer.connection.sendWindow == 20_000)
        peer.peerNext = peer.peerNext.advanced(by: 10)
        // 오래된 ACK(SND.UNA 앞)도 창을 바꾸지 않는다.
        _ = peer.receive(peer.segment(acknowledgment: sendNext.advanced(by: UInt32.max - 99), flags: [.ack], window: 3))
        #expect(peer.connection.sendWindow == 20_000)
    }

    @Test("줄어든 창: 쓸 수 있는 창이 음수면 새 데이터를 보내지 않는다(MUST-34)")
    func shrinkingWindow() throws {
        var peer = try ManualPeer.established(ackWindow: 10_000)
        let (_, first) = peer.connection.write(patternBytes(count: 5_000)[...], at: peer.now)
        #expect(first.segments.map(\.payload.count).reduce(0, +) == 5_000)
        _ = peer.receive(peer.segment(acknowledgment: peer.connection.sendUnacknowledged, flags: [.ack], window: 1_000))
        let (_, second) = peer.connection.write(patternBytes(count: 3_000)[...], at: peer.now)
        #expect(second.segments.isEmpty)
    }
}
