import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 닫기의 모든 순서, RST, TIME-WAIT, FIN-WAIT-2 linger, keep-alive. 계약 동작 T6·T7·T8과 시험 3.
@Suite("닫기")
struct ConnectionClosingTests {
    @Test("한쪽이 먼저 닫음: FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT 60초, 상대는 CLOSE-WAIT → LAST-ACK → 끝")
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

    @Test("동시에 닫음: 양쪽이 CLOSING을 거쳐 TIME-WAIT")
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

    @Test("반닫힘 뒤에도 반대 방향 데이터는 끝까지 간다")
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

    @Test("FIN 앞의 데이터는 모두 읽을 수 있고, 읽은 뒤에 끝을 안다")
    func dataBeforeFIN() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 3_000), from: .client)
        pair.finishWriting(.client)
        try pair.deliver()
        #expect(pair.server.hasReceivedEndOfStream)
        #expect(pair.read(.server) == patternBytes(count: 3_000))
        #expect(pair.serverEvents == [.established, .readable, .endOfStream])
    }

    @Test("앞에 빈 곳이 있는 FIN은 소비하지 않고 곧바로 ACK한다. 빈 곳이 메워진 뒤 다시 온 FIN을 소비한다")
    func finAfterGapIsNotConsumed() throws {
        var peer = try ManualPeer.established()
        let base = peer.peerNext
        let finAhead = peer.segment(
            sequence: base.advanced(by: 100), flags: [.ack, .fin], payload: patternBytes(count: 50))
        let outputs = peer.receive(finAhead)
        #expect(outputs.events.isEmpty)
        #expect(outputs.segments.first?.acknowledgmentNumber == base)
        #expect(peer.connection.state == .established)
        _ = peer.receive(peer.segment(sequence: base, flags: [.ack], payload: patternBytes(count: 100)))
        #expect(peer.connection.receiveNext == base.advanced(by: 150))
        #expect(!peer.connection.hasReceivedEndOfStream)
        let retransmittedFIN = peer.segment(sequence: base.advanced(by: 150), flags: [.ack, .fin])
        #expect(peer.receive(retransmittedFIN).events == [.endOfStream])
        #expect(peer.connection.state == .closeWait)
        #expect(peer.connection.receiveNext == base.advanced(by: 151))
    }

    @Test("close에 읽지 않은 데이터가 있으면 곧바로 RST, 상대는 .reset")
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

    @Test("close 뒤에 데이터가 오면 RST로 끝낸다(SHLD-3). finishWriting만 했으면 받는다")
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

    @Test("abort: <SEQ=SND.NXT><CTL=RST>, 상대는 .reset으로 끝나고 버퍼를 비운다")
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
        // 끝난 연결은 아무것도 내지 않는다.
        #expect(pair.client.abort().isEmpty)
        #expect(pair.client.write(patternBytes(count: 1)[...], at: pair.now).accepted == 0)
    }

    @Test("TIME-WAIT에서 FIN의 재전송에 ACK하고 60초를 다시 잰다")
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

    @Test("TIME-WAIT의 RST가 RCV.NXT면 끝난다, 창 밖 데이터에는 ACK")
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

    @Test("close한 연결은 FIN-WAIT-2에서 60초 안에 FIN이 오지 않으면 .timedOut. finishWriting만 했으면 기한이 없다")
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

    @Test("keep-alive: 2시간 뒤 <SEQ=SND.NXT−1>, 답이 오면 다시 2시간, 9번 답이 없으면 .timedOut")
    func keepalive() throws {
        var pair = try ConnectionPair.established()
        let start = pair.now
        try pair.run(for: .seconds(7_200) - .milliseconds(1))
        #expect(pair.clientSent.count == 2)
        try pair.run(for: .milliseconds(1))
        // 같은 시각에 상대의 탐침도 오므로(그 답은 SEQ=SND.NXT의 ACK다) 이 시각의 첫 세그먼트가 탐침이다.
        let probe = try #require(pair.clientSent.first { $0.at == start + .seconds(7_200) }?.segment)
        #expect(probe.flags == [.ack])
        #expect(probe.payload.isEmpty)
        #expect(probe.sequenceNumber == pair.client.sendNext.advanced(by: .max))
        #expect(pair.client.state == .established)

        // 답하는 상대: 연결이 그대로다.
        try pair.run(for: .seconds(3_600))
        #expect(pair.client.state == .established)

        // 답하지 않는 상대.
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
