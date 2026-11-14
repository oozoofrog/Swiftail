import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 연결 맺기: 능동·수동 열기, MSS와 창 확장의 협상, 거절, SYN·SYN-ACK의 재전송.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 T3·T4·T5, F2, R3·R4, X9와 시험 3·4.
@Suite("연결 맺기")
struct ConnectionOpeningTests {
    @Test("능동 열기의 SYN: MSS 1240, Window Scale 3, 확장하지 않은 창, ISS")
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

    @Test("IPv6의 MSS는 1220이다(1280 − 40 − 20)")
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

    @Test("수동·능동 열기가 맺어지고 양쪽에 .established가 한 번씩 나온다")
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
        // 마지막 ACK는 순수 ACK 하나다.
        let finalACK = pair.clientSent[1].segment
        #expect(finalACK.flags == [.ack])
        #expect(finalACK.sequenceNumber == SequenceNumber(1_001))
        #expect(finalACK.acknowledgmentNumber == SequenceNumber(900_001))
        #expect(pair.clientSent.count == 2)
        #expect(pair.serverSent.count == 1)
    }

    @Test("상대의 SYN에 Window Scale이 없으면 SYN-ACK에도 싣지 않고 양쪽 shift가 0이다")
    func windowScaleRequiresBothSides() throws {
        var peer = try ManualPeer.established(windowScale: nil, ackWindow: 40_000)
        #expect(peer.connection.offersWindowScale == false)
        #expect(peer.connection.receiveWindowShift == 0)
        #expect(peer.connection.sendWindow == 40_000)
        // 광고하는 창은 65,535를 넘지 못한다(버퍼는 256KiB, shift 0).
        let outputs = peer.send(flags: [.ack, .psh], payload: patternBytes(count: 3_000))
        let ack = try #require(outputs.segments.last)
        #expect(ack.acknowledgmentNumber == peer.peerNext)
        #expect(ack.window == 65_535)
    }

    @Test("SYN의 창 필드는 확장하지 않고, 그 뒤의 창은 상대의 shift로 읽는다. shift는 14까지")
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

    @Test("광고하는 창: 맺어진 뒤 버퍼 256KiB를 shift 3으로 내려 싣는다")
    func advertisedScaledWindow() throws {
        var pair = try ConnectionPair.established()
        _ = pair.write(patternBytes(count: 100), from: .client)
        let segment = try #require(pair.toServer.first)
        // 256KiB >> 3 = 32768
        #expect(segment.window == 32_768)
    }

    @Test("상대 MSS가 64보다 작으면 수동 열기는 그 SYN에 RST,ACK로 답하고 연결을 만들지 않는다")
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
                Issue.record("다른 오류: \(error)")
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

    @Test("ACK·RST가 있는 세그먼트는 수동 열기에 쓸 수 없다")
    func acceptRequiresInitialSynchronize() {
        let synAck = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(5),
            flags: [.syn, .ack])
        #expect(throws: TCPConnection.AcceptError.notInitialSYN) {
            _ = try TCPConnection.accept(synAck, initialSequenceNumber: SequenceNumber(1), at: .now)
        }
    }

    @Test("MSS 옵션이 없으면 IPv4 536으로 본다")
    func defaultPeerSegmentSize() throws {
        let peer = try ManualPeer.established(maximumSegmentSize: nil)
        #expect(peer.connection.sendMaximumSegmentSize == 536)
    }

    @Test("능동 열기: SYN-ACK의 MSS가 64보다 작으면 RST를 보내고 .refused")
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

    @Test("거절: SYN을 확인하는 RST에 .refused, ACK 없는 RST는 버린다")
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

    @Test("SYN-SENT: 틀린 ACK에는 <SEQ=SEG.ACK><CTL=RST>, ACK 없는 SYN(동시 열기)은 버린다")
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

    @Test("SYN-RECEIVED: 틀린 ACK에는 <SEQ=SEG.ACK><CTL=RST>")
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

    @Test("SYN-RECEIVED: RST가 RCV.NXT면 조용히 끝나고(.reset), 창 안의 다른 값이면 challenge ACK")
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

    @Test("SYN은 1·3·7·15·31·63·127초에 다시 보내고 247초에 .timedOut")
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

    @Test("SYN-ACK도 7번 다시 보내고 247초에 끝난다")
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

    @Test("SYN을 다시 보낸 연결은 맺어진 뒤 RTO가 3초다(RFC 6298 5.7). 다시 보내지 않았으면 핸드셰이크 RTT가 표본이다")
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
        // 서버는 SYN-ACK를 다시 보내지 않았다. 10ms 왕복의 표본으로 RTO = 10 + 4·5 = 30ms → 하한 200ms.
        var acceptedServer = server
        _ = acceptedServer.receive(
            TCPSegment(
                source: ConnectionHosts.client, destination: ConnectionHosts.server, sequenceNumber: SequenceNumber(101),
                acknowledgmentNumber: SequenceNumber(10), flags: [.ack], window: 1_000),
            at: arrival + .milliseconds(10))
        #expect(acceptedServer.state == .established)
        #expect(acceptedServer.retransmissionTimeout == .milliseconds(200))
    }

    @Test("SYN-SENT에서 abort·close는 아무것도 보내지 않는다")
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

    @Test("맺어지기 전에 쓴 데이터는 맺어진 뒤에 나간다")
    func writeBeforeEstablished() throws {
        var pair = try ConnectionPair.opened()
        #expect(pair.write(patternBytes(count: 10), from: .client) == 10)
        #expect(pair.toServer.isEmpty)
        try pair.deliver()
        #expect(pair.read(.server) == patternBytes(count: 10))
    }
}
