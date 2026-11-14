import SwiftailNetstack
import Testing

/// 계약 T2·X2~4와 시험 4·5·10. 기대값은 TCP 노트 4.2·RFC 5961 3.2·4.2·5.2다.
@Suite("독립 연결 입력 경계")
struct ConnectionInputScenarioTests {
    @Test("창 밖 RST는 무시, 창 안 다른 RST는 challenge, 정확한 RST는 reset", arguments: [0, 1, 2])
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

    @Test("동기화 상태의 SYN은 번호와 관계없이 challenge ACK", arguments: [UInt32(0), 1, 1_000_000, 0xFFFF_FFFF])
    func synchronizeInjection(_ offset: UInt32) throws {
        var peer = try ScriptedTCPPeer()
        let output = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: offset), flags: .syn)).scenarioSegments
        #expect(peer.connection.state == .established)
        #expect(output.count == 1)
        #expect(output.first?.flags == .ack)
        #expect(output.first?.acknowledgmentNumber == peer.peerStart)
    }

    @Test("범위를 벗어난 ACK의 데이터·FIN은 처리하지 않는다", arguments: [false, true])
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

    @Test("challenge ACK는 5초 안에 10개, 다음 구간에서 다시 허용")
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

    @Test("SYN-SENT·SYN-RECEIVED의 틀린 ACK는 그 ACK 번호의 RST")
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

    @Test("WL1·WL2: 오래된 SEQ·ACK는 창을 갱신하지 않는다")
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

    @Test("줄어든 창 밖으로 새 데이터를 내지 않고 다시 열리면 재개한다")
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

    @Test("Window Scale 미협상은 16비트, SYN의 창은 협상해도 확장하지 않는다", arguments: [false, true])
    func windowScaleNegotiation(_ negotiated: Bool) throws {
        var peer = try ScriptedTCPPeer(window: 100, scale: negotiated ? 3 : nil)
        #expect(peer.connection.sendWindow == 100)
        _ = peer.receive(peer.segment(window: 100))
        #expect(peer.connection.sendWindow == (negotiated ? 800 : 100))
    }

    @Test("MSS 63은 능동·수동 열기 모두 거절한다")
    func rejectsTooSmallMaximumSegmentSize() throws {
        let peer = try ScriptedTCPPeer()
        let syn = TCPSegment(source: peer.remote, destination: peer.local, sequenceNumber: SequenceNumber(90_000),
                             flags: .syn, window: 100, maximumSegmentSize: 63)
        do {
            _ = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(10_000), at: peer.now)
            Issue.record("계약 X9: MSS 63인 SYN은 거절해야 한다")
        } catch TCPConnection.AcceptError.unacceptableMaximumSegmentSize(let reset) {
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

    @Test("수신 창의 왼쪽에 걸친 부분은 잘라 받고 중복을 읽지 않는다")
    func leftOverlapIsClipped() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(payload: [0, 1, 2, 3]))
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 2), payload: [9, 9, 4, 5]))
        #expect(peer.connection.read(upTo: 100, at: peer.now).bytes == [0, 1, 2, 3, 4, 5])
    }

    @Test("받는 창의 네 칸과 오른쪽 경계 자르기")
    func segmentAcceptabilityAndRightClipping() throws {
        var peer = try ScriptedTCPPeer()
        // 셋째 ACK에서 shift 3인 창 32768을 광고했으므로 오른쪽 끝은 256KiB다(계약 F1·F2).
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
        // 256KiB까지 채우되 ACK로 광고된 오른쪽 끝 안에서만 넣는다.
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

    @Test("앞·뒤·가운데·전체 겹침은 먼저 받은 바이트를 보존한다", arguments: [0, 1, 2, 3])
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

    @Test("33번째 분리 구간은 버리되 빈 곳을 메우는 것은 허용한다")
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

    @Test("빈 곳 뒤에 먼저 온 FIN은 빈 곳을 메운 뒤 소비한다")
    func outOfOrderFinishIsConsumedAfterGap() throws {
        var peer = try ScriptedTCPPeer()
        _ = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 3), flags: [.ack, .fin]))
        #expect(!peer.connection.hasReceivedEndOfStream)
        let output = peer.receive(peer.segment(payload: [1, 2, 3]))
        #expect(peer.connection.read(upTo: 10, at: peer.now).bytes == [1, 2, 3])
        let consumedFinish = peer.connection.hasReceivedEndOfStream
        let reportedFinish = output.contains(.event(.endOfStream))
        let enteredCloseWait = peer.connection.state == .closeWait
        withKnownIssue("계약 T2·TCP 노트 4.2·RFC 9293 3.10.7.4 SHLD-31: 빈 곳 뒤 FIN을 보관하지 않아 재전송 전에는 EOF가 없다. M6-4의 명시된 shortcut. 재현: ISS=90000, FIN SEQ=90004, 이어 SEQ=90001의 3바이트; 난수 없음.") {
            #expect(consumedFinish && reportedFinish && enteredCloseWait)
        }
        if !consumedFinish {
            let retry = peer.receive(peer.segment(sequence: peer.peerStart.advanced(by: 3), flags: [.ack, .fin]))
            #expect(retry.contains(.event(.endOfStream)))
            #expect(peer.connection.state == .closeWait)
        }
    }

    @Test("1바이트 구간 1만 개에서도 읽는 바이트는 원본의 앞부분")
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

    @Test("고정 씨앗의 임의 창 밖·ACK·RST·SYN 주입 뒤 유효 데이터는 온전히 전달", arguments: [UInt64(1), 42, 0x5EED])
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
