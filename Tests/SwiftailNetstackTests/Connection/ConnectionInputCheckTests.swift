import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 시퀀스 검사와 RFC 5961의 세 검사, challenge ACK 속도 제한, 임의 세그먼트.
/// 계약 동작 T2, X1~X4와 시험 4·5.
@Suite("받는 세그먼트 검사")
struct ConnectionInputCheckTests {
    /// 연결이 보낸 순수 ACK: `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`.
    private func isAcknowledgment(_ segment: TCPSegment?, of peer: ManualPeer) -> Bool {
        guard let segment else { return false }
        return segment.flags == [.ack] && segment.payload.isEmpty
            && segment.sequenceNumber == peer.connection.sendNext
            && segment.acknowledgmentNumber == peer.connection.receiveNext
    }

    @Test("받아들일 조건 표의 네 칸(창 0과 창 > 0, 길이 0과 > 0)")
    func acceptabilityTable() throws {
        var peer = try ManualPeer.established()
        let next = peer.peerNext
        // 길이 0, 창 > 0: RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND면 받는다(답 없음).
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 10), flags: [.ack])).isEmpty)
        // 창 앞이면 받지 않고 ACK.
        #expect(isAcknowledgment(peer.receive(peer.segment(sequence: next.advanced(by: .max), flags: [.ack])).segments.first, of: peer))
        // 길이 > 0, 창 > 0: 마지막 바이트가 창 안이면 받는다(앞부분을 잘라 낸다).
        let straddling = peer.segment(
            sequence: next.advanced(by: UInt32.max - 4), flags: [.ack], payload: patternBytes(count: 10))
        _ = peer.receive(straddling)
        #expect(peer.connection.receiveNext == next.advanced(by: 5))
        #expect(peer.connection.read(upTo: .max, at: peer.now).bytes == Array(patternBytes(count: 10)[5...]))
        peer.peerNext = next.advanced(by: 5)

        // 창 0: 받는 버퍼 256KiB를 채운다(상대 SYN에 Window Scale이 있어 shift 3으로 버퍼 전체를 광고한다).
        var zero = try ManualPeer.established(windowScale: 7)
        for _ in 0..<(256 * 1024 / 1_024) {
            zero.send(flags: [.ack], payload: patternBytes(count: 1_024))
        }
        #expect(zero.connection.readableByteCount == 256 * 1024)
        // 길이 0, 창 0: SEG.SEQ = RCV.NXT만 받는다.
        #expect(zero.receive(zero.segment(flags: [.ack])).isEmpty)
        #expect(zero.receive(zero.segment(sequence: zero.peerNext.advanced(by: 1), flags: [.ack])).segments.count == 1)
        // 길이 > 0, 창 0: 받지 않는다. RCV.NXT에서 시작하면 데이터를 버리고 ACK를 보며 답한다.
        let probe = zero.receive(zero.segment(flags: [.ack], payload: [9]))
        #expect(probe.segments.first?.window == 0)
        #expect(probe.segments.first?.acknowledgmentNumber == zero.peerNext)
        #expect(zero.connection.readableByteCount == 256 * 1024)
    }

    @Test("광고한 오른쪽 끝을 넘는 바이트는 잘라 버린다")
    func trimsBeyondAdvertisedWindow() throws {
        var peer = try ManualPeer.established()
        // 상대 SYN에 Window Scale이 없으니 광고한 창은 65,535다.
        let large = patternBytes(count: 70_000)
        peer.send(flags: [.ack], payload: large)
        #expect(peer.connection.readableByteCount == 65_535)
    }

    @Test("RST: 창 밖이면 조용히 버리고, RCV.NXT면 끊고, 창 안의 다른 값이면 challenge ACK")
    func resetChecks() throws {
        var peer = try ManualPeer.established()
        let next = peer.peerNext
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 1_000_000), flags: [.rst])).isEmpty)
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: .max), flags: [.rst])).isEmpty)
        let challenge = peer.receive(peer.segment(sequence: next.advanced(by: 1), flags: [.rst]))
        #expect(challenge.segments.count == 1)
        #expect(isAcknowledgment(challenge.segments.first, of: peer))
        #expect(peer.connection.state == .established)
        #expect(peer.receive(peer.segment(sequence: next, flags: [.rst])) == [.event(.closed(.reset))])
    }

    @Test("동기화된 상태의 SYN에는 번호와 상관없이 challenge ACK를 보내고 버린다")
    func synchronizeInSynchronizedState() throws {
        var peer = try ManualPeer.established()
        for offset: UInt32 in [0, 100, 5_000_000] {
            let outputs = peer.receive(
                peer.segment(sequence: peer.peerNext.advanced(by: offset), flags: [.syn, .ack]))
            #expect(outputs.segments.count == 1)
            #expect(isAcknowledgment(outputs.segments.first, of: peer))
            #expect(peer.connection.state == .established)
        }
    }

    @Test("ACK가 SND.UNA − MAX.SND.WND .. SND.NXT 밖이면 버리고 ACK로 답한다. 안이면 오래된 ACK여도 데이터를 받는다")
    func acknowledgmentRange() throws {
        var peer = try ManualPeer.established(ackWindow: 1_000)
        let sendNext = peer.connection.sendNext
        let ahead = peer.segment(
            acknowledgment: sendNext.advanced(by: 1), flags: [.ack], payload: patternBytes(count: 10))
        let outputs = peer.receive(ahead)
        #expect(outputs.segments.count == 1)
        #expect(peer.connection.readableByteCount == 0)
        // MAX.SND.WND는 65,535(SYN의 창)다.
        let tooOld = peer.segment(
            acknowledgment: sendNext.advanced(by: UInt32.max - 65_535), flags: [.ack], payload: patternBytes(count: 10))
        #expect(peer.receive(tooOld).segments.count == 1)
        #expect(peer.connection.readableByteCount == 0)
        let old = peer.segment(
            acknowledgment: sendNext.advanced(by: UInt32.max - 100), flags: [.ack], payload: patternBytes(count: 10))
        _ = peer.receive(old)
        #expect(peer.connection.readableByteCount == 10)
        #expect(peer.connection.sendWindow == 1_000)
    }

    @Test("challenge ACK는 5초에 10개까지다. 데이터 없는 창 밖 세그먼트의 ACK도 같은 제한을 받는다")
    func challengeRateLimit() throws {
        var peer = try ManualPeer.established()
        let next = peer.peerNext
        var acknowledgments = 0
        for _ in 0..<11 {
            acknowledgments += peer.receive(peer.segment(sequence: next.advanced(by: 7), flags: [.rst])).segments.count
        }
        #expect(acknowledgments == 10)
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 9_999_999), flags: [.ack])).segments.isEmpty)
        // 데이터가 있는 창 밖 세그먼트에는 늘 답한다.
        let withData = peer.segment(sequence: next.advanced(by: 9_999_999), flags: [.ack], payload: [1])
        #expect(peer.receive(withData).segments.count == 1)
        _ = peer.advance(by: .seconds(5))
        #expect(peer.receive(peer.segment(sequence: next.advanced(by: 7), flags: [.syn])).segments.count == 1)
    }

    @Test("SEG.ACK > SND.NXT인 순수 ACK는 버리고 ACK한다(데이터 쪽 SND.UNA는 그대로)")
    func acknowledgmentBeyondSendNext() throws {
        var peer = try ManualPeer.established()
        _ = peer.connection.write(patternBytes(count: 100)[...], at: peer.now)
        let unacknowledged = peer.connection.sendUnacknowledged
        let outputs = peer.receive(
            peer.segment(acknowledgment: peer.connection.sendNext.advanced(by: 50), flags: [.ack]))
        #expect(outputs.segments.count == 1)
        #expect(peer.connection.sendUnacknowledged == unacknowledged)
    }

    @Test("임의의 세그먼트 2만 개를 넣어도 죽지 않고, advance 뒤의 기한은 지금보다 뒤다")
    func randomSegments() throws {
        var generator = SplitMix(seed: 0x5EED_CAFE)
        for round in 0..<20 {
            var peer = try ManualPeer.established(
                windowScale: round.isMultiple(of: 2) ? 14 : nil, ackWindow: UInt16(truncatingIfNeeded: generator.next()))
            var synSent = TCPConnection.connect(
                from: ConnectionHosts.server, to: ConnectionHosts.client,
                initialSequenceNumber: SequenceNumber(UInt32(truncatingIfNeeded: generator.next())), at: peer.now
            ).connection
            for _ in 0..<1_000 {
                let near = Bool.random(using: &generator)
                let base = near ? peer.peerNext : SequenceNumber(UInt32(truncatingIfNeeded: generator.next()))
                let ackBase = near ? peer.connection.sendNext : SequenceNumber(UInt32(truncatingIfNeeded: generator.next()))
                let segment = TCPSegment(
                    source: ConnectionHosts.client, destination: ConnectionHosts.server,
                    sequenceNumber: base.advanced(by: UInt32(truncatingIfNeeded: Int.random(in: -3_000...70_000, using: &generator))),
                    acknowledgmentNumber: ackBase.advanced(by: UInt32(truncatingIfNeeded: Int.random(in: -70_000...3_000, using: &generator))),
                    flags: TCPSegment.Flags(rawValue: UInt8.random(in: 0...31, using: &generator)),
                    window: UInt16.random(in: 0...UInt16.max, using: &generator),
                    maximumSegmentSize: Bool.random(using: &generator) ? UInt16.random(in: 0...2_000, using: &generator) : nil,
                    windowScale: Bool.random(using: &generator) ? UInt8.random(in: 0...20, using: &generator) : nil,
                    payload: patternBytes(count: Int.random(in: 0...1_500, using: &generator)))
                _ = peer.connection.receive(segment, at: peer.now)
                _ = synSent.receive(segment, at: peer.now)
                if Int.random(in: 0..<10, using: &generator) == 0 {
                    _ = peer.connection.write(patternBytes(count: Int.random(in: 0...5_000, using: &generator))[...], at: peer.now)
                }
                if Int.random(in: 0..<20, using: &generator) == 0 {
                    _ = peer.connection.read(upTo: Int.random(in: 0...100_000, using: &generator), at: peer.now)
                }
                peer.now = peer.now + .milliseconds(Int.random(in: 0...3_000, using: &generator))
                _ = peer.connection.advance(to: peer.now)
                _ = synSent.advance(to: peer.now)
                if let deadline = peer.connection.nextDeadline { #expect(deadline > peer.now) }
                if let deadline = synSent.nextDeadline { #expect(deadline > peer.now) }
                #expect(peer.connection.readableByteCount <= 256 * 1024)
                #expect(peer.connection.unacknowledgedSendByteCount <= 256 * 1024)
            }
        }
    }
}

/// 씨앗에서 결정적으로 도는 난수(SplitMix64).
struct SplitMix: RandomNumberGenerator {
    var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
