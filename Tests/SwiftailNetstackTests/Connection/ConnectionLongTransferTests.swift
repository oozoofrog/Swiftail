import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 시퀀스 번호가 한 바퀴를 넘게 도는 전송(계약 시험 6, F4의 4GiB). 맺은 뒤에는 ISS·IRS와 견주는 코드가 없어야 하고,
/// 오래 남는 번호(SND.WL1·WL2, `recover`, 광고한 창 끝)가 2³¹ 넘게 멀어져 앞뒤가 뒤집히지 않아야 한다.
/// 상대는 손으로 만든 ACK·데이터만 보내고 IP 패킷을 만들지 않아 빠르게 돈다.
@Suite("긴 전송")
struct ConnectionLongTransferTests {
    /// 2³²보다 조금 더(4GiB + 1MiB).
    static let transferLength = (1 << 32) + (1 << 20)

    @Test("보내는 쪽: 4GiB를 넘게 보내도 번호와 바이트가 맞고 cwnd가 줄지 않는다")
    func sendBeyondSequenceSpace() throws {
        var peer = try ManualPeer.established(iss: 0xFFFF_0000, windowScale: 7, ackWindow: 2_048)
        let chunk = patternBytes(count: 1 << 16)
        var expected = peer.connection.sendNext
        var sentCount = 0
        var writtenCount = 0
        var outputs: [TCPConnection.Output] = []
        while sentCount < Self.transferLength {
            if writtenCount < Self.transferLength, peer.connection.writableByteCount >= chunk.count {
                let (accepted, written) = peer.connection.write(chunk[...], at: peer.now)
                writtenCount += accepted
                outputs += written
            }
            for segment in outputs.segments {
                guard segment.sequenceNumber == expected,
                    segment.payload.first == chunk[sentCount % chunk.count],
                    segment.payload.last == chunk[(sentCount + segment.payload.count - 1) % chunk.count]
                else {
                    Issue.record("\(sentCount)바이트 뒤의 세그먼트가 틀렸다: \(segment.sequenceNumber) ≠ \(expected)")
                    return
                }
                expected = expected.advanced(by: UInt32(segment.payload.count))
                sentCount += segment.payload.count
            }
            peer.now = peer.now + .milliseconds(1)
            outputs = peer.connection.receive(
                peer.segment(acknowledgment: peer.connection.sendNext, flags: [.ack], window: 2_048), at: peer.now)
        }
        #expect(peer.connection.state == .established)
        #expect(peer.connection.sendNext == SequenceNumber(0xFFFF_0001).advanced(by: UInt32(truncatingIfNeeded: sentCount)))
        #expect(peer.connection.congestionWindow > 256 * 1024)
        // 마지막까지 확인받았다.
        #expect(peer.connection.sendUnacknowledged == peer.connection.sendNext)
    }

    @Test("받는 쪽: 4GiB를 넘게 받아도 순서대로 읽히고, 상대는 광고한 창만큼만 보내도 멈추지 않는다")
    func receiveBeyondSequenceSpace() throws {
        var peer = try ManualPeer.established(peerISS: 0xFFFF_8000, windowScale: 7)
        let segmentLength = 1_240
        let pattern = patternBytes(count: segmentLength * 211)
        var sentCount = 0
        var readCount = 0
        // 상대가 본 창의 오른쪽 끝: 마지막으로 받은 ACK + (창 << 3). 처음은 SYN-ACK의 65,535(확장하지 않음).
        var windowEnd = peer.peerNext.advanced(by: 65_535)
        func note(_ outputs: [TCPConnection.Output]) {
            for segment in outputs.segments {
                windowEnd = segment.acknowledgmentNumber.advanced(by: UInt32(segment.window) << 3)
            }
        }
        while readCount < Self.transferLength {
            var progressed = false
            while sentCount < Self.transferLength,
                peer.peerNext.advanced(by: UInt32(segmentLength)).precedesOrEquals(windowEnd)
            {
                let offset = sentCount % pattern.count
                note(peer.send(flags: [.ack], payload: Array(pattern[offset..<offset + segmentLength])))
                sentCount += segmentLength
                progressed = true
            }
            let (bytes, outputs) = peer.connection.read(upTo: .max, at: peer.now)
            note(outputs)
            if !bytes.isEmpty {
                guard bytes.first == pattern[readCount % pattern.count],
                    bytes.last == pattern[(readCount + bytes.count - 1) % pattern.count]
                else {
                    Issue.record("\(readCount)바이트에서 읽은 바이트가 틀렸다")
                    return
                }
                readCount += bytes.count
                progressed = true
            }
            guard progressed else {
                Issue.record("\(readCount)바이트에서 멈췄다")
                return
            }
            peer.now = peer.now + .milliseconds(1)
            note(peer.connection.advance(to: peer.now))
        }
        #expect(peer.connection.receiveNext == peer.peerNext)
        #expect(peer.connection.state == .established)
    }
}
