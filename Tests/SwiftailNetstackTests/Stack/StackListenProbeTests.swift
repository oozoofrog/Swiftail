import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 듣는 포트는 SYN이 아닌 세그먼트에 듣지 않는 포트와 똑같이 답한다. 수신 필터는 SYN만 ACL에 견주므로(계약 동작 X), 답이
/// 다르면 ACL이 막은 피어가 FIN만 든 세그먼트로 듣는 포트를 가려낸다. 계약 `docs/contracts/SwiftailNetstack.md` 동작 S3.
@Suite("스택: 듣는 포트와 듣지 않는 포트의 답")
struct StackListenProbeTests {
    /// 포트를 뺀 답의 모습.
    struct Reply: Equatable {
        var flags: TCPSegment.Flags
        var sequenceNumber: SequenceNumber
        var acknowledgmentNumber: SequenceNumber
        var window: UInt16
        var payloadCount: Int
    }

    /// 같은 세그먼트를 듣는 포트(443)와 듣지 않는 포트(444)에 넣었을 때의 답.
    func replies(
        flags: TCPSegment.Flags, payload: [UInt8]
    ) throws -> (listening: [Reply], closed: [Reply], listeningPorts: [UInt16]) {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        _ = try stack.listen(on: 443)
        let peer = IPEndpoint(address: StackHosts.peer(1), port: 40_000)
        func probe(_ port: UInt16) -> [TCPSegment] {
            let segment = peerSegment(
                from: peer, to: IPEndpoint(address: WireHosts.v4b, port: port), sequence: 7_000,
                acknowledgment: SequenceNumber(9_000), flags: flags, payload: payload)
            return (stack.receive(segment.packet, at: .now) + stack.advance(to: .now)).segments
        }
        func shape(_ segments: [TCPSegment]) -> [Reply] {
            segments.map {
                Reply(
                    flags: $0.flags, sequenceNumber: $0.sequenceNumber, acknowledgmentNumber: $0.acknowledgmentNumber,
                    window: $0.window, payloadCount: $0.payload.count)
            }
        }
        let listening = probe(443)
        let closed = probe(444)
        #expect(stack.connections.isEmpty)
        return (shape(listening), shape(closed), listening.map(\.source.port))
    }

    @Test(
        "SYN·ACK·RST가 없는 세그먼트에 듣는 포트도 RST로 답하고, 그 답은 듣지 않는 포트의 것과 플래그·번호까지 같다",
        arguments: [TCPSegment.Flags.fin, [], [.fin, .psh], [.psh]], [0, 5])
    func bareSegments(flags: TCPSegment.Flags, payloadCount: Int) throws {
        let payload = [UInt8](repeating: 0x41, count: payloadCount)
        let result = try replies(flags: flags, payload: payload)
        let length = UInt32(payloadCount) + (flags.contains(.fin) ? 1 : 0)
        // RFC 9293 3.10.7.1: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
        #expect(result.closed == [
            Reply(
                flags: [.rst, .ack], sequenceNumber: SequenceNumber(0),
                acknowledgmentNumber: SequenceNumber(7_000 + length), window: 0, payloadCount: 0)
        ])
        #expect(result.listening == result.closed)
        #expect(result.listeningPorts == [443])
    }

    @Test("ACK가 있는 세그먼트와 RST에도 두 포트의 답이 같다", arguments: [TCPSegment.Flags.ack, [.fin, .ack], [.rst], [.rst, .ack]])
    func acknowledgedAndResetSegments(flags: TCPSegment.Flags) throws {
        let result = try replies(flags: flags, payload: [])
        #expect(result.listening == result.closed)
        #expect(result.closed.isEmpty == flags.contains(.rst))
    }
}
