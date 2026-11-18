import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// A listening port answers non-SYN segments exactly as a non-listening port does. The inbound filter checks only SYN against the ACL (contract behavior X), so if replies
/// differ, a peer blocked by the ACL can identify listening ports using FIN-only segments. Contract `docs/contracts/SwiftailNetstack.md` behavior S3.
@Suite("Stack replies on listening and non-listening ports")
struct StackListenProbeTests {
    /// The reply without its ports.
    struct Reply: Equatable {
        var flags: TCPSegment.Flags
        var sequenceNumber: SequenceNumber
        var acknowledgmentNumber: SequenceNumber
        var window: UInt16
        var payloadCount: Int
    }

    /// The replies to the same segment delivered to a listening port (443) and a non-listening port (444).
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
        "A listening port also replies with RST to a segment without SYN, ACK, or RST, and the reply matches the non-listening port's flags and numbers",
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

    @Test("Both ports also give the same replies to segments with ACK and to RST", arguments: [TCPSegment.Flags.ack, [.fin, .ack], [.rst], [.rst, .ack]])
    func acknowledgedAndResetSegments(flags: TCPSegment.Flags) throws {
        let result = try replies(flags: flags, payload: [])
        #expect(result.listening == result.closed)
        #expect(result.closed.isEmpty == flags.contains(.rst))
    }
}
