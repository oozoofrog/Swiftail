import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 연결 없는 곳의 RST와 LISTEN의 규칙(RFC 9293 3.10.7.1·3.10.7.2).
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S2·S3, X8·X9와 시험 11.
@Suite("스택: RST와 LISTEN")
struct StackResetTests {
    static let peer = IPEndpoint(address: WireHosts.v4a, port: 40_000)
    static let closedPort = IPEndpoint(address: WireHosts.v4b, port: 80)
    static let listening = IPEndpoint(address: WireHosts.v4b, port: 443)

    func makeStack() throws -> TCPStack {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        _ = try stack.listen(on: 443)
        return stack
    }

    @Test("연결 없는 곳의 ACK 없는 세그먼트: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>")
    func resetWithoutAcknowledgment() throws {
        var stack = try makeStack()
        let syn = peerSegment(from: Self.peer, to: Self.closedPort, sequence: 1_000, flags: [.syn])
        let reply = stack.receive(syn.packet, at: .now).segments
        #expect(reply.count == 1)
        #expect(reply.first?.flags == [.rst, .ack])
        #expect(reply.first?.sequenceNumber == SequenceNumber(0))
        #expect(reply.first?.acknowledgmentNumber == SequenceNumber(1_001))
        #expect(reply.first?.source == Self.closedPort)
        #expect(reply.first?.destination == Self.peer)
        #expect(reply.first?.payload.isEmpty == true)

        // SEG.LEN은 데이터와 FIN을 센다.
        let finWithData = peerSegment(from: Self.peer, to: Self.closedPort, sequence: 7, flags: [.fin], payload: [1, 2, 3, 4, 5])
        #expect(stack.receive(finWithData.packet, at: .now).segments.first?.acknowledgmentNumber == SequenceNumber(13))
        #expect(stack.connections.isEmpty)
    }

    @Test("연결 없는 곳의 ACK 있는 세그먼트: <SEQ=SEG.ACK><CTL=RST>, IPv6도 같다")
    func resetWithAcknowledgment() throws {
        var stack = try makeStack()
        let data = peerSegment(
            from: Self.peer, to: Self.closedPort, sequence: 1_000, acknowledgment: SequenceNumber(777), flags: [.ack, .psh],
            payload: [1, 2, 3])
        let reply = stack.receive(data.packet, at: .now).segments
        #expect(reply.count == 1)
        #expect(reply.first?.flags == [.rst])
        #expect(reply.first?.sequenceNumber == SequenceNumber(777))

        let data6 = peerSegment(
            from: IPEndpoint(address: WireHosts.v6a, port: 40_000), to: IPEndpoint(address: WireHosts.v6b, port: 80),
            acknowledgment: SequenceNumber(99), flags: [.ack])
        let reply6 = stack.receive(data6.packet, at: .now).segments
        #expect(reply6.first?.flags == [.rst])
        #expect(reply6.first?.sequenceNumber == SequenceNumber(99))
        #expect(reply6.first?.destination.address == WireHosts.v6a)
    }

    @Test("RST에는 답하지 않는다(연결 없는 곳, 리스너)")
    func noReplyToReset() throws {
        var stack = try makeStack()
        for destination in [Self.closedPort, Self.listening] {
            for flags: TCPSegment.Flags in [[.rst], [.rst, .ack], [.rst, .syn]] {
                let reset = peerSegment(from: Self.peer, to: destination, acknowledgment: SequenceNumber(5), flags: flags)
                #expect(stack.receive(reset.packet, at: .now).isEmpty)
            }
        }
        #expect(stack.connections.isEmpty)
    }

    @Test("리스너에 온 ACK에는 <SEQ=SEG.ACK><CTL=RST>, SYN도 ACK도 RST도 없으면 듣지 않는 포트처럼 <RST,ACK>로 답한다")
    func listenerRules() throws {
        var stack = try makeStack()
        let ack = peerSegment(from: Self.peer, to: Self.listening, acknowledgment: SequenceNumber(4_321), flags: [.ack])
        let reply = stack.receive(ack.packet, at: .now).segments
        #expect(reply.count == 1)
        #expect(reply.first?.flags == [.rst])
        #expect(reply.first?.sequenceNumber == SequenceNumber(4_321))

        let synAck = peerSegment(from: Self.peer, to: Self.listening, acknowledgment: SequenceNumber(10), flags: [.syn, .ack])
        #expect(stack.receive(synAck.packet, at: .now).segments.map(\.flags) == [[.rst]])

        // 듣지 않는 포트와 같은 답이어야 한다(`StackListenProbeTests`).
        for flags: TCPSegment.Flags in [[], [.fin], [.psh]] {
            let stray = peerSegment(from: Self.peer, to: Self.listening, flags: flags, payload: [1])
            #expect(stack.receive(stray.packet, at: .now).segments.map(\.flags) == [[.rst, .ack]])
        }
        #expect(stack.connections.isEmpty)
    }

    @Test("리스너에 온 SYN은 SYN-ACK로 답하고 맺는 중인 연결이 된다")
    func listenerAcceptsSynchronize() throws {
        var stack = try makeStack()
        let syn = peerSegment(from: Self.peer, to: Self.listening, sequence: 1_000, flags: [.syn])
        let reply = stack.receive(syn.packet, at: .now)
        #expect(reply.events.isEmpty)
        let synAck = try #require(reply.segments.first)
        #expect(synAck.flags == [.syn, .ack])
        #expect(synAck.acknowledgmentNumber == SequenceNumber(1_001))
        #expect(stack.halfOpenCount == 1)
        expectStackInvariants(stack)
    }

    @Test("상대 MSS가 64보다 작은 SYN에는 RST로 답하고 연결을 만들지 않는다")
    func tinySegmentSize() throws {
        var stack = try makeStack()
        let syn = peerSegment(from: Self.peer, to: Self.listening, sequence: 1_000, flags: [.syn], maximumSegmentSize: 40)
        let reply = stack.receive(syn.packet, at: .now).segments
        #expect(reply.map(\.flags) == [[.rst, .ack]])
        #expect(reply.first?.acknowledgmentNumber == SequenceNumber(1_001))
        #expect(stack.connections.isEmpty)
        #expect(stack.halfOpenCount == 0)
    }
}
