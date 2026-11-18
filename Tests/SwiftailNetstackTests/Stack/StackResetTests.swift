import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// RST without a connection and the LISTEN rules (RFC 9293 3.10.7.1·3.10.7.2).
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors S2·S3, X8·X9, and test 11.
@Suite("Stack RST and LISTEN")
struct StackResetTests {
    static let peer = IPEndpoint(address: WireHosts.v4a, port: 40_000)
    static let closedPort = IPEndpoint(address: WireHosts.v4b, port: 80)
    static let listening = IPEndpoint(address: WireHosts.v4b, port: 443)

    func makeStack() throws -> TCPStack {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        _ = try stack.listen(on: 443)
        return stack
    }

    @Test("A segment without ACK where there is no connection: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>")
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

        // SEG.LEN counts data and FIN.
        let finWithData = peerSegment(from: Self.peer, to: Self.closedPort, sequence: 7, flags: [.fin], payload: [1, 2, 3, 4, 5])
        #expect(stack.receive(finWithData.packet, at: .now).segments.first?.acknowledgmentNumber == SequenceNumber(13))
        #expect(stack.connections.isEmpty)
    }

    @Test("A segment with ACK where there is no connection: <SEQ=SEG.ACK><CTL=RST>, including IPv6")
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

    @Test("Does not respond to RST (no connection or a listener)")
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

    @Test("An ACK to a listener gets <SEQ=SEG.ACK><CTL=RST>. With no SYN, ACK, or RST, the listener responds with <RST,ACK> as a non-listening port would")
    func listenerRules() throws {
        var stack = try makeStack()
        let ack = peerSegment(from: Self.peer, to: Self.listening, acknowledgment: SequenceNumber(4_321), flags: [.ack])
        let reply = stack.receive(ack.packet, at: .now).segments
        #expect(reply.count == 1)
        #expect(reply.first?.flags == [.rst])
        #expect(reply.first?.sequenceNumber == SequenceNumber(4_321))

        let synAck = peerSegment(from: Self.peer, to: Self.listening, acknowledgment: SequenceNumber(10), flags: [.syn, .ack])
        #expect(stack.receive(synAck.packet, at: .now).segments.map(\.flags) == [[.rst]])

        // The reply must match the non-listening port (`StackListenProbeTests`).
        for flags: TCPSegment.Flags in [[], [.fin], [.psh]] {
            let stray = peerSegment(from: Self.peer, to: Self.listening, flags: flags, payload: [1])
            #expect(stack.receive(stray.packet, at: .now).segments.map(\.flags) == [[.rst, .ack]])
        }
        #expect(stack.connections.isEmpty)
    }

    @Test("A SYN to a listener gets a SYN-ACK and becomes an opening connection")
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

    @Test("A SYN with a peer MSS below 64 gets RST and creates no connection")
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
