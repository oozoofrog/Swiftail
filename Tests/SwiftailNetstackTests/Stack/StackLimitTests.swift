import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Limits: 16 listeners, 64 opening connections and 16 per address, 32 in the accept queue, 256 connections, and 1,024 TIME-WAIT records (for 64 connections and records per address, see
/// `StackPeerShareTests`).
/// Excess SYNs are dropped without a response and reported as `limitReached`. The stack accepts SYNs again once space frees up.
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors S3~S6, X7, M, and test 11.
@Suite("Stack limits")
struct StackLimitTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)

    func makeServer() -> TCPStack {
        StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
    }

    @Test("Allows one listener per port and up to 16 listeners. Closing frees that port for reopening, and the old ID leaves the new listener alone")
    func listeners() throws {
        var stack = makeServer()
        var ids: [TCPStack.ListenerID] = []
        for port in UInt16(1)...16 {
            ids.append(try stack.listen(on: port))
        }
        #expect(throws: TCPStack.ListenError.limitReached) { try stack.listen(on: 17) }
        #expect(throws: TCPStack.ListenError.addressInUse) { try stack.listen(on: 3) }
        _ = stack.stopListening(ids[2])
        let reopened = try stack.listen(on: 3)
        #expect(reopened != ids[2])
        #expect(stack.stopListening(ids[2]).isEmpty)
        #expect(stack.listenersByPort[3] == reopened)
    }

    @Test("Allows up to 16 opening connections for one remote address and drops the 17th SYN without a response")
    func halfOpenPerAddress() throws {
        var stack = makeServer()
        _ = try stack.listen(on: 443)
        let address = StackHosts.peer(1)
        for port in UInt16(1_000)..<1_016 {
            let syn = peerSegment(from: IPEndpoint(address: address, port: port), to: Self.server, flags: [.syn])
            #expect(stack.receive(syn.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        let extra = peerSegment(from: IPEndpoint(address: address, port: 1_016), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        // Accepts a different address.
        let other = peerSegment(from: IPEndpoint(address: StackHosts.peer(2), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(other.packet, at: .now).segments.count == 1)
        #expect(stack.halfOpenCountByAddress[address] == 16)
        expectStackInvariants(stack)
    }

    @Test("Allows up to 64 opening connections stack-wide. Accepts more once they disappear within 247 seconds")
    func halfOpenTotal() throws {
        var stack = makeServer()
        let start = ContinuousClock.now
        _ = try stack.listen(on: 443)
        _ = try stack.listen(on: 8_443)
        for host in UInt8(1)...4 {
            for port in UInt16(1_000)..<1_016 {
                let destination = IPEndpoint(address: WireHosts.v4b, port: port % 2 == 0 ? 443 : 8_443)
                let syn = peerSegment(from: IPEndpoint(address: StackHosts.peer(host), port: port), to: destination, flags: [.syn])
                #expect(stack.receive(syn.packet, at: start).segments.count == 1)
            }
        }
        #expect(stack.halfOpenCount == 64)
        let extra = peerSegment(from: IPEndpoint(address: StackHosts.peer(5), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: start) == [.dropped(.limitReached(.halfOpenConnections))])
        expectStackInvariants(stack)

        // Disappears at 247 seconds after 7 SYN-ACK retransmissions (contract behaviors R4, X7). Stays until then.
        _ = advance(&stack, to: start + .seconds(246))
        #expect(stack.halfOpenCount == 64)
        let late = advance(&stack, to: start + .seconds(248))
        #expect(late.events.isEmpty)
        #expect(stack.halfOpenCount == 0)
        #expect(stack.connections.isEmpty)
        #expect(stack.receive(extra.packet, at: start + .seconds(248)).segments.count == 1)
        expectStackInvariants(stack)
    }

    /// Advances to `limit`, calling `advance` at every `nextDeadline` as a node does.
    func advance(_ stack: inout TCPStack, to limit: ContinuousClock.Instant) -> [TCPStack.Output] {
        var outputs: [TCPStack.Output] = []
        while let deadline = stack.nextDeadline, deadline <= limit {
            outputs += stack.advance(to: deadline)
        }
        return outputs + stack.advance(to: limit)
    }

    /// Completes the handshake from remote `peer` into `stack`. Returns the event if the connection enters the listener queue.
    func handshake(_ stack: inout TCPStack, from peer: IPEndpoint) -> [TCPStack.Output] {
        let syn = peerSegment(from: peer, to: Self.server, sequence: 1_000, flags: [.syn])
        guard let synAck = stack.receive(syn.packet, at: .now).segments.first else { return [] }
        let ack = peerSegment(
            from: peer, to: Self.server, sequence: 1_001, acknowledgment: synAck.sequenceNumber.advanced(by: 1),
            flags: [.ack])
        return stack.receive(ack.packet, at: .now)
    }

    @Test("The accept queue holds up to 32. If full, drops SYNs without a response. Dequeuing allows SYNs again")
    func acceptQueue() throws {
        var stack = makeServer()
        let listener = try stack.listen(on: 443)
        // Each peer has 16 slots in the queue, so fill it with two addresses (`StackPeerGroupTests`).
        for port in UInt16(1_000)..<1_032 {
            let address = StackHosts.peer(port < 1_016 ? 1 : 2)
            #expect(handshake(&stack, from: IPEndpoint(address: address, port: port)) == [.event(.acceptable(listener))])
        }
        #expect(stack.listeners[listener]?.queue.count == 32)
        let peer = IPEndpoint(address: StackHosts.peer(1), port: 2_000)
        let syn = peerSegment(from: peer, to: Self.server, flags: [.syn])
        #expect(stack.receive(syn.packet, at: .now) == [.dropped(.limitReached(.acceptQueue))])

        let popped = stack.accept(from: listener, at: .now)
        let first = try #require(popped?.connection)
        #expect(stack.connection(first)?.remoteEndpoint.port == 1_000)
        #expect(handshake(&stack, from: peer) == [.event(.acceptable(listener))])
        expectStackInvariants(stack)
    }

    @Test("An opening connection takes a slot in the listener's queue too (the queue stays within 32)")
    func acceptQueueCountsHalfOpen() throws {
        var stack = makeServer()
        let listener = try stack.listen(on: 443)
        for port in UInt16(1_000)..<1_020 {
            _ = handshake(&stack, from: IPEndpoint(address: StackHosts.peer(port < 1_010 ? 1 : 20), port: port))
        }
        for host in UInt8(2)...13 {
            let syn = peerSegment(from: IPEndpoint(address: StackHosts.peer(host), port: 1_000), to: Self.server, flags: [.syn])
            #expect(stack.receive(syn.packet, at: .now).segments.count == 1)
        }
        let extra = peerSegment(from: IPEndpoint(address: StackHosts.peer(14), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: .now) == [.dropped(.limitReached(.acceptQueue))])
        #expect(stack.listeners[listener]?.queue.count == 20)
        #expect(stack.listeners[listener]?.halfOpenCount == 12)
        expectStackInvariants(stack)
    }

    @Test("Allows up to 256 connections. Above the limit, connect yields limitReached and SYNs are dropped without a response. Aborting one makes room again")
    func connections() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: .now)
        _ = try stack.listen(on: 9_000)
        // Each remote address allows up to 64 connections, so use four addresses (M6 review A).
        let remotes = [WireHosts.v4b, StackHosts.peer(1), StackHosts.peer(2), StackHosts.peer(3)].map {
            IPEndpoint(address: $0, port: 443)
        }
        let remote = remotes[0]
        var ids: [TCPStack.ConnectionID] = []
        for index in 0..<256 {
            ids.append(try stack.connect(to: remotes[index % 4], at: .now).connection)
        }
        #expect(throws: TCPStack.ConnectError.limitReached) {
            try stack.connect(to: IPEndpoint(address: StackHosts.peer(4), port: 443), at: .now)
        }
        let syn = peerSegment(
            from: IPEndpoint(address: WireHosts.v4b, port: 5_000), to: IPEndpoint(address: WireHosts.v4a, port: 9_000),
            flags: [.syn])
        #expect(stack.receive(syn.packet, at: .now) == [.dropped(.limitReached(.connections))])

        #expect(stack.abort(ids[0], at: .now).events.map(\.withoutStatistics) == [.closed(ids[0], .aborted, .unchecked)])
        #expect(stack.connections.count == 255)
        _ = try stack.connect(to: remote, at: .now)
        expectStackInvariants(stack)
    }

    @Test("Allows up to 1,024 TIME-WAIT records and keeps them until the deadline. Rejects connect and SYN while full")
    func timeWaitRecords() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: start)
        let listener = try stack.listen(on: 443)
        let kept = try stack.acceptHandmade(
            from: IPEndpoint(address: StackHosts.peer(100), port: 1_000), to: Self.server, listener: listener, at: start)
        // Each remote address allows up to 64 records, so fill the limit with sixteen addresses (M6 review A).
        for index in 0..<1_024 {
            let peer = IPEndpoint(address: StackHosts.peer(UInt8(1 + index / 64)), port: UInt16(2_000 + index % 64))
            let id = try stack.acceptHandmade(from: peer, to: Self.server, listener: listener, at: start)
            try stack.closeIntoTimeWait(id, at: start)
        }
        #expect(stack.timeWaitRecords.count == 1_024)
        #expect(stack.connections.count == 1)

        #expect(throws: TCPStack.ConnectError.limitReached) {
            try stack.connect(to: IPEndpoint(address: StackHosts.peer(101), port: 443), at: start)
        }
        let syn = peerSegment(from: IPEndpoint(address: StackHosts.peer(102), port: 5_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(syn.packet, at: start) == [.dropped(.limitReached(.timeWaitRecords))])

        // Once the records are full, a connection entering TIME-WAIT stays a connection and completes TIME-WAIT without becoming a record.
        try stack.closeIntoTimeWait(kept, at: start)
        #expect(stack.timeWaitRecords.count == 1_024)
        #expect(stack.connections.count == 1)
        #expect(stack.connections.values.first?.connection.state == .timeWait)
        expectStackInvariants(stack)

        // Acknowledge a retransmitted FIN for that record's 4-tuple.
        let (tuple, record) = try #require(stack.timeWaitRecords.first)
        let reply = stack.retransmitFin(to: tuple, at: start)
        #expect(reply.map(\.flags) == [[.ack]])
        #expect(reply.first?.acknowledgmentNumber == record.receiveNext)

        _ = advance(&stack, to: start + .seconds(59))
        #expect(stack.timeWaitRecords.count == 1_024)
        _ = advance(&stack, to: start + .seconds(61))
        #expect(stack.timeWaitRecords.isEmpty)
        #expect(stack.connections.isEmpty)
        _ = try stack.connect(to: IPEndpoint(address: StackHosts.peer(101), port: 443), at: start + .seconds(61))
        expectStackInvariants(stack)
    }
}
