import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Before an application accepts a connection (while in the listener queue), the receive window is capped at 16KiB. The receive buffer grows to the last written position, so with the window fully
/// open, a peer could allocate 256KiB per connection with only 1 in-order byte and 1 byte at the end of the window. Acceptance opens the window to the entire buffer.
/// Contract `docs/contracts/SwiftailNetstack.md` behavior S5, M.
@Suite("Stack receive window before acceptance")
struct StackUnacceptedWindowTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)
    /// The stack's Window Scale shift.
    static let shift = TCPConnection.ownWindowShift
    /// Contract behavior M: receive window before acceptance.
    static let unacceptedWindow = 16 * 1024

    /// A remote `peer` with window scaling enabled completes the handshake. The connection stays queued. Returns the peer's next ACK number.
    func handshake(
        _ stack: inout TCPStack, from peer: IPEndpoint, at now: ContinuousClock.Instant
    ) throws -> SequenceNumber {
        var syn = peerSegment(from: peer, to: Self.server, sequence: 1_000, flags: [.syn])
        syn.windowScale = 7
        let synAck = try #require(stack.receive(syn.packet, at: now).segments.first)
        #expect(synAck.flags == [.syn, .ack])
        #expect(Int(synAck.window) == Self.unacceptedWindow)
        let acknowledgment = synAck.sequenceNumber.advanced(by: 1)
        let ack = peerSegment(from: peer, to: Self.server, sequence: 1_001, acknowledgment: acknowledgment, flags: [.ack])
        _ = stack.receive(ack.packet, at: now)
        return acknowledgment
    }

    /// The peer sends 1 in-order byte, reads the window advertised in the ACK, and sends 1 more byte at the last position in that window. Returns the advertised window.
    func stretchWindow(
        _ stack: inout TCPStack, from peer: IPEndpoint, acknowledgment: SequenceNumber, at now: ContinuousClock.Instant
    ) throws -> Int {
        let first = peerSegment(
            from: peer, to: Self.server, sequence: 1_001, acknowledgment: acknowledgment, flags: [.ack], payload: [1])
        let outputs = stack.receive(first.packet, at: now) + stack.advance(to: now + .milliseconds(40))
        let ack = try #require(outputs.segments.last)
        #expect(ack.acknowledgmentNumber == SequenceNumber(1_002))
        let window = Int(ack.window) << Self.shift
        let last = peerSegment(
            from: peer, to: Self.server, sequence: UInt32(1_002 + window - 1), acknowledgment: acknowledgment,
            flags: [.ack], payload: [2])
        _ = stack.receive(last.packet, at: now + .milliseconds(40))
        return window
    }

    func allocatedByteCount(_ stack: TCPStack) -> Int {
        stack.connections.values.reduce(0) { $0 + $1.connection.receiveBuffer.allocatedByteCount }
    }

    @Test("Even if 32 queued connections receive out to their window edges, their receive buffers total at most 32 × 16KiB")
    func queuedConnectionsHoldSmallBuffers() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: start)
        let listener = try stack.listen(on: 443)
        for index in 0..<32 {
            let now = start + .milliseconds(index * 50)
            // A peer has 16 slots in the listener queue, so use two addresses.
            let peer = IPEndpoint(address: StackHosts.peer(UInt8(1 + index / 16)), port: UInt16(2_000 + index))
            let acknowledgment = try handshake(&stack, from: peer, at: now)
            let window = try stretchWindow(&stack, from: peer, acknowledgment: acknowledgment, at: now)
            #expect(window < Self.unacceptedWindow)
        }
        #expect(stack.listeners[listener]?.queue.count == 32)
        // Each connection holds 1 in-order byte and 1 byte at the end of the window.
        #expect(stack.connections.values.allSatisfy {
            $0.connection.readableByteCount == 1 && $0.connection.receiveBuffer.outOfOrderByteCount == 1
        })
        #expect(allocatedByteCount(stack) <= 32 * Self.unacceptedWindow)
    }

    @Test("On acceptance, a window update ACK advertises the entire buffer and data at the end of that window is accepted")
    func acceptOpensWindow() throws {
        let now = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        let listener = try stack.listen(on: 443)
        let peer = IPEndpoint(address: StackHosts.peer(1), port: 2_000)
        let acknowledgment = try handshake(&stack, from: peer, at: now)

        let popped = stack.accept(from: listener, at: now)
        let accepted = try #require(popped)
        let update = try #require(accepted.outputs.segments.first)
        #expect(accepted.outputs.segments.count == 1)
        #expect(update.flags == [.ack])
        #expect(update.acknowledgmentNumber == SequenceNumber(1_001))
        let window = Int(update.window) << Self.shift
        #expect(window == ReceiveBuffer.defaultCapacity)

        let last = peerSegment(
            from: peer, to: Self.server, sequence: UInt32(1_001 + window - 1), acknowledgment: acknowledgment,
            flags: [.ack], payload: [9])
        _ = stack.receive(last.packet, at: now)
        #expect(stack.connections[accepted.connection]?.connection.receiveBuffer.outOfOrderByteCount == 1)
        // The buffer of a connection held by the application grows to the written position as before.
        #expect(allocatedByteCount(stack) == ReceiveBuffer.defaultCapacity)
    }

    @Test("Accepts up to only 16KiB before acceptance and receives the rest afterward")
    func transferAcrossAccept() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let (clientID, outputs) = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()

        let upload = patternBytes(count: 200_000, seed: 4)
        var sent = pair.write(upload, to: clientID, from: .client)
        try pair.run(for: .seconds(2))
        let queued = try #require(pair.server.listeners[listener]?.queue.first)
        #expect(pair.server.connection(queued)?.readableByteCount == Self.unacceptedWindow)

        let popped = pair.server.accept(from: listener, at: pair.now)
        let accepted = try #require(popped)
        pair.collect(accepted.outputs, from: .server)
        var received: [UInt8] = []
        let deadline = pair.now + .seconds(30)
        while received.count < upload.count, pair.now < deadline {
            if sent < upload.count { sent += pair.write(Array(upload[sent...]), to: clientID, from: .client) }
            try pair.deliver()
            received += pair.read(accepted.connection, from: .server)
            try pair.run(for: .milliseconds(5))
        }
        #expect(received == upload)
    }
}
