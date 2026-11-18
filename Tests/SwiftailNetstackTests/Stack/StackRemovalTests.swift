import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Stack duties when ending connections: local address changes, remote address owner changes, listener closure, application-released connections, and old IDs.
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors S5·S9, X10, and test 11.
@Suite("Stack connection termination")
struct StackRemovalTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)

    @Test("Connections to an address that is no longer local end with peerRemoved without sending anything")
    func localAddressRemoved() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let v4 = try pair.open(listener: listener)
        let v6 = try pair.open(listener: listener, ipv6: true)
        let outputs = pair.client.setLocalAddresses([WireHosts.v6a])
        #expect(outputs.count == 1)
        #expect(outputs.events.map(\.withoutStatistics) == [.closed(v4.client, .peerRemoved, .unchecked)])
        #expect(pair.client.connection(v4.client) == nil)
        #expect(pair.client.connection(v6.client) != nil)
        #expect(pair.client.write([1], to: v4.client, at: pair.now) == (0, []))
        // Packets arriving at that address are no longer local.
        _ = pair.write([1, 2], to: v4.server, from: .server)
        try pair.deliver()
        #expect(pair.clientDrops == [.notForUs])
        expectStackInvariants(pair.client)
    }

    /// Before the fix, there was no call to abort a closing connection that the application released with `close`, so node shutdown discarded it without RST.
    @Test("Abort all: emit one RST each for application-held, released with close but still closing, and queued connections, then clear them without events")
    func abortAllResetsEveryConnection() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let held = try pair.open(listener: listener)
        let closing = try pair.open(listener: listener)
        // One connection the server has not accepted (it stays queued).
        let queued = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(queued.outputs, from: .client)
        try pair.deliver()
        // A connection closed by the client: FIN went out, but the connection is still closing because the peer has yet to receive it.
        let closeOutputs = pair.client.close(closing.client, at: pair.now)
        #expect(closeOutputs.segments.contains { $0.flags.contains(.fin) })

        let clientOutputs = pair.client.abortAll()
        #expect(clientOutputs.events.isEmpty)
        #expect(clientOutputs.segments.count == 3)
        #expect(clientOutputs.segments.allSatisfy { $0.flags.contains(.rst) })
        #expect(pair.client.connections.isEmpty)
        expectStackInvariants(pair.client)

        let serverOutputs = pair.server.abortAll()
        #expect(serverOutputs.events.isEmpty)
        #expect(serverOutputs.segments.count == 3)
        #expect(serverOutputs.segments.allSatisfy { $0.flags.contains(.rst) })
        #expect(pair.server.connections.isEmpty)
        #expect(pair.server.listeners[listener]?.queue.isEmpty == true)
        expectStackInvariants(pair.server)
        _ = held
    }

    @Test("Ends connections for the remote address: reports application-held connections and silently removes queued and opening connections")
    func remoteAddressRemoved() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        let listener = try stack.listen(on: 443)
        let peer = StackHosts.peer(7)
        var accepted: [TCPStack.ConnectionID] = []
        for port in UInt16(1_000)..<1_003 {
            let source = IPEndpoint(address: peer, port: port)
            let synOutputs = stack.receive(
                peerSegment(from: source, to: Self.server, sequence: 10, flags: [.syn]).packet, at: .now)
            let synAck = try #require(synOutputs.segments.first)
            let ack = peerSegment(
                from: source, to: Self.server, sequence: 11, acknowledgment: synAck.sequenceNumber.advanced(by: 1),
                flags: [.ack])
            _ = stack.receive(ack.packet, at: .now)
            if port == 1_000, let id = stack.accept(from: listener, at: .now)?.connection { accepted.append(id) }
        }
        _ = stack.receive(
            peerSegment(from: IPEndpoint(address: peer, port: 2_000), to: Self.server, flags: [.syn]).packet, at: .now)
        let other = IPEndpoint(address: StackHosts.peer(8), port: 1_000)
        _ = stack.receive(peerSegment(from: other, to: Self.server, flags: [.syn]).packet, at: .now)
        #expect(stack.connections.count == 5)

        let outputs = stack.removeConnections(toRemoteAddress: peer)
        #expect(outputs.count == 1)
        #expect(outputs.events.map(\.withoutStatistics) == [.closed(accepted[0], .peerRemoved, .unchecked)])
        #expect(stack.connections.count == 1)
        #expect(stack.listeners[listener]?.queue.isEmpty == true)
        #expect(stack.halfOpenCount == 1)
        #expect(stack.halfOpenCountByAddress[peer] == nil)
        expectStackInvariants(stack)
    }

    @Test("Closing a listener resets queued connections and silently drops opening connections. Dequeued connections stay intact")
    func stopListening() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let accepted = try pair.open(listener: listener)
        let (queuedClient, outputs) = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        // One opening connection: the client's final ACK is lost.
        let (_, synOutputs) = try pair.client.connect(to: Self.server, at: pair.now)
        let syn = try #require(synOutputs.packets.first)
        _ = pair.server.receive(syn, at: pair.now)
        #expect(pair.server.halfOpenCount == 1)
        #expect(pair.server.listeners[listener]?.queue.count == 1)

        let closing = pair.server.stopListening(listener)
        let resets = closing.segments
        #expect(resets.count == 1)
        #expect(resets.first?.flags == [.rst])
        #expect(resets.first?.destination == pair.client.connection(queuedClient)?.localEndpoint)
        #expect(closing.events.isEmpty)
        #expect(pair.server.connections.count == 1)
        #expect(pair.server.connection(accepted.server) != nil)
        #expect(pair.server.halfOpenCount == 0)
        #expect(pair.server.listenersByPort.isEmpty)

        pair.collect(closing, from: .server)
        try pair.deliver()
        #expect(pair.clientEvents.map(\.withoutStatistics).contains(.closed(queuedClient, .reset, .unchecked)))
        expectStackInvariants(pair.server)
    }

    @Test("The stack finishes a connection released with close without emitting events. Calls with an old ID do nothing")
    func releasedConnection() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        let eventsBefore = pair.serverEvents
        _ = pair.write([1, 2, 3], to: ids.client, from: .client)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        try pair.run(for: .seconds(1))
        // Data arriving after close gets RST (SHLD-3), but the server gets no event because the connection was released.
        #expect(pair.serverEvents == eventsBefore)
        #expect(pair.server.connections.isEmpty)
        #expect(pair.server.read(upTo: 10, from: ids.server, at: pair.now) == ([], []))
        #expect(pair.server.write([1], to: ids.server, at: pair.now) == (0, []))
        #expect(pair.server.close(ids.server, at: pair.now).isEmpty)
        #expect(pair.server.abort(ids.server, at: pair.now).isEmpty)
        #expect(pair.server.finishWriting(ids.server, at: pair.now).isEmpty)
    }

    @Test("A queued connection cannot be called by ID before dequeue")
    func queuedConnectionIsNotApplications() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let (_, outputs) = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        let queued = try #require(pair.server.listeners[listener]?.queue.first)
        #expect(pair.server.abort(queued, at: pair.now).isEmpty)
        #expect(pair.server.connection(queued)?.state == .established)
    }
}
