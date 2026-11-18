// Shared stack test helpers. Provides `StackPair` to connect two stacks in memory, helpers for feeding handcrafted packets to one stack,
// and table invariant checks. The harness that injects loss and reordering belongs to M6-6.

import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Fake addresses and secrets for tests. The addresses are not from a real tailnet.
enum StackHosts {
    static let clientAddresses = [WireHosts.v4a, WireHosts.v6a]
    static let serverAddresses = [WireHosts.v4b, WireHosts.v6b]
    static let secret = (0..<32).map { UInt8($0) &* 7 &+ 3 }

    /// 100.64.1.`host`.
    static func peer(_ host: UInt8) -> IPAddress {
        WireHosts.address("100.64.1.\(host)")
    }

    static func makeStack(
        addresses: [IPAddress], now: ContinuousClock.Instant, secret: [UInt8] = StackHosts.secret
    ) -> TCPStack {
        var stack = TCPStack(isnSecret: secret, now: now)
        _ = stack.setLocalAddresses(addresses)
        return stack
    }
}

extension Array where Element == TCPStack.Output {
    var packets: [[UInt8]] {
        compactMap { if case .ipPacket(let packet) = $0 { packet } else { nil } }
    }

    /// Segments parsed from emitted packets. Packets emitted by the stack always parse (otherwise the test fails).
    var segments: [TCPSegment] {
        packets.map { packet in
            do {
                return try TCPSegment(parsingIPPacket: packet)
            } catch {
                Issue.record("The stack emitted a packet that could not be parsed: \(error)")
                return TCPSegment(
                    source: IPEndpoint(address: WireHosts.v4a, port: 0),
                    destination: IPEndpoint(address: WireHosts.v4a, port: 0), sequenceNumber: SequenceNumber(0),
                    flags: [])
            }
        }
    }

    var events: [TCPStack.Event] {
        compactMap { if case .event(let event) = $0 { event } else { nil } }
    }

    var drops: [TCPStack.Drop] {
        compactMap { if case .dropped(let drop) = $0 { drop } else { nil } }
    }

    /// A connection released by the application ended (`.releasedConnectionClosed`).
    var releasedCloses: [ReleasedClose] {
        compactMap {
            if case .releasedConnectionClosed(let reason, let statistics) = $0 {
                ReleasedClose(reason: reason, statistics: statistics)
            } else {
                nil
            }
        }
    }
}

/// The payload of `.releasedConnectionClosed`.
struct ReleasedClose: Equatable {
    var reason: TCPStack.CloseReason
    var statistics: TCPConnection.Statistics
}

extension TCPStack.Event {
    /// An event with `.closed` statistics replaced by `TCPConnection.Statistics.unchecked`. Used by tests comparing only event order, ID, and reason
    /// (`ConnectionStatisticsTests` covers statistics).
    var withoutStatistics: Self {
        guard case .closed(let id, let reason, _) = self else { return self }
        return .closed(id, reason, .unchecked)
    }
}

extension TCPConnection.Statistics {
    /// Placeholder for statistics that are not compared.
    static let unchecked = Self(openedAt: .now)
}

extension TCPSegment {
    /// Packet bytes the test will feed to the stack.
    var packet: [UInt8] {
        guard let packet = ipPacket() else { fatalError("Could not turn the test segment into a packet: \(self)") }
        return packet
    }
}

/// Creates a compact representation of a segment sent by the peer.
func peerSegment(
    from source: IPEndpoint, to destination: IPEndpoint, sequence: UInt32 = 5_000,
    acknowledgment: SequenceNumber = SequenceNumber(0), flags: TCPSegment.Flags, payload: [UInt8] = [],
    window: UInt16 = 65_535, maximumSegmentSize: UInt16? = nil
) -> TCPSegment {
    TCPSegment(
        source: source, destination: destination, sequenceNumber: SequenceNumber(sequence),
        acknowledgmentNumber: acknowledgment, flags: flags, window: window,
        maximumSegmentSize: maximumSegmentSize ?? (flags.contains(.syn) ? 1_240 : nil), payload: payload)
}

/// Connects two stacks (`client` uses IPv4 and IPv6 addresses `v4a` and `v6a`, and `server` uses `v4b` and `v6b`) over a lossless link. The test provides the time.
///
/// After feeding the accumulated packets as a batch to one side, calls `advance(to:)` at the same time to get the delayed ACK (as the node does when batching).
struct StackPair {
    enum Side { case client, server }

    var now: ContinuousClock.Instant
    var client: TCPStack
    var server: TCPStack
    var clientEvents: [TCPStack.Event] = []
    var serverEvents: [TCPStack.Event] = []
    var clientDrops: [TCPStack.Drop] = []
    var serverDrops: [TCPStack.Drop] = []
    var clientReleasedCloses: [ReleasedClose] = []
    var serverReleasedCloses: [ReleasedClose] = []
    /// All segments emitted by each side.
    var clientSent: [TCPSegment] = []
    var serverSent: [TCPSegment] = []
    var toServer: [[UInt8]] = []
    var toClient: [[UInt8]] = []

    init(now: ContinuousClock.Instant = .now) {
        self.now = now
        client = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: now)
        server = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now, secret: Array(StackHosts.secret.reversed()))
    }

    mutating func collect(_ outputs: [TCPStack.Output], from side: Side) {
        for output in outputs {
            switch (output, side) {
            case (.ipPacket(let packet), .client):
                toServer.append(packet)
                if let segment = try? TCPSegment(parsingIPPacket: packet) { clientSent.append(segment) }
            case (.ipPacket(let packet), .server):
                toClient.append(packet)
                if let segment = try? TCPSegment(parsingIPPacket: packet) { serverSent.append(segment) }
            case (.event(let event), .client): clientEvents.append(event)
            case (.event(let event), .server): serverEvents.append(event)
            case (.dropped(let drop), .client): clientDrops.append(drop)
            case (.dropped(let drop), .server): serverDrops.append(drop)
            case (.releasedConnectionClosed(let reason, let statistics), .client):
                clientReleasedCloses.append(ReleasedClose(reason: reason, statistics: statistics))
            case (.releasedConnectionClosed(let reason, let statistics), .server):
                serverReleasedCloses.append(ReleasedClose(reason: reason, statistics: statistics))
            }
        }
    }

    /// Delivers all accumulated packets. The recipient emits an ACK with `advance(to: now)` after receiving a batch.
    mutating func deliver() throws {
        var rounds = 0
        while !toServer.isEmpty || !toClient.isEmpty {
            rounds += 1
            guard rounds < 100_000 else { throw HarnessError(description: "The exchange did not finish") }
            let forServer = toServer
            toServer = []
            for packet in forServer {
                collect(server.receive(packet, at: now), from: .server)
            }
            if !forServer.isEmpty { collect(server.advance(to: now), from: .server) }
            let forClient = toClient
            toClient = []
            for packet in forClient {
                collect(client.receive(packet, at: now), from: .client)
            }
            if !forClient.isEmpty { collect(client.advance(to: now), from: .client) }
        }
    }

    /// Runs timers and exchanges packets up to `limit`. On return, `now` equals `limit`.
    mutating func run(until limit: ContinuousClock.Instant) throws {
        try deliver()
        while let next = [client.nextDeadline, server.nextDeadline].compactMap({ $0 }).min(), next <= limit {
            now = max(now, next)
            collect(client.advance(to: now), from: .client)
            collect(server.advance(to: now), from: .server)
            try deliver()
        }
        now = max(now, limit)
    }

    mutating func run(for duration: Duration) throws {
        try run(until: now + duration)
    }

    /// The client connects to the server's `port`, and the server dequeues the connection. Returns both sides' IDs.
    mutating func open(
        port: UInt16 = 443, listener: TCPStack.ListenerID, ipv6: Bool = false
    ) throws -> (client: TCPStack.ConnectionID, server: TCPStack.ConnectionID) {
        let address = ipv6 ? WireHosts.v6b : WireHosts.v4b
        let (clientID, outputs) = try client.connect(to: IPEndpoint(address: address, port: port), at: now)
        collect(outputs, from: .client)
        try deliver()
        guard let accepted = server.accept(from: listener, at: now) else {
            throw HarnessError(description: "The server queue was empty: \(serverDrops)")
        }
        collect(accepted.outputs, from: .server)
        try deliver()
        return (clientID, accepted.connection)
    }

    mutating func write(_ bytes: [UInt8], to id: TCPStack.ConnectionID, from side: Side) -> Int {
        switch side {
        case .client:
            let (accepted, outputs) = client.write(bytes[...], to: id, at: now)
            collect(outputs, from: .client)
            return accepted
        case .server:
            let (accepted, outputs) = server.write(bytes[...], to: id, at: now)
            collect(outputs, from: .server)
            return accepted
        }
    }

    mutating func read(_ id: TCPStack.ConnectionID, from side: Side) -> [UInt8] {
        switch side {
        case .client:
            let (bytes, outputs) = client.read(upTo: .max, from: id, at: now)
            collect(outputs, from: .client)
            return bytes
        case .server:
            let (bytes, outputs) = server.read(upTo: .max, from: id, at: now)
            collect(outputs, from: .server)
            return bytes
        }
    }

    /// The client closes first and the server closes next. The client retains TIME-WAIT.
    mutating func closeFromClient(_ ids: (client: TCPStack.ConnectionID, server: TCPStack.ConnectionID)) throws {
        collect(client.close(ids.client, at: now), from: .client)
        try deliver()
        collect(server.close(ids.server, at: now), from: .server)
        try deliver()
    }
}

extension TCPStack {
    /// A handcrafted remote `peer` (ISN 1,000, window 65,535) establishes a connection to the `local` listener, and the application dequeues it.
    mutating func acceptHandmade(
        from peer: IPEndpoint, to local: IPEndpoint, listener: ListenerID, at now: ContinuousClock.Instant
    ) throws -> ConnectionID {
        let syn = peerSegment(from: peer, to: local, sequence: 1_000, flags: [.syn])
        guard let synAck = receive(syn.packet, at: now).segments.first, synAck.flags == [.syn, .ack] else {
            throw HarnessError(description: "No SYN-ACK")
        }
        let ack = peerSegment(
            from: peer, to: local, sequence: 1_001, acknowledgment: synAck.sequenceNumber.advanced(by: 1), flags: [.ack])
        _ = receive(ack.packet, at: now)
        guard let accepted = accept(from: listener, at: now) else { throw HarnessError(description: "The queue was empty") }
        return accepted.connection
    }

    /// The application calls `close` first, and the peer acknowledges this side's FIN and sends its own. Once `advance` at the same time emits the ACK, the connection
    /// becomes a TIME-WAIT record (if the records are not full). Returns the 4-tuple.
    @discardableResult
    mutating func closeIntoTimeWait(_ id: ConnectionID, at now: ContinuousClock.Instant) throws -> FourTuple {
        guard let connection = connection(id) else { throw HarnessError(description: "No connection") }
        _ = close(id, at: now)
        let fin = peerSegment(
            from: connection.remoteEndpoint, to: connection.localEndpoint, sequence: connection.receiveNext.rawValue,
            acknowledgment: connection.sendNext.advanced(by: 1), flags: [.fin, .ack])
        _ = receive(fin.packet, at: now)
        _ = advance(to: now)
        return FourTuple(local: connection.localEndpoint, remote: connection.remoteEndpoint)
    }

    /// Sends a retransmitted peer FIN to the TIME-WAIT record `tuple`. Sends nothing if the record is absent. Returns the reply.
    mutating func retransmitFin(to tuple: FourTuple, at now: ContinuousClock.Instant) -> [TCPSegment] {
        guard let record = timeWaitRecords[tuple] else { return [] }
        let fin = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.advanced(by: .max).rawValue,
            acknowledgment: record.sendNext, flags: [.fin, .ack])
        return receive(fin.packet, at: now).segments
    }
}

/// Checks that the stack's tables agree and stay within limits (contract behavior M).
func expectStackInvariants(_ stack: TCPStack, sourceLocation: SourceLocation = #_sourceLocation) {
    #expect(stack.connections.count <= TCPStack.maximumConnections, sourceLocation: sourceLocation)
    #expect(stack.timeWaitRecords.count <= TCPStack.maximumTimeWaitRecords, sourceLocation: sourceLocation)
    #expect(stack.listeners.count <= TCPStack.maximumListeners, sourceLocation: sourceLocation)
    var halfOpenByAddress: [IPAddress: Int] = [:]
    var halfOpenByListener: [TCPStack.ListenerID: Int] = [:]
    for entry in stack.connections.values {
        if case .halfOpen(let listener) = entry.role {
            #expect(entry.connection.state == .synReceived, sourceLocation: sourceLocation)
            halfOpenByAddress[entry.connection.remoteEndpoint.address, default: 0] += 1
            halfOpenByListener[listener, default: 0] += 1
        }
    }
    let halfOpen = halfOpenByAddress.values.reduce(0, +)
    #expect(stack.halfOpenCount == halfOpen, sourceLocation: sourceLocation)
    #expect(halfOpen <= TCPStack.maximumHalfOpenConnections, sourceLocation: sourceLocation)
    #expect(stack.halfOpenCountByAddress == halfOpenByAddress, sourceLocation: sourceLocation)
    #expect(
        halfOpenByAddress.values.allSatisfy { $0 <= TCPStack.maximumHalfOpenConnectionsPerAddress },
        sourceLocation: sourceLocation)
    for (id, listener) in stack.listeners {
        #expect(listener.halfOpenCount == halfOpenByListener[id, default: 0], sourceLocation: sourceLocation)
        #expect(
            listener.queue.count + listener.halfOpenCount <= TCPStack.maximumAcceptQueueLength,
            sourceLocation: sourceLocation)
        for queued in listener.queue {
            #expect(stack.connections[queued]?.role == .queued(id), sourceLocation: sourceLocation)
        }
    }
    var connectionsByAddress: [IPAddress: Int] = [:]
    for entry in stack.connections.values {
        connectionsByAddress[entry.connection.remoteEndpoint.address, default: 0] += 1
    }
    #expect(stack.connectionCountByAddress == connectionsByAddress, sourceLocation: sourceLocation)
    #expect(
        connectionsByAddress.values.allSatisfy { $0 <= TCPStack.maximumConnectionsPerAddress },
        sourceLocation: sourceLocation)
    var recordsByAddress: [IPAddress: Set<FourTuple>] = [:]
    for tuple in stack.timeWaitRecords.keys {
        recordsByAddress[tuple.remote.address, default: []].insert(tuple)
    }
    #expect(stack.timeWaitTuplesByAddress.mapValues { Set($0) } == recordsByAddress, sourceLocation: sourceLocation)
    #expect(
        stack.timeWaitTuplesByAddress.values.allSatisfy {
            $0.count == Set($0).count && $0.count <= TCPStack.maximumTimeWaitRecordsPerAddress
        }, sourceLocation: sourceLocation)
    #expect(stack.timeWaitRecords.values.allSatisfy { $0.deadline <= $0.lifetimeEnd }, sourceLocation: sourceLocation)
    #expect(stack.earliestTimeWaitDeadline == stack.timeWaitRecords.values.map(\.deadline).min(), sourceLocation: sourceLocation)
    for (tuple, id) in stack.connectionsByTuple {
        #expect(stack.connections[id]?.tuple == tuple, sourceLocation: sourceLocation)
        #expect(stack.timeWaitRecords[tuple] == nil, sourceLocation: sourceLocation)
    }
}
