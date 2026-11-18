// Shared connection test helpers. Provides `ConnectionPair` to connect two connections in memory and helpers for feeding handcrafted segments to one
// connection. The full harness for injecting loss and reordering (`LinkSimulator`) belongs to M6-6. This file contains only what it needs.

import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Fake addresses for tests. They are not real tailnet addresses.
enum ConnectionHosts {
    static let client = IPEndpoint(address: WireHosts.v4a, port: 40_000)
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)
    static let client6 = IPEndpoint(address: WireHosts.v6a, port: 40_000)
    static let server6 = IPEndpoint(address: WireHosts.v6b, port: 443)
}

struct HarnessError: Error, CustomStringConvertible {
    var description: String
}

extension Array where Element == TCPConnection.Output {
    var segments: [TCPSegment] {
        compactMap { if case .segment(let segment) = $0 { segment } else { nil } }
    }

    var events: [TCPConnection.Event] {
        compactMap { if case .event(let event) = $0 { event } else { nil } }
    }
}

extension TCPSegment {
    /// Turns the segment into an IP packet and parses it again. Also exercises the codec (checksum and options).
    func roundTripped() throws -> TCPSegment {
        guard let packet = ipPacket() else { throw HarnessError(description: "Could not create an IP packet: \(self)") }
        return try TCPSegment(parsingIPPacket: packet)
    }
}

/// Test byte sequence. Generated deterministically from a seed.
func patternBytes(count: Int, seed: UInt8 = 7) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed) &+ ($0 >> 8)) }
}

/// Joins two connections (active-open `client` and passive-open `server`) over a lossless link. The test provides the time.
///
/// Segments are delivered after being encoded as IP packets and parsed back. After feeding accumulated segments to one side in a batch, calls `advance(to:)`
/// to get the delayed ACK (as the node does when batching). Use `drop` to drop specific segments.
struct ConnectionPair {
    enum Side { case client, server }

    var now: ContinuousClock.Instant
    var client: TCPConnection
    var server: TCPConnection
    var clientEvents: [TCPConnection.Event] = []
    var serverEvents: [TCPConnection.Event] = []
    /// All segments emitted by each side (including dropped segments), with their times.
    var clientSent: [(at: ContinuousClock.Instant, segment: TCPSegment)] = []
    var serverSent: [(at: ContinuousClock.Instant, segment: TCPSegment)] = []
    var toServer: [TCPSegment] = []
    var toClient: [TCPSegment] = []
    /// When true, drops that segment.
    var drop: (Side, TCPSegment) -> Bool = { _, _ in false }
    /// When false, calls `advance` for each segment without batching ACKs (so duplicate ACKs arrive one at a time).
    var batched = true

    /// A pair that has completed the three-way handshake.
    static func established(
        clientISS: UInt32 = 1_000, serverISS: UInt32 = 900_000,
        client local: IPEndpoint = ConnectionHosts.client, server remote: IPEndpoint = ConnectionHosts.server,
        roundTrip: Duration = .milliseconds(10)
    ) throws -> ConnectionPair {
        var pair = try opened(
            clientISS: clientISS, serverISS: serverISS, client: local, server: remote, roundTrip: roundTrip)
        try pair.deliver()
        guard pair.client.state == .established, pair.server.state == .established else {
            throw HarnessError(description: "Connection was not established: \(pair.client.state), \(pair.server.state)")
        }
        return pair
    }

    /// A pair that has sent SYN and whose server has emitted SYN-ACK. Delivers one hop per half of `roundTrip`.
    static func opened(
        clientISS: UInt32 = 1_000, serverISS: UInt32 = 900_000,
        client local: IPEndpoint = ConnectionHosts.client, server remote: IPEndpoint = ConnectionHosts.server,
        roundTrip: Duration = .milliseconds(10)
    ) throws -> ConnectionPair {
        let start = ContinuousClock.now
        let (client, clientOutputs) = TCPConnection.connect(
            from: local, to: remote, initialSequenceNumber: SequenceNumber(clientISS), at: start)
        guard let syn = clientOutputs.segments.first else { throw HarnessError(description: "No SYN") }
        let arrival = start + roundTrip / 2
        let (server, serverOutputs) = try TCPConnection.accept(
            syn.roundTripped(), initialSequenceNumber: SequenceNumber(serverISS), at: arrival)
        var pair = ConnectionPair(now: start + roundTrip, client: client, server: server)
        pair.clientSent = [(start, syn)]
        pair.collect(serverOutputs, from: .server)
        return pair
    }

    mutating func collect(_ outputs: [TCPConnection.Output], from side: Side) {
        for output in outputs {
            switch output {
            case .segment(let segment):
                switch side {
                case .client:
                    clientSent.append((now, segment))
                    if !drop(.client, segment) { toServer.append(segment) }
                case .server:
                    serverSent.append((now, segment))
                    if !drop(.server, segment) { toClient.append(segment) }
                }
            case .event(let event):
                switch side {
                case .client: clientEvents.append(event)
                case .server: serverEvents.append(event)
                }
            }
        }
    }

    /// Delivers all accumulated segments. The receiver emits an ACK with `advance(to: now)` after receiving a batch.
    mutating func deliver() throws {
        var rounds = 0
        while !toServer.isEmpty || !toClient.isEmpty {
            rounds += 1
            guard rounds < 100_000 else { throw HarnessError(description: "The exchange did not finish") }
            let forServer = toServer
            toServer = []
            for segment in forServer {
                collect(server.receive(try segment.roundTripped(), at: now), from: .server)
                if !batched { collect(server.advance(to: now), from: .server) }
            }
            if !forServer.isEmpty { collect(server.advance(to: now), from: .server) }
            let forClient = toClient
            toClient = []
            for segment in forClient {
                collect(client.receive(try segment.roundTripped(), at: now), from: .client)
                if !batched { collect(client.advance(to: now), from: .client) }
            }
            if !forClient.isEmpty { collect(client.advance(to: now), from: .client) }
        }
    }

    /// Runs timers and exchanges segments up to `limit`. On return, `now` equals `limit`.
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

    mutating func write(_ bytes: [UInt8], from side: Side) -> Int {
        switch side {
        case .client:
            let (accepted, outputs) = client.write(bytes[...], at: now)
            collect(outputs, from: .client)
            return accepted
        case .server:
            let (accepted, outputs) = server.write(bytes[...], at: now)
            collect(outputs, from: .server)
            return accepted
        }
    }

    mutating func read(_ side: Side, upTo maximumLength: Int = .max) -> [UInt8] {
        switch side {
        case .client:
            let (bytes, outputs) = client.read(upTo: maximumLength, at: now)
            collect(outputs, from: .client)
            return bytes
        case .server:
            let (bytes, outputs) = server.read(upTo: maximumLength, at: now)
            collect(outputs, from: .server)
            return bytes
        }
    }

    mutating func finishWriting(_ side: Side) {
        switch side {
        case .client: collect(client.finishWriting(at: now), from: .client)
        case .server: collect(server.finishWriting(at: now), from: .server)
        }
    }

    mutating func close(_ side: Side) {
        switch side {
        case .client: collect(client.close(at: now), from: .client)
        case .server: collect(server.close(at: now), from: .server)
        }
    }

    /// Both sides send `data` simultaneously and read each other's bytes to completion. Returns the received bytes (`client`'s received bytes, then `server`'s).
    /// When a timer must run (delayed ACK or retransmission), advances time by `step`.
    mutating func exchange(
        clientSends: [UInt8], serverSends: [UInt8], step: Duration = .milliseconds(5),
        timeLimit: Duration = .seconds(600)
    ) throws -> (clientReceived: [UInt8], serverReceived: [UInt8]) {
        var clientOffset = 0
        var serverOffset = 0
        var clientReceived: [UInt8] = []
        var serverReceived: [UInt8] = []
        let deadline = now + timeLimit
        while clientReceived.count < serverSends.count || serverReceived.count < clientSends.count {
            guard now < deadline else {
                throw HarnessError(
                    description: "Transfer did not finish: \(serverReceived.count)/\(clientSends.count), "
                        + "\(clientReceived.count)/\(serverSends.count)")
            }
            if clientOffset < clientSends.count {
                clientOffset += write(Array(clientSends[clientOffset...]), from: .client)
            }
            if serverOffset < serverSends.count {
                serverOffset += write(Array(serverSends[serverOffset...]), from: .server)
            }
            try deliver()
            clientReceived += read(.client)
            serverReceived += read(.server)
            try deliver()
            try run(for: step)
        }
        return (clientReceived, serverReceived)
    }
}

/// A test peer that feeds handcrafted segments to one connection. The connection is on the `server` side (passive open), and this value holds the peer's (client's) sequence number.
struct ManualPeer {
    var connection: TCPConnection
    var now: ContinuousClock.Instant
    /// The next sequence number the peer will use (the peer's SND.NXT).
    var peerNext: SequenceNumber
    /// The peer's window field.
    var peerWindow: UInt16 = 65_535

    /// A connection established by passive open. The peer SYN's MSS and Window Scale are configurable.
    static func established(
        peerISS: UInt32 = 5_000, iss: UInt32 = 70_000, maximumSegmentSize: UInt16? = 1_240,
        windowScale: UInt8? = nil, synWindow: UInt16 = 65_535, ackWindow: UInt16 = 65_535
    ) throws -> ManualPeer {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server,
            sequenceNumber: SequenceNumber(peerISS), flags: [.syn], window: synWindow,
            maximumSegmentSize: maximumSegmentSize, windowScale: windowScale)
        let (connection, _) = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(iss), at: start)
        var peer = ManualPeer(connection: connection, now: start, peerNext: SequenceNumber(peerISS).advanced(by: 1))
        peer.peerWindow = ackWindow
        let outputs = peer.send(flags: [.ack])
        guard outputs.events == [.established] else {
            throw HarnessError(description: "Connection was not established: \(outputs)")
        }
        return peer
    }

    /// A segment sent by the peer. Uses `sequence` (default `peerNext`) and `acknowledgment` (default the connection's SND.NXT).
    func segment(
        sequence: SequenceNumber? = nil, acknowledgment: SequenceNumber? = nil, flags: TCPSegment.Flags,
        payload: [UInt8] = [], window: UInt16? = nil
    ) -> TCPSegment {
        TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server,
            sequenceNumber: sequence ?? peerNext,
            acknowledgmentNumber: acknowledgment ?? connection.sendNext, flags: flags,
            window: window ?? peerWindow, payload: payload)
    }

    /// Feeds a segment and calls `advance` at the same time (to get the delayed ACK).
    mutating func receive(_ segment: TCPSegment) -> [TCPConnection.Output] {
        connection.receive(segment, at: now) + connection.advance(to: now)
    }

    /// Sends a segment starting at `peerNext` and advances `peerNext` by that amount.
    @discardableResult
    mutating func send(
        flags: TCPSegment.Flags, payload: [UInt8] = [], acknowledgment: SequenceNumber? = nil, window: UInt16? = nil
    ) -> [TCPConnection.Output] {
        let segment = segment(acknowledgment: acknowledgment, flags: flags, payload: payload, window: window)
        peerNext = peerNext.advanced(by: segment.sequenceLength)
        return receive(segment)
    }

    mutating func advance(by duration: Duration) -> [TCPConnection.Output] {
        now = now + duration
        return connection.advance(to: now)
    }
}
