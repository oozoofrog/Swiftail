import SwiftailBase

/// A stack that groups multiple TCP connections and listeners (contract behaviors S, X7, X8, and X10).
///
/// A value type without sockets, clocks, or random numbers. Inputs are IP packet bytes (`receive(_:at:)`), time
/// (`advance(to:)`), application calls (opening and closing listeners, taking from the accept queue, `connect`, and
/// calling `write`, `read`, `finishWriting`, `close`, or `abort` by connection ID), and updates to the local address
/// list. Outputs are outgoing IP packets, events, and drops (`Output`), which must be processed in emission order
/// (contract behavior S10).
///
/// The node calls the stack in the following order.
/// 1. After creation, pass the local tailnet addresses with `setLocalAddresses(_:)` and the per-peer groups of remote
///    addresses with `setRemoteAddressGroups(_:)`. Repeat each time a netmap is applied.
/// 2. Pass each packet in a received group to `receive(_:at:)`, then **call `advance(to:)` with the same time** at the
///    end of the group. Immediate ACKs (for example, out-of-order data) come from the packet's `receive` output. Only
///    ACKs for in-order data are coalesced, one per 2×MSS (contract behavior F5).
/// 3. Set a timer for `nextDeadline` and call `advance(to:)` when it fires.
///
/// A `ConnectionID` identifies a connection and a `ListenerID` identifies a listener. Neither number is reused within a
/// stack, so calls with a stale ID for an ended connection have no effect and cannot reach a new connection. Events are
/// emitted only for application-held connections, opened with `connect` or taken with `accept`. Events during
/// establishment, while queued, or after the application calls `close` or `abort` are unreported. The end of a released
/// connection produces one `.releasedConnectionClosed` for logging.
///
/// This file contains the type declaration, state, and time handling. Receiving, application calls, connection cleanup,
/// ISNs, and TIME-WAIT records are in files in the same directory. Contract `docs/contracts/SwiftailNetstack.md`
/// behaviors S, X, and M. Notes `docs/protocol-notes/tcp-netstack.md` §§4.2 and 4.3.
package struct TCPStack: Sendable {
    /// Identifies one connection. Never reused within the stack.
    package struct ConnectionID: Hashable, Sendable {
        /// A number the stack assigns in sequence, shared with listener IDs. Determines order for deterministic output.
        package let rawValue: UInt64
    }

    /// Identifies one listener. Never reused within the stack, even when reopening the same port.
    package struct ListenerID: Hashable, Sendable {
        /// A number the stack assigns in sequence, shared with connection IDs.
        package let rawValue: UInt64
    }

    /// An output of the stack. Process in emission order (contract behavior S10).
    ///
    /// Within a send pass, packets for one connection follow sequence order. Retransmission can revisit earlier
    /// sequence numbers on a later pass.
    package enum Output: Sendable, Equatable {
        /// An outgoing IP packet. The node passes it to the engine.
        case ipPacket([UInt8])
        /// An event to report to the application.
        case event(Event)
        /// A received packet was dropped. The node counts drops for logging (contract behavior K2).
        case dropped(Drop)
        /// TCP processing has ended for a connection the application released with `close` or `abort` (it reached
        /// CLOSED or entered TIME-WAIT). Carries the reason and statistics to that point, including retransmissions
        /// after release. The node uses it solely for the `Connection ended` log and does not wake application calls
        /// (contract “Connection close statistics log,” “Connections released by the application”). Emitted once per
        /// connection, except for connections that already emitted `.closed` while held and those discarded by
        /// `abortAll()`.
        case releasedConnectionClosed(CloseReason, TCPConnection.Statistics)
    }

    /// An event to report to the application. Events are emitted only for connections held by the application and for listeners.
    package enum Event: Sendable, Equatable {
        /// A connection opened with `connect` was established.
        case established(ConnectionID)
        /// A connection entered the listener's accept queue. Take it with `accept(from:)`.
        case acceptable(ListenerID)
        /// Bytes became readable after there were none.
        case readable(ConnectionID)
        /// Space became available in a previously full send buffer.
        case writable(ConnectionID)
        /// The peer closed its write side (FIN). All data received before it can be read.
        case endOfStream(ConnectionID)
        /// The connection ended. No further events follow for this connection. If `.finished`, unread data remains
        /// readable. Carries transmission statistics through the end, or through entry into TIME-WAIT for a connection
        /// reported at that point.
        case closed(ConnectionID, CloseReason, TCPConnection.Statistics)
    }

    /// The reason the connection ended. Extends `TCPConnection.CloseReason` with `peerRemoved` from the stack.
    package enum CloseReason: Sendable, Equatable {
        /// Both FINs were exchanged. Reported on entering TIME-WAIT. The stack keeps a record for the remaining 60 seconds.
        case finished
        /// The peer aborted with RST.
        case reset
        /// The peer refused the outgoing connection (RST in response to SYN, or a peer MSS below 64).
        case refused
        /// The peer did not respond (retransmission limit, zero-window probes, keep-alive, or FIN-WAIT-2 deadline).
        case timedOut
        /// This side aborted (`abort`, `close` with unread data, or data arriving after `close`).
        case aborted
        /// The local address changed (contract behavior S9) or the remote address's owner changed (contract behavior X10). Nothing was sent.
        case peerRemoved

        init(_ reason: TCPConnection.CloseReason) {
            switch reason {
            case .finished: self = .finished
            case .reset: self = .reset
            case .refused: self = .refused
            case .timedOut: self = .timedOut
            case .aborted: self = .aborted
            }
        }
    }

    /// The reason a received packet was dropped. Excludes segments the protocol drops silently, such as an RST for an absent connection.
    package enum Drop: Sendable, Equatable {
        /// The packet is not TCP (contract behavior N2). ICMP and UDP are not handled.
        case notTCP
        /// An invalid length, header, or option, or a fragment.
        case malformed
        /// An incorrect checksum.
        case badChecksum
        /// The destination is not a local tailnet address (contract behavior S1).
        case notForUs
        /// A limit was reached, so the SYN went unanswered (contract behaviors S4~S6).
        case limitReached(Limit)
    }

    /// The limit that caused a SYN to be dropped (the table in contract behavior M).
    package enum Limit: Sendable, Equatable {
        /// 64 establishing connections across the stack.
        case halfOpenConnections
        /// 16 establishing connections for one remote peer. Counts its addresses together (`setRemoteAddressGroups(_:)`).
        case halfOpenConnectionsPerAddress
        /// 32 entries in a listener's accept queue, including establishing connections.
        case acceptQueue
        /// 16 entries that one remote peer can hold in a single listener's accept queue, including establishing
        /// connections. Prevents one peer from filling the queue and blocking SYNs from others.
        case acceptQueueShare
        /// 256 connections across the stack.
        case connections
        /// 64 connections for one remote peer. Prevents one peer from filling all 256 slots and blocking others (M6 review A).
        case connectionsPerAddress
        /// 1,024 TIME-WAIT records across the stack.
        case timeWaitRecords
    }

    /// A failure of `listen(on:)`.
    package enum ListenError: Error, Sendable, Equatable {
        /// The port already has a listener.
        case addressInUse
        /// There are 16 listeners.
        case limitReached
    }

    /// A failure of `connect(to:at:)`.
    package enum ConnectError: Error, Sendable, Equatable {
        /// No local address shares the destination's address family (contract behavior S8). The node reports `unknownHost`.
        case noLocalAddress
        /// There are 256 connections, 64 connections to that remote peer, 1,024 TIME-WAIT records, or no outgoing port
        /// for the destination.
        case limitReached
    }

    // MARK: Limits (Contract Behavior M)
    //
    // Limits with `PerAddress` in the name apply to each remote peer. A peer's IPv4 and IPv6 addresses count together.
    // An address that the node did not identify as belonging to a peer gets its own share
    // (`setRemoteAddressGroups(_:)`).

    static let maximumListeners = 16
    static let maximumHalfOpenConnections = 64
    static let maximumHalfOpenConnectionsPerAddress = 16
    static let maximumAcceptQueueLength = 32
    /// The number of entries one remote peer can hold in a listener's accept queue, including establishing connections.
    /// Half the queue and equal to the per-peer limit for establishing connections.
    static let maximumAcceptQueueShare = maximumAcceptQueueLength / 2
    static let maximumConnections = 256
    static let maximumConnectionsPerAddress = 64
    static let maximumTimeWaitRecords = 1_024
    static let maximumTimeWaitRecordsPerAddress = 64
    /// Ports for outgoing connections (contract behavior S8).
    static let ephemeralPorts: ClosedRange<UInt16> = 49_152...65_535

    // MARK: State

    /// Local tailnet addresses. Accepts packets only for these addresses and chooses source addresses for outgoing connections from them.
    package internal(set) var localAddresses: [IPAddress] = []
    /// All connections, including establishing, queued, application-held, released but still closing, and those with
    /// only remaining data. At most 256. Insert and remove only with `insertConnection(_:)` and `removeConnection(_:)`
    /// to keep per-address counts consistent. Mutate entry values in place.
    var connections: [ConnectionID: ConnectionEntry] = [:]
    /// The number of connections (`connections` entries) per remote address. The limit (64) counts the peer's addresses together.
    private(set) var connectionCountByAddress: [IPAddress: Int] = [:]
    /// Maps a remote address to the addresses in its group (one peer) that share limits. The node supplies it for each
    /// netmap (`setRemoteAddressGroups(_:)`). An address absent here forms a group of one.
    private(set) var remoteAddressGroups: [IPAddress: [IPAddress]] = [:]
    /// Maps a 4-tuple to a connection. Connections whose TCP processing has ended are removed here, either because they
    /// moved to a TIME-WAIT record or because they closed.
    var connectionsByTuple: [FourTuple: ConnectionID] = [:]
    /// The `nextDeadline` for each connection. Updated whenever a connection takes a step, so finding a deadline does not rescan its timers.
    var connectionDeadlines: [ConnectionID: ContinuousClock.Instant] = [:]
    /// TIME-WAIT records. Holds up to 1,024 and does not drop them before their deadline (contract behavior S6). If a
    /// remote peer exceeds 64 records, removes its oldest record (M6 review A). Only functions in “TIME-WAIT Records”
    /// below modify these records.
    private(set) var timeWaitRecords: [FourTuple: TimeWaitRecord] = [:]
    /// The 4-tuples of TIME-WAIT records per remote address. In creation order and referring to the same records as `timeWaitRecords`.
    private(set) var timeWaitTuplesByAddress: [IPAddress: [FourTuple]] = [:]
    /// The earliest TIME-WAIT record deadline. Lets `advance` skip scanning records when none is due.
    private(set) var earliestTimeWaitDeadline: ContinuousClock.Instant?
    var listeners: [ListenerID: Listener] = [:]
    var listenersByPort: [UInt16: ListenerID] = [:]
    /// The number of SYN-RECEIVED connections, both stack-wide and per remote address. The limit for one peer (16)
    /// counts its addresses together.
    var halfOpenCount = 0
    var halfOpenCountByAddress: [IPAddress: Int] = [:]
    /// The next ID to assign, shared by connections and listeners.
    var nextIdentifier: UInt64 = 1
    /// The next outgoing port to try.
    var nextEphemeralPort = TCPStack.ephemeralPorts.lowerBound
    let initialSequenceNumbers: InitialSequenceNumberGenerator

    /// Creates a stack.
    ///
    /// - Parameters:
    ///   - isnSecret: The ISN secret (RFC 6528 §3). On each `run()`, the node supplies 32 bytes drawn from system
    ///     randomness. Omitted from events, errors, `description`, and `dump` (contract behavior K1).
    ///   - now: The time at which the ISN clock component is 0.
    package init(isnSecret: [UInt8], now: ContinuousClock.Instant) {
        initialSequenceNumbers = InitialSequenceNumberGenerator(secret: isnSecret, origin: now)
    }

    // MARK: Readable Values

    /// The connection's current value (state, addresses, number of readable bytes, space to write, and whether FIN
    /// arrived). Returns `nil` for an unknown ID.
    ///
    /// This is a copy of the value. Read it and immediately discard it. Retaining it makes the stack copy the entire
    /// buffer when mutating the buffer.
    package func connection(_ id: ConnectionID) -> TCPConnection? {
        connections[id]?.connection
    }

    /// The earliest deadline across all connections and TIME-WAIT records. Returns `nil` when none exists.
    ///
    /// Scans the stored connection deadlines (up to 256) and compares with the earliest TIME-WAIT record deadline.
    // shortcut: Scans connection deadlines without a heap (see “finding stack timeout: scans all connections” in the contract's exclusions table). Change
    // this if the connection limit increases substantially.
    package var nextDeadline: ContinuousClock.Instant? {
        var earliest = earliestTimeWaitDeadline
        for deadline in connectionDeadlines.values where earliest.map({ deadline < $0 }) ?? true {
            earliest = deadline
        }
        return earliest
    }

    // MARK: Time

    /// Processes all deadlines up to `now`. Removes due TIME-WAIT records and calls `advance(to:)` on due connections.
    /// Delayed ACKs also go out here. Processes connections in deadline order, breaking ties by ID to make output
    /// deterministic.
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        expireTimeWaitRecords(at: now)

        var due: [(deadline: ContinuousClock.Instant, id: ConnectionID)] = []
        for (id, deadline) in connectionDeadlines where deadline <= now {
            due.append((deadline, id))
        }
        due.sort { ($0.deadline, $0.id.rawValue) < ($1.deadline, $1.id.rawValue) }

        var outputs: [Output] = []
        for (_, id) in due {
            let connectionOutputs = modifyConnection(id) { $0.advance(to: now) } ?? []
            process(connectionOutputs, of: id, at: now, into: &outputs)
        }
        return outputs
    }
}

// MARK: - Connection Table

extension TCPStack {
    /// Inserts a new connection in the table and assigns an ID. Only this method increments the count per remote
    /// address (`removeConnection(_:)` decrements it).
    mutating func insertConnection(_ entry: ConnectionEntry) -> ConnectionID {
        let id = makeConnectionID()
        connections[id] = entry
        connectionsByTuple[entry.tuple] = id
        connectionCountByAddress[entry.connection.remoteEndpoint.address, default: 0] += 1
        return id
    }

    /// Removes a connection from the table without sending anything. Updates the establishing count, queue, and count
    /// per remote address together.
    mutating func removeConnection(_ id: ConnectionID) {
        guard let entry = connections.removeValue(forKey: id) else { return }
        connectionDeadlines[id] = nil
        let tuple = entry.tuple
        if connectionsByTuple[tuple] == id {
            connectionsByTuple[tuple] = nil
        }
        let address = entry.connection.remoteEndpoint.address
        let remaining = connectionCountByAddress[address, default: 1] - 1
        connectionCountByAddress[address] = remaining > 0 ? remaining : nil
        switch entry.role {
        case .halfOpen(let listenerID):
            leaveHalfOpen(address, listener: listenerID)
        case .queued(let listenerID):
            listeners[listenerID]?.queue.removeAll { $0 == id }
        case .application, .released:
            break
        }
    }

    /// The peer with remote `address` has 64 connections. Rejects new SYNs and `connect` calls.
    func isConnectionLimitReached(for address: IPAddress) -> Bool {
        let count = addressesSharingLimits(with: address).reduce(0) { $0 + connectionCountByAddress[$1, default: 0] }
        return count >= Self.maximumConnectionsPerAddress
    }
}

// MARK: - Remote Address Groups

extension TCPStack {
    /// Groups remote addresses by peer. The node supplies them alongside local addresses whenever it applies a netmap
    /// (contract behavior S, “Per-peer share”).
    ///
    /// Limits for one remote peer (64 connections, 16 establishing connections, 16 entries in a listener queue, and 64
    /// TIME-WAIT records) count addresses in the same group together. Counting per address alone would give a peer with
    /// IPv4 and IPv6 addresses two shares. Counts are stored per address and added when checked, so a change to the
    /// grouping needs no count updates.
    ///
    /// - Parameter groups: Maps a remote address to a group name. Addresses with the same value share a group. The
    ///   stack does not interpret the value. The node supplies the node ID of the peer with that address. An absent
    ///   address forms its own group.
    package mutating func setRemoteAddressGroups(_ groups: [IPAddress: Int]) {
        var members: [Int: [IPAddress]] = [:]
        for (address, group) in groups {
            members[group, default: []].append(address)
        }
        remoteAddressGroups = [:]
        for addresses in members.values where addresses.count > 1 {
            // Establish an order so the same input removes the same records.
            let sorted = addresses.sorted { $0.bytes.lexicographicallyPrecedes($1.bytes) }
            for address in sorted {
                remoteAddressGroups[address] = sorted
            }
        }
    }

    /// The remote addresses that share a limit with `address`, including `address`.
    func addressesSharingLimits(with address: IPAddress) -> [IPAddress] {
        remoteAddressGroups[address] ?? [address]
    }
}

// MARK: - TIME-WAIT Records

extension TCPStack {
    /// Adds a record. Its 4-tuple's connection must already be out of the table, and no record may exist for that 4-tuple.
    ///
    /// If the remote peer already has 64 records, first removes its oldest. This is the exception to behavior S6's rule
    /// against early removal. It affects only that peer's old connections, since late segments for that 4-tuple receive
    /// RST. This prevents one peer from filling all 1,024 records and blocking SYNs and `connect` calls from others (M6
    /// review A). Counts the peer's addresses together. The oldest is whichever first record per address (in creation
    /// order) entered TIME-WAIT earliest (earliest `lifetimeEnd`).
    mutating func addTimeWaitRecord(_ record: TimeWaitRecord, for tuple: FourTuple) {
        let address = tuple.remote.address
        let tupleLists = addressesSharingLimits(with: address).compactMap { timeWaitTuplesByAddress[$0] }
        if tupleLists.reduce(0, { $0 + $1.count }) >= Self.maximumTimeWaitRecordsPerAddress {
            var oldest: (tuple: FourTuple, lifetimeEnd: ContinuousClock.Instant)?
            for tuples in tupleLists {
                guard let first = tuples.first, let lifetimeEnd = timeWaitRecords[first]?.lifetimeEnd else { continue }
                if oldest.map({ lifetimeEnd < $0.lifetimeEnd }) ?? true {
                    oldest = (first, lifetimeEnd)
                }
            }
            let evicted = oldest.flatMap { forgetTimeWaitRecord($0.tuple) }
            if evicted?.deadline == earliestTimeWaitDeadline {
                earliestTimeWaitDeadline = timeWaitRecords.values.lazy.map(\.deadline).min()
            }
        }
        timeWaitRecords[tuple] = record
        timeWaitTuplesByAddress[address, default: []].append(tuple)
        earliestTimeWaitDeadline = min(earliestTimeWaitDeadline ?? record.deadline, record.deadline)
    }

    /// Replies to a segment for `tuple`'s record (`TimeWaitRecord.reply`). Returns `nil` if the record is missing.
    mutating func replyInTimeWait(
        to segment: TCPSegment, for tuple: FourTuple, at now: ContinuousClock.Instant
    ) -> TCPSegment? {
        guard let index = timeWaitRecords.index(forKey: tuple) else { return nil }
        let previousDeadline = timeWaitRecords.values[index].deadline
        let reply = timeWaitRecords.values[index].reply(to: segment, at: now)
        // Deadlines only move later. Recompute the earliest deadline only when it moves later.
        if timeWaitRecords.values[index].deadline != previousDeadline, previousDeadline == earliestTimeWaitDeadline {
            earliestTimeWaitDeadline = timeWaitRecords.values.lazy.map(\.deadline).min()
        }
        return reply
    }

    /// Removes due records. Skips the scan if the earliest deadline has yet to arrive.
    mutating func expireTimeWaitRecords(at now: ContinuousClock.Instant) {
        guard let earliest = earliestTimeWaitDeadline, earliest <= now else { return }
        var expired: [FourTuple] = []
        for (tuple, record) in timeWaitRecords where record.deadline <= now {
            expired.append(tuple)
        }
        for tuple in expired {
            forgetTimeWaitRecord(tuple)
        }
        earliestTimeWaitDeadline = timeWaitRecords.values.lazy.map(\.deadline).min()
    }

    /// Removes one record from the table and the per-address list. The caller recomputes the earliest deadline.
    @discardableResult
    private mutating func forgetTimeWaitRecord(_ tuple: FourTuple) -> TimeWaitRecord? {
        guard let record = timeWaitRecords.removeValue(forKey: tuple) else { return nil }
        let address = tuple.remote.address
        timeWaitTuplesByAddress[address]?.removeAll { $0 == tuple }
        if timeWaitTuplesByAddress[address]?.isEmpty == true {
            timeWaitTuplesByAddress[address] = nil
        }
        return record
    }
}

// MARK: - Table Entries

/// The connection lookup key (local address, local port, remote address, remote port).
struct FourTuple: Hashable, Sendable {
    var local: IPEndpoint
    var remote: IPEndpoint
}

/// A single listening port.
struct Listener: Sendable {
    let port: UInt16
    /// Established connections the application has yet to take, in arrival order.
    var queue: [TCPStack.ConnectionID] = []
    /// The number of still-establishing connections created from SYNs to this listener. At most 32 when combined with the queue.
    var halfOpenCount = 0
}

/// A connection table entry.
struct ConnectionEntry: Sendable {
    /// Who holds the connection.
    enum Role: Sendable, Equatable {
        /// SYN-RECEIVED. Created from a SYN that arrived at the listener.
        case halfOpen(TCPStack.ListenerID)
        /// Established and in the listener's queue.
        case queued(TCPStack.ListenerID)
        /// Held by the application (`connect`, `accept`). Reports events.
        case application
        /// The application released it with `close`. Removed when TCP finishes closing.
        case released
    }

    var connection: TCPConnection
    var role: Role
    /// The application was notified with `.closed`. No events are emitted afterward.
    var hasReportedClose = false
    /// TCP processing ended (closed or moved to a TIME-WAIT record). Retains only the unread application data until the
    /// application calls `close` or `abort`.
    var isDetached = false

    var tuple: FourTuple {
        FourTuple(local: connection.localEndpoint, remote: connection.remoteEndpoint)
    }
}
