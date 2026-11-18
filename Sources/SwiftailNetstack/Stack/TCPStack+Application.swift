import SwiftailBase

/// Application and node calls for listening, connecting, reading, writing and closing by connection ID, and changing
/// addresses (contract behaviors S3, S5, S8, S9, and X10).
///
/// Calls by connection ID affect only connections held by the application, either opened with `connect` or taken with
/// `accept`. An unknown ID, an ID released by the application with `close` or `abort`, or an ID in the queue has no
/// effect. Writes return 0 bytes and reads return an empty array.
extension TCPStack {
    // MARK: Listeners

    /// Listens on `port` at all the local node's tailnet addresses (IPv4 and IPv6) (contract behavior S3). Allows one
    /// listener per port and up to 16 total. The node filters out port 0.
    package mutating func listen(on port: UInt16) throws(ListenError) -> ListenerID {
        guard listenersByPort[port] == nil else { throw .addressInUse }
        guard listeners.count < Self.maximumListeners else { throw .limitReached }
        let id = makeListenerID()
        listeners[id] = Listener(port: port)
        listenersByPort[port] = id
        return id
    }

    /// Stops listening. Aborts queued connections with RST and discards connections still establishing without sending
    /// anything (contract behavior S5). Connections already taken by the application are unaffected. An unknown ID has
    /// no effect.
    package mutating func stopListening(_ id: ListenerID) -> [Output] {
        guard let listener = listeners.removeValue(forKey: id) else { return [] }
        listenersByPort[listener.port] = nil
        var outputs: [Output] = []
        for connectionID in listener.queue {
            let connectionOutputs = modifyConnection(connectionID) { $0.abort() } ?? []
            for case .segment(let segment) in connectionOutputs {
                append(segment, to: &outputs)
            }
            removeConnection(connectionID)
        }
        let halfOpen = connections.compactMap { connectionID, entry in
            entry.role == .halfOpen(id) ? connectionID : nil
        }
        for connectionID in halfOpen.sorted(by: { $0.rawValue < $1.rawValue }) {
            removeConnection(connectionID)
        }
        return outputs
    }

    /// Takes one established connection from the listener's accept queue. Returns `nil` for an empty queue or an unknown listener.
    ///
    /// The application now holds the connection and receives subsequent events. Because data and FIN received while
    /// queued did not produce events, the node checks for readable bytes and FIN with `connection(_:)` after taking it.
    /// This opens the receive window that was capped while queued and includes a window update ACK in the output
    /// (`TCPConnection.openReceiveWindow(at:)`).
    package mutating func accept(
        from listenerID: ListenerID, at now: ContinuousClock.Instant
    ) -> (connection: ConnectionID, outputs: [Output])? {
        guard let index = listeners.index(forKey: listenerID), !listeners.values[index].queue.isEmpty else { return nil }
        let id = listeners.values[index].queue.removeFirst()
        connections[id]?.role = .application
        let connectionOutputs = modifyConnection(id) { $0.openReceiveWindow(at: now) } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        return (id, outputs)
    }

    // MARK: Connecting

    /// Connects to `remote` (active open). The output contains a SYN, followed by `.established(id)` on establishment
    /// or `.closed(id, .refused)` on refusal.
    ///
    /// Uses the first local address in the destination's family as the source. Selects ports in order from 49152…65535,
    /// skipping 4-tuples used by connections or TIME-WAIT records (contract behavior S8).
    ///
    /// Returns `limitReached` at 256 connections, 64 connections to that remote peer, or 1,024 TIME-WAIT records
    /// (contract behavior S6 and the text below it).
    package mutating func connect(
        to remote: IPEndpoint, at now: ContinuousClock.Instant
    ) throws(ConnectError) -> (connection: ConnectionID, outputs: [Output]) {
        guard let localAddress = localAddresses.first(where: { $0.isIPv4 == remote.address.isIPv4 }) else {
            throw .noLocalAddress
        }
        guard connections.count < Self.maximumConnections, !isConnectionLimitReached(for: remote.address),
            timeWaitRecords.count < Self.maximumTimeWaitRecords,
            let local = freeLocalEndpoint(address: localAddress, remote: remote)
        else { throw .limitReached }

        let initialSequenceNumber = initialSequenceNumbers.initialSequenceNumber(local: local, remote: remote, at: now)
        let opened = TCPConnection.connect(
            from: local, to: remote, initialSequenceNumber: initialSequenceNumber, at: now)
        let id = insertConnection(ConnectionEntry(connection: opened.connection, role: .application))
        var outputs: [Output] = []
        process(opened.outputs, of: id, at: now, into: &outputs)
        return (id, outputs)
    }

    /// The local address and port for an outgoing connection. Makes one pass starting at `nextEphemeralPort` to find an unused 4-tuple.
    private mutating func freeLocalEndpoint(address: IPAddress, remote: IPEndpoint) -> IPEndpoint? {
        let range = Self.ephemeralPorts
        for _ in range {
            let port = nextEphemeralPort
            nextEphemeralPort = port == range.upperBound ? range.lowerBound : port + 1
            let tuple = FourTuple(local: IPEndpoint(address: address, port: port), remote: remote)
            if connectionsByTuple[tuple] == nil, timeWaitRecords[tuple] == nil {
                return tuple.local
            }
        }
        return nil
    }

    // MARK: Calls by Connection ID

    /// Writes as much as fits in the send buffer (`TCPConnection.write`). If it cannot accept all bytes, emits
    /// `.writable(id)` when space becomes available.
    package mutating func write(
        _ bytes: ArraySlice<UInt8>, to id: ConnectionID, at now: ContinuousClock.Instant
    ) -> (accepted: Int, outputs: [Output]) {
        guard isLive(id) else { return (0, []) }
        let result = modifyConnection(id) { $0.write(bytes, at: now) } ?? (accepted: 0, outputs: [])
        var outputs: [Output] = []
        process(result.outputs, of: id, at: now, into: &outputs)
        return (result.accepted, outputs)
    }

    /// Takes up to `maximumLength` readable bytes (`TCPConnection.read`). Also reads data left on ended connections.
    package mutating func read(
        upTo maximumLength: Int, from id: ConnectionID, at now: ContinuousClock.Instant
    ) -> (bytes: [UInt8], outputs: [Output]) {
        guard let index = connections.index(forKey: id), connections.values[index].role == .application else {
            return ([], [])
        }
        if connections.values[index].isDetached {
            return (connections.values[index].connection.receiveBuffer.read(upTo: maximumLength), [])
        }
        let result = modifyConnection(id) { $0.read(upTo: maximumLength, at: now) } ?? (bytes: [], outputs: [])
        var outputs: [Output] = []
        process(result.outputs, of: id, at: now, into: &outputs)
        return (result.bytes, outputs)
    }

    /// Finishes sending (`TCPConnection.finishWriting`). Reads can continue.
    package mutating func finishWriting(_ id: ConnectionID, at now: ContinuousClock.Instant) -> [Output] {
        guard isLive(id) else { return [] }
        let connectionOutputs = modifyConnection(id) { $0.finishWriting(at: now) } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        return outputs
    }

    /// Closes and releases the connection (`TCPConnection.close`). The stack handles the finish (FIN exchange,
    /// TIME-WAIT) without reporting those events. When it finishes (CLOSED or TIME-WAIT), emits one
    /// `.releasedConnectionClosed` for logging. If this call ends it immediately with RST because of unread data, emits
    /// `.closed(id, .aborted)` instead.
    package mutating func close(_ id: ConnectionID, at now: ContinuousClock.Instant) -> [Output] {
        guard let index = connections.index(forKey: id), connections.values[index].role == .application else {
            return []
        }
        if connections.values[index].isDetached {
            removeConnection(id)
            return []
        }
        let connectionOutputs = modifyConnection(id) { $0.close(at: now) } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        connections[id]?.role = .released
        return outputs
    }

    /// Immediately aborts and releases the connection (`TCPConnection.abort`). Emits `.closed(id, .aborted)`.
    package mutating func abort(_ id: ConnectionID, at now: ContinuousClock.Instant) -> [Output] {
        guard let index = connections.index(forKey: id), connections.values[index].role == .application else {
            return []
        }
        if connections.values[index].isDetached {
            removeConnection(id)
            return []
        }
        let connectionOutputs = modifyConnection(id) { $0.abort() } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        return outputs
    }

    /// Aborts and discards all remaining connections. Called when the node stops (contract behavior N8).
    ///
    /// Sends one RST for application-held, establishing, and queued connections, and for connections the application
    /// released with `close` that are still exchanging FINs. Discards connections in states where `TCPConnection.abort`
    /// sends no RST. Emits no events. Leaves listeners and TIME-WAIT records alone.
    package mutating func abortAll() -> [Output] {
        var outputs: [Output] = []
        for id in connections.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            let connectionOutputs = modifyConnection(id) { $0.abort() } ?? []
            for case .segment(let segment) in connectionOutputs {
                append(segment, to: &outputs)
            }
            removeConnection(id)
        }
        return outputs
    }

    /// A connection held by the application whose TCP processing is still active.
    private func isLive(_ id: ConnectionID) -> Bool {
        guard let entry = connections[id] else { return false }
        return entry.role == .application && !entry.isDetached
    }

    // MARK: Address Changes

    /// Updates local tailnet addresses. The node calls this whenever it applies a netmap (contract behaviors S9 and N7).
    ///
    /// Connections using an address no longer local end without sending anything. Emits `.closed(id, .peerRemoved)` for
    /// application-held connections, and removes establishing and queued connections without reporting them. Keeps
    /// TIME-WAIT records until their deadlines.
    package mutating func setLocalAddresses(_ addresses: [IPAddress]) -> [Output] {
        localAddresses = addresses
        return discardConnections { !addresses.contains($0.local.address) }
    }

    /// Ends all connections whose remote address is `remoteAddress` without sending anything (the stack side of contract behavior X10).
    ///
    /// When applying a netmap, the node compares the current owner with the owner (node key) at establishment and calls
    /// this for each address whose owner disappeared or changed. Emits `.closed(id, .peerRemoved)` for application-held
    /// connections, and removes establishing and queued connections without reporting them. Keeps TIME-WAIT records
    /// until their deadlines. A record responds with a challenge ACK to a SYN using its 4-tuple from the new owner.
    package mutating func removeConnections(toRemoteAddress remoteAddress: IPAddress) -> [Output] {
        discardConnections { $0.remote.address == remoteAddress }
    }

    /// Ends active TCP connections whose 4-tuples match `matches`, in ID order.
    private mutating func discardConnections(where matches: (FourTuple) -> Bool) -> [Output] {
        let doomed = connections.compactMap { id, entry in
            !entry.isDetached && matches(entry.tuple) ? id : nil
        }
        var outputs: [Output] = []
        for id in doomed.sorted(by: { $0.rawValue < $1.rawValue }) {
            discard(id, reason: .peerRemoved, into: &outputs)
        }
        return outputs
    }
}
