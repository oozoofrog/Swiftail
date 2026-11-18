import SwiftailBase

/// Manages the connection table by converting connection output to stack output and updating the table after the connection takes a step.
///
/// Every path that drives a connection (receive, time, application call) ends by calling `process(_:of:at:into:)`. That
/// centralizes transitions from establishment to queue, TIME-WAIT to record, and closed to removal, so counts for the
/// limits (establishing connections and queued connections) stay consistent with the table.
extension TCPStack {
    /// Updates one connection in place. Returns `nil` for an unknown ID.
    ///
    /// Removing and reinserting an entry would temporarily give the buffer storage two owners and copy the entire
    /// buffer on mutation. Update it in place in the table.
    mutating func modifyConnection<Result>(
        _ id: ConnectionID, _ body: (inout TCPConnection) -> Result
    ) -> Result? {
        guard let index = connections.index(forKey: id) else { return nil }
        return body(&connections.values[index].connection)
    }

    /// Converts output from connection `id` to stack output and updates the table.
    ///
    /// Converts segments to IP packets and forwards only events for application-held connections, tagging them with IDs
    /// (see the type documentation). Preserves the connection's output order.
    mutating func process(
        _ connectionOutputs: [TCPConnection.Output], of id: ConnectionID, at now: ContinuousClock.Instant,
        into outputs: inout [Output]
    ) {
        for output in connectionOutputs {
            switch output {
            case .segment(let segment):
                append(segment, to: &outputs)
            case .event(let event):
                report(event, of: id, into: &outputs)
            }
        }
        settle(id, at: now, into: &outputs)
    }

    /// Serializes and emits a segment as an IP packet. Both connection addresses are always in the same family and the
    /// segment fits within the MTU, so serialization succeeds.
    func append(_ segment: TCPSegment, to outputs: inout [Output]) {
        if let packet = segment.ipPacket() {
            outputs.append(.ipPacket(packet))
        }
    }

    /// Emits the event with the ID if the application holds the connection. `reportClose(_:of:into:)` reports closure only once.
    private mutating func report(_ event: TCPConnection.Event, of id: ConnectionID, into outputs: inout [Output]) {
        if case .closed(let reason) = event {
            reportClose(CloseReason(reason), of: id, into: &outputs)
            return
        }
        guard let index = connections.index(forKey: id),
            connections.values[index].role == .application, !connections.values[index].hasReportedClose
        else { return }
        switch event {
        case .established: outputs.append(.event(.established(id)))
        case .readable: outputs.append(.event(.readable(id)))
        case .writable: outputs.append(.event(.writable(id)))
        case .endOfStream: outputs.append(.event(.endOfStream(id)))
        case .closed: break
        }
    }

    /// Reports once per connection when TCP processing ends (it reaches CLOSED or enters TIME-WAIT). Emits `.closed`
    /// for an application-held connection and `.releasedConnectionClosed` for a released connection, for logging only
    /// (contract “Connection close statistics log”). Does not report establishing or queued connections.
    private mutating func reportClose(_ reason: CloseReason, of id: ConnectionID, into outputs: inout [Output]) {
        guard let index = connections.index(forKey: id), !connections.values[index].hasReportedClose else { return }
        let statistics = connections.values[index].connection.statistics
        switch connections.values[index].role {
        case .application: outputs.append(.event(.closed(id, reason, statistics)))
        case .released: outputs.append(.releasedConnectionClosed(reason, statistics))
        case .halfOpen, .queued: return
        }
        connections.values[index].hasReportedClose = true
    }

    /// Updates the table to reflect the connection's new state after it takes a step.
    ///
    /// - When a passive open establishes, moves it to the queue and emits `.acceptable` (contract behavior S5).
    /// - Removes a closed connection. Also silently removes an establishing connection closed with `.reset` (the second
    ///   step in RFC 9293 §3.10.7.4, “return to LISTEN”). If an application-held connection has unread data, retains
    ///   only that until the application releases it.
    /// - On entering TIME-WAIT, reports `.closed(.finished)` (or `.releasedConnectionClosed(.finished)` for a released
    ///   connection) and moves it to a record after the ACK of the peer's FIN goes out (contract behavior S6). At 1,024
    ///   records, keeps the connection itself until TIME-WAIT ends, so neither records nor connections exceed their
    ///   limits. A record lives for up to 240 seconds after the connection entered TIME-WAIT
    ///   (`TimeWaitRecord.lifetimeEnd`).
    /// - Otherwise, records the connection's deadline again.
    private mutating func settle(_ id: ConnectionID, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard let index = connections.index(forKey: id), !connections.values[index].isDetached else { return }
        let state = connections.values[index].connection.state
        let role = connections.values[index].role

        if case .halfOpen(let listenerID) = role, state != .synReceived, state != .closed {
            leaveHalfOpen(connections.values[index].connection.remoteEndpoint.address, listener: listenerID)
            connections.values[index].role = .queued(listenerID)
            listeners[listenerID]?.queue.append(id)
            outputs.append(.event(.acceptable(listenerID)))
        }

        switch state {
        case .closed:
            finish(id)
        case .timeWait:
            reportClose(.finished, of: id, into: &outputs)
            let connection = connections.values[index].connection
            if connection.timers[.acknowledgment] == nil, timeWaitRecords.count < Self.maximumTimeWaitRecords {
                addTimeWaitRecord(
                    TimeWaitRecord(
                        sendNext: connection.sendNext, receiveNext: connection.receiveNext,
                        deadline: connection.timers[.timeWait] ?? now + TCPConnection.timeWaitDuration,
                        lifetimeEnd: (connection.timeWaitEnteredAt ?? now) + TCPConnection.maximumTimeWaitLifetime),
                    for: connections.values[index].tuple)
                finish(id)
            } else {
                connectionDeadlines[id] = connection.nextDeadline
            }
        default:
            connectionDeadlines[id] = connections.values[index].connection.nextDeadline
        }
    }

    /// Removes a connection whose TCP processing has ended. If an application-held connection has unread data, retains only that.
    private mutating func finish(_ id: ConnectionID) {
        guard let index = connections.index(forKey: id) else { return }
        if connections.values[index].role == .application, connections.values[index].connection.readableByteCount > 0 {
            connections.values[index].isDetached = true
            connectionsByTuple[connections.values[index].tuple] = nil
            connectionDeadlines[id] = nil
        } else {
            removeConnection(id)
        }
    }

    /// Ends a connection without sending anything. Reports `.closed(reason)` for an application-held connection or
    /// `.releasedConnectionClosed(reason)` for a released one (contract behaviors S9 and X10).
    mutating func discard(_ id: ConnectionID, reason: CloseReason, into outputs: inout [Output]) {
        reportClose(reason, of: id, into: &outputs)
        removeConnection(id)
    }

    /// Removes one connection from the establishing count because it established or was removed.
    mutating func leaveHalfOpen(_ remoteAddress: IPAddress, listener listenerID: ListenerID) {
        halfOpenCount -= 1
        let remaining = halfOpenCountByAddress[remoteAddress, default: 1] - 1
        halfOpenCountByAddress[remoteAddress] = remaining > 0 ? remaining : nil
        listeners[listenerID]?.halfOpenCount -= 1
    }

    /// A new connection ID. Never reused within the stack (it will not exhaust 2⁶⁴ IDs). `insertConnection(_:)` inserts it in the table.
    mutating func makeConnectionID() -> ConnectionID {
        defer { nextIdentifier &+= 1 }
        return ConnectionID(rawValue: nextIdentifier)
    }

    /// A new listener ID. Uses the same number sequence as connection IDs.
    mutating func makeListenerID() -> ListenerID {
        defer { nextIdentifier &+= 1 }
        return ListenerID(rawValue: nextIdentifier)
    }
}
