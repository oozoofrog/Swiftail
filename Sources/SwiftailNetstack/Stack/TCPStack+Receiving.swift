import SwiftailBase

/// Packet reception, including parsing, lookup, LISTEN, and RST for an absent connection (contract behaviors S1~S6, X7 and X8).
extension TCPStack {
    /// Receives one IP packet. Accepting arbitrary input bytes does not crash (contract behavior X1).
    ///
    /// Lookup order (contract behavior S1). Drop packets whose destination is not a local address, then look for a
    /// connection by 4-tuple, a TIME-WAIT record for the same 4-tuple, and a listener on the destination port, in that
    /// order. If none exists, reply with RST (S2). A TIME-WAIT record comes before a listener, so a SYN with the same
    /// 4-tuple does not create a new connection while the record exists.
    ///
    /// Immediate pure ACKs come out in this packet's output. `advance(to:)` emits ACKs delayed on a 40ms deadline. Call
    /// `advance(to:)` with the same time after passing the entire group.
    package mutating func receive(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output] {
        let segment: TCPSegment
        do {
            segment = try TCPSegment(parsingIPPacket: ipPacket)
        } catch {
            switch error {
            case .notTCP: return [.dropped(.notTCP)]
            case .malformed: return [.dropped(.malformed)]
            case .badChecksum: return [.dropped(.badChecksum)]
            }
        }
        // The filter has already checked this, but the stack checks it too (contract behavior S1).
        guard localAddresses.contains(segment.destination.address) else { return [.dropped(.notForUs)] }

        var outputs: [Output] = []
        let tuple = FourTuple(local: segment.destination, remote: segment.source)
        if let id = connectionsByTuple[tuple] {
            let connectionOutputs = modifyConnection(id) { $0.receive(segment, at: now) } ?? []
            process(connectionOutputs, of: id, at: now, into: &outputs)
        } else if timeWaitRecords[tuple] != nil {
            if let reply = replyInTimeWait(to: segment, for: tuple, at: now) {
                append(reply, to: &outputs)
            }
        } else if let listenerID = listenersByPort[segment.destination.port] {
            receiveInListen(segment, listener: listenerID, at: now, into: &outputs)
        } else if let reset = Self.reset(answering: segment) {
            append(reset, to: &outputs)
        }
        return outputs
    }

    // MARK: LISTEN (RFC 9293 3.10.7.2)

    /// A segment arrived at a listener. For a segment with SYN set and ACK and RST clear, checks the limits and
    /// creates a connection. Skips SYN security and compartment checks (RFC 9293 §3.10.7.2, step three).
    ///
    /// Responds to other segments as on an unlistened port (`reset(answering:)`). Ignores RST, sends
    /// `<SEQ=SEG.ACK><CTL=RST>` if ACK is set, and sends `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>` if neither is set.
    /// The last differs from step four of RFC 9293 §3.10.7.2 (“drop”). Because the receive filter checks only SYN
    /// against the rules (contract behavior X), a silent drop would let an ACL-blocked peer distinguish listening ports
    /// by whether a FIN-only segment gets a reply.
    ///
    /// Drops a SYN without a reply when a limit is reached (contract behaviors S4~S6, X7, 64 connections for one remote
    /// peer and its 16-entry share of the queue). The peer retransmits the SYN.
    private mutating func receiveInListen(
        _ segment: TCPSegment, listener listenerID: ListenerID, at now: ContinuousClock.Instant,
        into outputs: inout [Output]
    ) {
        let flags = segment.flags
        guard flags.contains(.syn), !flags.contains(.ack), !flags.contains(.rst), let listener = listeners[listenerID]
        else {
            if let reset = Self.reset(answering: segment) {
                append(reset, to: &outputs)
            }
            return
        }

        let remoteAddress = segment.source.address
        let peerAddresses = addressesSharingLimits(with: remoteAddress)
        let exceeded: Limit? =
            if connections.count >= Self.maximumConnections {
                .connections
            } else if isConnectionLimitReached(for: remoteAddress) {
                .connectionsPerAddress
            } else if timeWaitRecords.count >= Self.maximumTimeWaitRecords {
                .timeWaitRecords
            } else if halfOpenCount >= Self.maximumHalfOpenConnections {
                .halfOpenConnections
            } else if peerAddresses.reduce(0, { $0 + halfOpenCountByAddress[$1, default: 0] })
                >= Self.maximumHalfOpenConnectionsPerAddress
            {
                .halfOpenConnectionsPerAddress
            } else if listener.queue.count + listener.halfOpenCount >= Self.maximumAcceptQueueLength {
                .acceptQueue
            } else if pendingConnectionCount(of: listenerID, from: peerAddresses) >= Self.maximumAcceptQueueShare {
                .acceptQueueShare
            } else {
                nil
            }
        if let exceeded {
            outputs.append(.dropped(.limitReached(exceeded)))
            return
        }

        let initialSequenceNumber = initialSequenceNumbers.initialSequenceNumber(
            local: segment.destination, remote: segment.source, at: now)
        let opened: (connection: TCPConnection, outputs: [TCPConnection.Output])
        do {
            opened = try TCPConnection.accept(
                segment, initialSequenceNumber: initialSequenceNumber,
                receiveWindowLimit: TCPConnection.unacceptedReceiveWindow, at: now)
        } catch {
            // Responds to the SYN with RST when the peer's MSS is less than 64 (contract behavior X9). The check above
            // already ruled out `notInitialSYN`.
            if case .unacceptableMaximumSegmentSize(let reset) = error {
                append(reset, to: &outputs)
            }
            return
        }

        let id = insertConnection(ConnectionEntry(connection: opened.connection, role: .halfOpen(listenerID)))
        halfOpenCount += 1
        halfOpenCountByAddress[remoteAddress, default: 0] += 1
        listeners[listenerID]?.halfOpenCount += 1
        process(opened.outputs, of: id, at: now, into: &outputs)
    }

    /// Counts the entries in listener `listenerID`'s queue and its establishing connections with a remote address in `addresses`.
    // shortcut: Scan the connection table (up to 256 entries) per SYN. Separate per-peer counts on each listener would
    // need updates on every move and removal. Revisit this when the connection limit increases substantially.
    private func pendingConnectionCount(of listenerID: ListenerID, from addresses: [IPAddress]) -> Int {
        connections.values.lazy.filter { entry in
            (entry.role == .halfOpen(listenerID) || entry.role == .queued(listenerID))
                && addresses.contains(entry.connection.remoteEndpoint.address)
        }.count
    }

    // MARK: No Connection (RFC 9293 §3.10.7.1)

    /// The RST response to a segment for which no connection, record, or listener exists. Does not reply to RST (`nil`).
    ///
    /// If ACK is clear, returns `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`. If it is set, returns
    /// `<SEQ=SEG.ACK><CTL=RST>`. The reply carries no data and is no larger than the input, so there is no
    /// amplification. Applies no separate rate limit (contract behavior X8).
    static func reset(answering segment: TCPSegment) -> TCPSegment? {
        guard !segment.flags.contains(.rst) else { return nil }
        if segment.flags.contains(.ack) {
            return TCPSegment(
                source: segment.destination, destination: segment.source,
                sequenceNumber: segment.acknowledgmentNumber, flags: [.rst])
        }
        return TCPSegment(
            source: segment.destination, destination: segment.source, sequenceNumber: SequenceNumber(0),
            acknowledgmentNumber: segment.sequenceNumber.advanced(by: segment.sequenceLength), flags: [.rst, .ack])
    }
}
