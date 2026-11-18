/// Application calls for writing, reading, finishing writes, closing, and aborting (RFC 9293 §§3.10.2~3.10.5, contract behavior T6).
///
/// Each call ends by sending what it can and emitting due ACKs. An ended connection does nothing except return
/// remaining data on reads.
extension TCPConnection {
    /// Writes as many bytes as fit in the send buffer. Writes before establishment (SYN-SENT, SYN-RECEIVED) go out after establishment.
    ///
    /// - Returns: The number of accepted bytes and the output. If some bytes did not fit, emits `.writable` when space
    ///   becomes available. Returns 0 after finishing writes (`finishWriting` or `close`) or in a state that cannot
    ///   write.
    package mutating func write(
        _ bytes: ArraySlice<UInt8>, at now: ContinuousClock.Instant
    ) -> (accepted: Int, outputs: [Output]) {
        guard canWrite else { return (0, []) }
        let accepted = sendBuffer.append(bytes)
        if accepted < bytes.count { isWriteBlocked = true }
        var outputs: [Output] = []
        completeCall(at: now, into: &outputs)
        return (accepted, outputs)
    }

    /// Takes up to `maximumLength` readable bytes from the front. The receive window opens by the amount read. A window
    /// update ACK goes out if the remaining advertised window is at most half the buffer and the SWS avoidance
    /// threshold is met (contract behavior F3, `windowUpdateIsDue`).
    package mutating func read(
        upTo maximumLength: Int, at now: ContinuousClock.Instant
    ) -> (bytes: [UInt8], outputs: [Output]) {
        let bytes = receiveBuffer.read(upTo: maximumLength)
        var outputs: [Output] = []
        guard state != .closed else { return (bytes, []) }
        if !bytes.isEmpty, !finReceived, windowUpdateIsDue {
            switch state {
            case .established, .finWait1, .finWait2:
                scheduleAcknowledgment(immediately: true, at: now)
            default:
                break
            }
        }
        completeCall(at: now, into: &outputs)
        return (bytes, outputs)
    }

    /// Raises the receive window limit to buffer capacity. If established, immediately advertises the new window
    /// (window update ACK). The stack calls this when it takes the connection from the listener's queue and hands it to
    /// the application (`receiveWindowLimit`, contract behavior M).
    package mutating func openReceiveWindow(at now: ContinuousClock.Instant) -> [Output] {
        receiveWindowLimit = receiveBuffer.capacity
        var outputs: [Output] = []
        guard state != .closed else { return outputs }
        if state == .established, windowUpdateIsDue {
            scheduleAcknowledgment(immediately: true, at: now)
        }
        completeCall(at: now, into: &outputs)
        return outputs
    }

    /// Finishes sending (half-close). FIN goes out after the last buffered byte has been sent, moving ESTABLISHED → FIN-WAIT-1 or
    /// CLOSE-WAIT → LAST-ACK. Reads can continue. If called before establishment, sends FIN after establishment.
    package mutating func finishWriting(at now: ContinuousClock.Instant) -> [Output] {
        guard canWrite else { return [] }
        finRequested = true
        var outputs: [Output] = []
        completeCall(at: now, into: &outputs)
        return outputs
    }

    /// Closes the connection by ending reads in addition to `finishWriting` (RFC 9293 §3.10.4, contract behavior T6).
    ///
    /// - With unread data, immediately sends `<SEQ=SND.NXT><CTL=RST>` and ends (SHLD-3).
    /// - If new data arrives afterward, sends RST and ends.
    /// - In FIN-WAIT-2, ends if the peer's FIN does not arrive within 60 seconds.
    /// - In SYN-SENT, ends without sending anything (RFC 9293 §3.10.4 deletes the TCB).
    package mutating func close(at now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        switch state {
        case .closed:
            return []
        case .synSent:
            terminate(.aborted, into: &outputs)
            return outputs
        case .timeWait:
            readClosed = true
            receiveBuffer = ReceiveBuffer(initialSequence: receiveBuffer.nextSequence)
            return []
        default:
            break
        }
        readClosed = true
        if receiveBuffer.readableCount > 0 {
            outputs.append(.segment(resetSegment(sequence: sendNext)))
            terminate(.aborted, into: &outputs)
            return outputs
        }
        if canWrite { finRequested = true }
        if state == .finWait2, timers[.finWait2Linger] == nil {
            timers[.finWait2Linger] = now + Self.finWait2Linger
        }
        completeCall(at: now, into: &outputs)
        return outputs
    }

    /// Aborts the connection immediately and drops buffered data (RFC 9293 §3.10.5).
    ///
    /// SYN-SENT sends nothing. CLOSING, LAST-ACK, and TIME-WAIT also send nothing because both sides have finished
    /// sending data (same section). Otherwise sends `<SEQ=SND.NXT><CTL=RST>`.
    package mutating func abort() -> [Output] {
        var outputs: [Output] = []
        switch state {
        case .closed:
            return []
        case .synSent, .closing, .lastAck, .timeWait:
            break
        case .synReceived, .established, .finWait1, .finWait2, .closeWait:
            outputs.append(.segment(resetSegment(sequence: sendNext)))
        }
        terminate(.aborted, into: &outputs)
        return outputs
    }

    /// The application can still write. It has not finished writing, and the state precedes the local FIN.
    var canWrite: Bool {
        guard !finRequested else { return false }
        switch state {
        case .synSent, .synReceived, .established, .closeWait: return true
        default: return false
        }
    }

    /// At the end of an application call, send what can be sent and emit due ACKs. An outgoing data segment already
    /// carried the ACK if one went out.
    private mutating func completeCall(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard state != .closed else { return }
        transmit(at: now, into: &outputs)
        flushAcknowledgment(at: now, into: &outputs)
    }
}
