/// Sends data and FIN segments, retransmissions, ACKs, and window advertisements.
///
/// The amount that can be sent is `min(cwnd, SND.WND) − FlightSize` (contract behavior R5). New data goes through
/// sender SWS avoidance (RFC 9293 §3.8.6.2.1). Ranges before `SND.NXT` (go-back-N after RTO) are retransmissions, so
/// they check only cwnd and ignore the peer's window (RFC 7323 §2.4 item 4, retransmission of segments that were in the
/// window when sent). Retransmission always starts at `SND.UNA` (contract behavior R7). Received SACK blocks are not
/// used yet (M6-10b).
extension TCPConnection {
    /// Sends data and FIN that can be sent now and sets send-related timers (retransmission, zero-window probe, SWS override).
    ///
    /// - Parameter overridingSillyWindowAvoidance: The override timer expired. Sends as much as the window allows
    ///   without applying the SWS avoidance conditions.
    mutating func transmit(
        at now: ContinuousClock.Instant, overridingSillyWindowAvoidance: Bool = false, into outputs: inout [Output]
    ) {
        switch state {
        case .established, .closeWait, .finWait1, .closing, .lastAck: break
        default: return
        }
        // Reduce cwnd if no data has been sent for a while (RFC 5681 §4.1, contract behavior R8).
        if !hasOutstandingData, let lastDataSentAt, unsentDataCount > 0 {
            congestionControl.restartAfterIdle(
                idleDuration: now - lastDataSentAt, retransmissionTimeout: retransmissionTimeout)
        }
        var override = overridingSillyWindowAvoidance
        var blockedBySillyWindow = false
        // The receive buffer does not change during sending, so all segments emitted by this call carry the same SACK option.
        let payloadLimit = segmentPayloadLimit
        while true {
            let isRetransmission = transmitNext.precedes(sendNext)
            var length = min(payloadLimit, unsentDataCount)
            if isRetransmission {
                length = min(length, Int(sendNext.distance(from: transmitNext)))
            }
            let windowRoom = max(0, Int(sendWindowEnd.distance(from: transmitNext)))
            if !isRetransmission, length > 0 {
                // Sender SWS avoidance (contract behavior F7): min(D, U) >= MSS, D <= U, min(D, U) >= Max(SND.WND)/2, or override.
                let pending = unsentDataCount
                let usable = min(pending, windowRoom)
                guard usable > 0 else { break }
                guard usable >= payloadLimit || pending <= windowRoom
                    || usable * 2 >= maximumSendWindow || override
                else {
                    blockedBySillyWindow = true
                    break
                }
                length = min(length, windowRoom)
            }
            // Avoid making a small segment truncated by cwnd. Data is in flight, so an ACK will reopen cwnd.
            let flight = Int(transmitNext.distance(from: sendUnacknowledged))
            if length > 0, congestionControl.congestionWindow - flight < length { break }

            let segmentEnd = transmitNext.advanced(by: UInt32(length))
            var fin = false
            if finRequested, segmentEnd == finSequence {
                // A retransmitted FIN ignores the window. A first FIN must be inside the window. The peer will not
                // accept it if the window is 0.
                fin = finSequence.precedes(sendNext) || windowRoom > length
            }
            guard length > 0 || fin else { break }

            let start = transmitNext
            let end = segmentEnd.advanced(by: fin ? 1 : 0)
            outputs.append(.segment(dataSegment(from: start, length: length, fin: fin)))
            if isRetransmission {
                statistics.retransmittedBytes += length
                discardRoundTripSample(overlapping: start, end)
            } else {
                statistics.sentBytes += length
                if roundTripSample == nil {
                    roundTripSample = RoundTripSample(start: start, end: end, sentAt: now)
                }
            }
            if sendNext.precedes(end) { sendNext = end }
            transmitNext = end
            if length > 0 { lastDataSentAt = now }
            if timers[.retransmission] == nil {
                timers[.retransmission] = now + retransmissionTimeout
            }
            if fin {
                if state == .established { state = .finWait1 }
                if state == .closeWait { state = .lastAck }
            }
            override = false
        }
        updateTransmissionTimers(at: now, blockedBySillyWindow: blockedBySillyWindow)
    }

    /// The number of bytes starting at `transmitNext` that have yet to be sent or will be retransmitted with go-back-N.
    var unsentDataCount: Int {
        max(0, Int(sendBuffer.endSequence.distance(from: transmitNext)))
    }

    /// Sets send-related timers.
    ///
    /// - Retransmission (RFC 6298 §5.2). Clear it if nothing is unacknowledged. Sending and ACK processing start it.
    /// - Zero-window probe (RFC 9293 §3.8.6.1, contract behavior F8). Set for one RTO later when nothing is in flight,
    ///   data or FIN is waiting to go out, and the window is closed.
    /// - SWS override (contract behavior F7). Set for 200ms later if SWS avoidance blocked sending because the window was small.
    mutating func updateTransmissionTimers(at now: ContinuousClock.Instant, blockedBySillyWindow: Bool) {
        if !hasOutstandingData {
            timers[.retransmission] = nil
        }
        let hasPending = unsentDataCount > 0 || (finRequested && !finSent)
        let windowClosed = Int(sendWindowEnd.distance(from: transmitNext)) <= 0
        if hasPending, !hasOutstandingData, windowClosed {
            if timers[.zeroWindowProbe] == nil {
                zeroWindowProbeInterval = retransmissionTimeout
                timers[.zeroWindowProbe] = now + zeroWindowProbeInterval
            }
        } else {
            timers[.zeroWindowProbe] = nil
        }
        if blockedBySillyWindow {
            if timers[.sillyWindowOverride] == nil {
                timers[.sillyWindowOverride] = now + Self.sillyWindowOverrideTimeout
            }
        } else {
            timers[.sillyWindowOverride] = nil
        }
    }

    /// Retransmits one segment from `SND.UNA` (fast retransmit, partial ACK, RFC 5681 §3.2, RFC 6582 §3.2). Ignores the
    /// window and cwnd. Does not go past `SND.NXT`.
    mutating func retransmitFirstUnacknowledgedSegment(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let start = sendUnacknowledged
        let available = max(0, Int(sendBuffer.endSequence.distance(from: start)))
        let length = min(segmentPayloadLimit, available, Int(sendNext.distance(from: start)))
        let fin = finSent && start.advanced(by: UInt32(length)) == finSequence
        guard length > 0 || fin else { return }
        let end = start.advanced(by: UInt32(length + (fin ? 1 : 0)))
        outputs.append(.segment(dataSegment(from: start, length: length, fin: fin)))
        statistics.retransmittedBytes += length
        discardRoundTripSample(overlapping: start, end)
        if transmitNext.precedes(end) { transmitNext = end }
    }

    /// Discards the measurement if retransmitted range `[start, end)` overlaps the segment being timed (Karn, contract behavior R2).
    mutating func discardRoundTripSample(overlapping start: SequenceNumber, _ end: SequenceNumber) {
        guard let sample = roundTripSample else { return }
        if sample.start.precedes(end), start.precedes(sample.end) {
            roundTripSample = nil
        }
    }

    // MARK: Segment Construction

    /// A segment carrying `length` bytes from `start` and FIN if present. Includes ACK and the current window. Sets PSH
    /// on a segment carrying the final buffered byte.
    mutating func dataSegment(from start: SequenceNumber, length: Int, fin: Bool) -> TCPSegment {
        let offset = Int(start.distance(from: sendBuffer.startSequence))
        var flags: TCPSegment.Flags = [.ack]
        if fin { flags.insert(.fin) }
        if length > 0, start.advanced(by: UInt32(length)) == sendBuffer.endSequence { flags.insert(.psh) }
        return acknowledgingSegment(
            sequence: start, flags: flags, payload: sendBuffer.bytes(from: offset, upTo: length))
    }

    /// A segment with ACK set. Includes RCV.NXT, the current window, and SACK blocks (`sackBlocksToSend`), and clears
    /// any delayed ACK because this segment carries it. Pure ACKs, piggybacked ACKs on data, zero-window probes, and
    /// keep-alives all go through here, so every outgoing ACK carries SACK while gaps remain (RFC 2018 §4).
    mutating func acknowledgingSegment(
        sequence: SequenceNumber, flags: TCPSegment.Flags, payload: [UInt8] = []
    ) -> TCPSegment {
        let window = advertisedWindowField()
        timers[.acknowledgment] = nil
        unacknowledgedByteCount = 0
        return TCPSegment(
            source: localEndpoint, destination: remoteEndpoint, sequenceNumber: sequence,
            acknowledgmentNumber: receiveNext, flags: flags, window: window, sackBlocks: sackBlocksToSend,
            payload: payload)
    }

    /// The SACK blocks to carry on the current ACK, up to 4 out-of-order ranges from the receive buffer, newest first
    /// (RFC 2018 §4, `ReceiveBuffer.sackBlocks`). Always empty if the peer did not send SACK-Permitted (RFC 2018 §4
    /// MUST NOT).
    ///
    /// shortcut: Omits D-SACK (RFC 2883, a first block reporting that previously received data arrived again). It only
    /// detects spurious retransmission at the peer and does not accelerate recovery. Revisit this when peer-side
    /// reordering detection (such as RACK) becomes a problem.
    var sackBlocksToSend: [TCPSegment.SACKBlock] {
        peerPermitsSACK ? receiveBuffer.sackBlocks(limit: TCPSegment.maximumSACKBlockCount) : []
    }

    /// The data limit for the outgoing data segment, Eff.snd.MSS minus the length of the segment's SACK option (RFC
    /// 9293 §3.7.1, contract behavior T5). The advertised MSS fills MTU 1280, so any option requires reducing data to
    /// keep the IP packet within 1280.
    var segmentPayloadLimit: Int {
        guard peerPermitsSACK else { return sendMaximumSegmentSize }
        let blockCount = min(receiveBuffer.outOfOrderRangeCount, TCPSegment.maximumSACKBlockCount)
        return sendMaximumSegmentSize - TCPSegment.sackOptionLength(blockCount: blockCount)
    }

    /// `<SEQ=sequence><CTL=RST>`.
    func resetSegment(sequence: SequenceNumber) -> TCPSegment {
        TCPSegment(source: localEndpoint, destination: remoteEndpoint, sequenceNumber: sequence, flags: [.rst])
    }

    // MARK: ACK

    /// Schedules an ACK by deadline. An immediate ACK is due now and goes out in `advance(to:)` at the same time or at
    /// the end of an application call. Keeps an earlier deadline if one exists, so the 40ms delayed ACK is not
    /// postponed.
    mutating func scheduleAcknowledgment(immediately: Bool, at now: ContinuousClock.Instant) {
        let deadline = immediately ? now : now + Self.delayedAcknowledgmentTimeout
        if let existing = timers[.acknowledgment], existing <= deadline { return }
        timers[.acknowledgment] = deadline
    }

    /// Sends a due ACK as `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`.
    mutating func flushAcknowledgment(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard let deadline = timers[.acknowledgment], deadline <= now else { return }
        sendAcknowledgment(into: &outputs)
    }

    mutating func sendAcknowledgment(into outputs: inout [Output]) {
        switch state {
        case .synSent, .closed:
            timers[.acknowledgment] = nil
        default:
            outputs.append(.segment(acknowledgingSegment(sequence: sendNext, flags: [.ack])))
        }
    }

    // MARK: Advertised Window

    /// The outgoing window field on non-SYN segments, `RCV.WND >> Rcv.Wind.Shift` (RFC 7323 §2.3).
    ///
    /// Receiver SWS avoidance (RFC 9293 §3.8.6.2.2, contract behavior F3). Move the advertised edge only if the right
    /// edge allowed by the buffer is at least `min(buffer/2, Eff.snd.MSS)` farther than the advertised edge. The new
    /// edge is rounded down using the shift and never moves left (SHLD-14). Even if rounding makes the field indicate
    /// an earlier edge, accept through the previously advertised edge (RFC 7323 §2.4).
    mutating func advertisedWindowField() -> UInt16 {
        let receiveNext = self.receiveNext
        let candidateEnd = receiveWindowEnd
        let threshold = min(receiveBuffer.capacity / 2, sendMaximumSegmentSize)
        if Int(candidateEnd.distance(from: advertisedWindowEnd)) >= threshold {
            let span = max(0, Int(candidateEnd.distance(from: receiveNext)))
            let field = min(Int(UInt16.max), span >> receiveWindowShift)
            let quantizedEnd = receiveNext.advanced(by: UInt32(field << receiveWindowShift))
            if advertisedWindowEnd.precedes(quantizedEnd) {
                advertisedWindowEnd = quantizedEnd
            }
        }
        let span = max(0, Int(advertisedWindowEnd.distance(from: receiveNext)))
        return UInt16(min(Int(UInt16.max), span >> receiveWindowShift))
    }

    /// Determines when to send an immediate pure window update ACK after the application reads (contract behavior F3).
    /// The remaining advertised window (advertised right edge − RCV.NXT) must be at most half the receive buffer, and
    /// the advertised edge must be able to advance by the SWS avoidance threshold (`min(buffer/2, MSS)`) or more.
    ///
    /// If the remaining window is more than half the buffer, the peer still has plenty of room to send. The next window
    /// rides on an ACK of data (2×MSS or 40ms) or on outgoing data. This avoids a pure ACK each time the application
    /// reads a little. A zero or small window leaves at most half the buffer, so reading enough to reach the threshold
    /// immediately advertises the window and avoids a stall.
    var windowUpdateIsDue: Bool {
        let remaining = Int(advertisedWindowEnd.distance(from: receiveNext))
        guard remaining <= receiveBuffer.capacity / 2 else { return false }
        let threshold = min(receiveBuffer.capacity / 2, sendMaximumSegmentSize)
        return Int(receiveWindowEnd.distance(from: advertisedWindowEnd)) >= threshold
    }

    /// The right edge of the currently advertisable window, as far as both free buffer space and `receiveWindowLimit` allow.
    private var receiveWindowEnd: SequenceNumber {
        let limit = min(receiveBuffer.capacity, receiveWindowLimit)
        return receiveBuffer.nextSequence.advanced(by: UInt32(max(0, limit - receiveBuffer.readableCount)))
    }
}
