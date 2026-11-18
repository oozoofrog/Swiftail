/// Receives segments. Processing in synchronized states (SYN-RECEIVED onward) follows RFC 9293 §3.10.7.4 in order:
/// sequence check → RST → SYN → ACK → data → FIN (contract behavior T2). gVisor uses a different order, with data
/// before ACK. RST, SYN, and ACK checks follow RFC 5961 (contract behavior X3).
extension TCPConnection {
    /// Processes one segment from the peer. The stack has already checked that the 4-tuple belongs to this connection.
    ///
    /// Immediate ACKs (out-of-order data, data filling a gap, 2×MSS of accumulated data, FIN, out-of-window segments,
    /// and so on) come from this segment's output. This sends one ACK per segment even when received in a group (RFC
    /// 5681 §4.2 immediate ACK, since the peer's fast retransmit counts three duplicate ACKs). Only deferrable ACKs
    /// (less than 2×MSS of in-order data) get a 40ms deadline (see the type documentation). Accepting any segment does
    /// not crash (contract behavior X1).
    package mutating func receive(_ segment: TCPSegment, at now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        switch state {
        case .closed:
            return []
        case .synSent:
            receiveInSynSent(segment, at: now, into: &outputs)
        default:
            receiveSynchronized(segment, at: now, into: &outputs)
            if isFastRetransmitPending {
                isFastRetransmitPending = false
                if state != .closed { retransmitFirstUnacknowledgedSegment(at: now, into: &outputs) }
            }
            // Measure from the state after processing, so a connection that just entered FIN-WAIT-2 or CLOSE-WAIT also gets keep-alive.
            refreshKeepalive(at: now)
        }
        transmit(at: now, into: &outputs)
        // If data went out, it carried the ACK and cleared its deadline. Emit any remaining ACK whose deadline is now.
        flushAcknowledgment(at: now, into: &outputs)
        return outputs
    }

    /// Data and FIN that passed the sequence check, trimmed to the window.
    struct InboundText {
        /// The first sequence number of remaining data, at least `RCV.NXT`.
        var sequence: SequenceNumber
        var payload: ArraySlice<UInt8>
        /// FIN is inside the window. Its number is `sequence + payload.count`.
        var fin: Bool
        /// The window was 0, so all data was dropped (the special allowance for a zero window in step one of RFC 9293 §3.10.7.4).
        var droppedForZeroWindow: Bool
    }

    mutating func receiveSynchronized(_ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let flags = segment.flags

        // In TIME-WAIT, the sequence check would reject a retransmission of the peer's already consumed FIN. Check it
        // first, answer with ACK, and restart the 60-second timer (TIME-WAIT in steps five and eight of RFC 9293
        // §3.10.7.4, contract behavior T6). Cap the deadline at 240 seconds from entering TIME-WAIT (2MSL in RFC 9293
        // §3.6.1). This prevents a peer from holding the connection by retransmitting FIN every 59 seconds (M6 review
        // A).
        if state == .timeWait, flags.contains(.fin), !flags.contains(.rst), !flags.contains(.syn),
            segment.sequenceNumber.advanced(by: UInt32(clamping: segment.payload.count))
                == receiveNext.advanced(by: .max)  // RCV.NXT − 1
        {
            let lifetimeEnd = (timeWaitEnteredAt ?? now) + Self.maximumTimeWaitLifetime
            timers[.timeWait] = min(now + Self.timeWaitDuration, lifetimeEnd)
            scheduleAcknowledgment(immediately: true, at: now)
            return
        }

        // First, sequence check (table 6). ACK and drop an unacceptable segment, or silently drop an RST. Replies to
        // segments without data are rate-limited (contract behavior X2).
        guard let text = acceptedText(of: segment) else {
            if !flags.contains(.rst), !segment.payload.isEmpty || challengeLimiter.permit(at: now) {
                scheduleAcknowledgment(immediately: true, at: now)
            }
            return
        }

        // Second, RST (RFC 5961 §3.2). Send a challenge ACK if in the window but not at RCV.NXT. Use the original SEG.SEQ.
        if flags.contains(.rst) {
            if segment.sequenceNumber == receiveNext {
                terminate(.reset, into: &outputs)
            } else {
                sendChallengeAcknowledgment(at: now)
            }
            return
        }

        // Fourth, SYN. SYN-RECEIVED from a passive open returns to LISTEN (the stack silently removes it). In
        // synchronized states, send a challenge ACK and drop it regardless of its number (RFC 5961 §4.2).
        if flags.contains(.syn) {
            if state == .synReceived {
                terminate(.reset, into: &outputs)
            } else {
                sendChallengeAcknowledgment(at: now)
            }
            return
        }

        // Fifth, ACK.
        guard flags.contains(.ack) else { return }
        if state == .synReceived {
            guard completeHandshake(segment, at: now, into: &outputs) else { return }
        } else {
            guard processAcknowledgment(segment, at: now, into: &outputs) else { return }
        }

        // Step six (URG) is unused (contract exclusions table). Proceed to steps seven and eight.
        if text.droppedForZeroWindow {
            scheduleAcknowledgment(immediately: true, at: now)
        }
        processText(text, at: now, into: &outputs)
    }

    // MARK: First Step — Sequence Check

    /// Checks acceptability (RFC 9293 §3.10.7.4 table 6). If acceptable, trims bytes outside the window, both already
    /// received bytes and bytes beyond its advertised right edge.
    ///
    /// RCV.WND extends to the farthest advertised right edge (contract behavior F1, RFC 7323 §2.4). A window of 0
    /// generally rejects data segments. For a segment starting at RCV.NXT, drops the data and checks only ACK and RST
    /// (the special allowance for a zero window in the same section). Otherwise the side that closed the window would
    /// miss the peer's ACKs.
    ///
    /// Accepts a **FIN without data** at RCV.NXT even if the window is 0 (contract behavior T6). Table 6 would reject
    /// it because it has length 1, but FIN uses no buffer. gVisor measures length using data alone and accepts this FIN
    /// (`rcv.go:460`, `header/tcp.go:682-685`). It also sends FIN regardless of the window. Rejecting it would make
    /// retransmission back off on RTO, delaying EOF by up to 120 seconds and possibly reaching the peer's
    /// retransmission limit (M6 review A). Drops FIN with data along with the data, following the rule above.
    func acceptedText(of segment: TCPSegment) -> InboundText? {
        let receiveNext = self.receiveNext
        let window = max(0, Int(advertisedWindowEnd.distance(from: receiveNext)))
        let start = Int(segment.sequenceNumber.distance(from: receiveNext))
        let length = Int(segment.sequenceLength)
        if length == 0 {
            guard window == 0 ? start == 0 : (0 <= start && start < window) else { return nil }
        } else if window == 0 {
            guard start == 0 else { return nil }
            let isBareFin = segment.payload.isEmpty && segment.flags.contains(.fin) && !segment.flags.contains(.syn)
            return InboundText(sequence: receiveNext, payload: [], fin: isBareFin, droppedForZeroWindow: !isBareFin)
        } else {
            let last = start + length - 1
            guard (0 <= start && start < window) || (0 <= last && last < window) else { return nil }
        }

        // Data starts at the number after SYN. Trim the left (before RCV.NXT) and right (past the advertised edge). Do
        // not consume a trimmed FIN.
        var sequence = segment.sequenceNumber.advanced(by: segment.flags.contains(.syn) ? 1 : 0)
        var payload = segment.payload[...]
        let behind = Int(receiveNext.distance(from: sequence))
        if behind > 0 {
            let dropped = min(behind, payload.count)
            payload = payload.dropFirst(dropped)
            sequence = sequence.advanced(by: UInt32(dropped))
        }
        let room = max(0, Int(advertisedWindowEnd.distance(from: sequence)))
        // FIN is numbered at the end of the original data. Do not consume it before RCV.NXT (already consumed) or beyond the advertised edge.
        let fin = segment.flags.contains(.fin) && behind <= segment.payload.count && payload.count < room
        if payload.count > room {
            payload = payload.prefix(room)
        }
        return InboundText(sequence: sequence, payload: payload, fin: fin, droppedForZeroWindow: false)
    }

    // MARK: Fifth Step — ACK

    /// ACK in SYN-RECEIVED. If `SND.UNA < SEG.ACK =< SND.NXT`, enter ESTABLISHED and fill the window from this segment.
    /// Otherwise, send `<SEQ=SEG.ACK><CTL=RST>` (contract behavior T4). Skip the preliminary RFC 5961 §5.2 range check
    /// in this state. Every invalid ACK gets RST, as in Linux and gVisor.
    mutating func completeHandshake(
        _ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]
    ) -> Bool {
        let ack = segment.acknowledgmentNumber
        guard sendUnacknowledged.precedes(ack), ack.precedesOrEquals(sendNext) else {
            outputs.append(.segment(resetSegment(sequence: ack)))
            return false
        }
        sendUnacknowledged = ack
        let peerWindow = scaledWindow(of: segment)
        sendWindow = peerWindow
        maximumSendWindow = max(maximumSendWindow, peerWindow)
        lastPeerWindow = peerWindow
        sendWindowUpdateSequence = segment.sequenceNumber
        sendWindowUpdateAcknowledgment = ack
        establish(at: now, into: &outputs)
        return true
    }

    /// Processes an ACK in a synchronized state. Returns `true` if processing should continue for this segment.
    ///
    /// 1. RFC 5961 §5.2. If outside `SND.UNA − MAX.SND.WND =< SEG.ACK =< SND.NXT`, drop and reply with ACK (contract
    ///    behavior X3, rate limit X4).
    /// 2. If it acknowledges new data, update the buffer, RTT, congestion control, and timer. If `SEG.ACK = SND.UNA`,
    ///    check for a duplicate ACK (RFC 5681 §2).
    /// 3. Update the window only if `SND.UNA =< SEG.ACK =< SND.NXT` and the WL1 and WL2 rules hold (contract behavior F9).
    /// 4. Transition state if the local FIN was acknowledged.
    mutating func processAcknowledgment(
        _ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]
    ) -> Bool {
        let ack = segment.acknowledgmentNumber
        guard Int(ack.distance(from: sendUnacknowledged)) >= -maximumSendWindow, ack.precedesOrEquals(sendNext) else {
            if challengeLimiter.permit(at: now) {
                scheduleAcknowledgment(immediately: true, at: now)
            }
            return false
        }
        acknowledgedSinceRetransmissionTimeout = true
        let peerWindow = scaledWindow(of: segment)
        // Restart the count because the peer answered the probe (MUST-37). A connection released by the application
        // requires progress (contract behavior F8).
        if !readClosed || sendUnacknowledged.precedes(ack) || peerWindow > 0 {
            zeroWindowProbeCount = 0
        }

        // shortcut: Does not use received SACK blocks (`segment.sackBlocks`). Selective retransmission of lost ranges
        // (RFC 6675) is M6-10b. The statistics count whether the peer sends SACK (M6-10b S1).
        if !segment.sackBlocks.isEmpty { statistics.acknowledgmentsWithSACK += 1 }
        if sendUnacknowledged.precedes(ack) {
            acknowledge(upTo: ack, at: now, into: &outputs)
        } else if ack == sendUnacknowledged, isDuplicateAcknowledgment(segment, peerWindow: peerWindow) {
            statistics.duplicateAcknowledgments += 1
            let threshold = congestionControl.slowStartThreshold
            let instruction = congestionControl.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext)
            if instruction == .retransmitFirstUnacknowledgedSegment {
                isFastRetransmitPending = true
                statistics.fastRetransmits += 1
                if congestionControl.slowStartThreshold < threshold { statistics.slowStartThresholdReductions += 1 }
            }
        }
        lastPeerWindow = peerWindow

        if sendUnacknowledged.precedesOrEquals(ack),
            sendWindowUpdateSequence.precedes(segment.sequenceNumber)
                || (sendWindowUpdateSequence == segment.sequenceNumber
                    && sendWindowUpdateAcknowledgment.precedesOrEquals(ack))
        {
            sendWindow = peerWindow
            maximumSendWindow = max(maximumSendWindow, peerWindow)
            sendWindowUpdateSequence = segment.sequenceNumber
            sendWindowUpdateAcknowledgment = ack
        }

        guard finAcknowledged else { return true }
        switch state {
        case .finWait1:
            enterFinWait2(at: now)
        case .closing:
            enterTimeWait(at: now)
            return false
        case .lastAck:
            terminate(.finished, into: &outputs)
            return false
        default:
            break
        }
        return true
    }

    /// An ACK of new data (ESTABLISHED in step five of RFC 9293 §3.10.7.4, RFC 6298 §§5.2 and 5.3).
    mutating func acknowledge(upTo ack: SequenceNumber, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let acknowledgedCount = Int(ack.distance(from: sendUnacknowledged))
        // The ACK of FIN is outside the buffer. Discard data only up to the FIN number.
        let released = sendBuffer.acknowledge(upTo: finAcknowledgedBy(ack) ? finSequence : ack)
        sendUnacknowledged = ack
        if transmitNext.precedes(ack) { transmitNext = ack }
        retransmissionCount = 0
        if let sample = roundTripSample, sample.end.precedesOrEquals(ack) {
            retransmissionEstimator.recordSample(now - sample.sentAt)
            roundTripSample = nil
        }
        let instruction = congestionControl.acknowledgeNewData(
            bytes: acknowledgedCount, ackNumber: ack, sendNext: sendNext)
        timers[.retransmission] = hasOutstandingData ? now + retransmissionTimeout : nil
        if instruction == .retransmitFirstUnacknowledgedSegment {
            isFastRetransmitPending = true
            statistics.partialAcknowledgmentRetransmits += 1
        } else if !congestionControl.isInFastRecovery {
            statistics.maximumCongestionWindow = max(
                statistics.maximumCongestionWindow, congestionControl.congestionWindow)
        }
        if released > 0, isWriteBlocked {
            isWriteBlocked = false
            outputs.append(.event(.writable))
        }
    }

    /// Duplicate ACK (RFC 5681 §2). There is unacknowledged data, the segment has no data, SYN, or FIN, the ACK equals
    /// the highest seen so far (SND.UNA), and the advertised window is the same as in the preceding ACK.
    func isDuplicateAcknowledgment(_ segment: TCPSegment, peerWindow: Int) -> Bool {
        hasOutstandingData && segment.payload.isEmpty && !segment.flags.contains(.syn)
            && !segment.flags.contains(.fin) && segment.acknowledgmentNumber == sendUnacknowledged
            && peerWindow == lastPeerWindow
    }

    func finAcknowledgedBy(_ ack: SequenceNumber) -> Bool {
        finRequested && ack == finSequence.advanced(by: 1)
    }

    /// The window on a non-SYN segment, `SEG.WND << Snd.Wind.Shift` (RFC 7323 §2.3).
    func scaledWindow(of segment: TCPSegment) -> Int {
        Int(segment.window) << sendWindowShift
    }

    // MARK: Seventh and Eighth Steps — Data and FIN

    /// Accepts data only in ESTABLISHED, FIN-WAIT-1, and FIN-WAIT-2. Consumes FIN only after the preceding data has
    /// arrived without gaps (contract behavior T2). In other states, the peer has already sent FIN, so ignore data and
    /// FIN.
    mutating func processText(_ text: InboundText, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch state {
        case .established, .finWait1, .finWait2: break
        default: return
        }
        if !text.payload.isEmpty {
            // New data after close. Send RST to report lost data and end the connection (SHLD-3, contract behavior T6).
            if readClosed {
                outputs.append(.segment(resetSegment(sequence: sendNext)))
                terminate(.aborted, into: &outputs)
                return
            }
            let wasReadable = receiveBuffer.readableCount > 0
            let inOrder = text.sequence == receiveBuffer.nextSequence
            let insertion = receiveBuffer.insert(text.payload, at: text.sequence)
            // Immediately ACK out-of-order data or data filling a gap (RFC 5681 §4.2). For in-order data, ACK
            // immediately once 2×RMSS accumulates, or within 40ms otherwise (contract behavior F5).
            if !inOrder || insertion.filledGap || insertion.advancedCount == 0 {
                scheduleAcknowledgment(immediately: true, at: now)
            } else {
                unacknowledgedByteCount += insertion.advancedCount
                scheduleAcknowledgment(
                    immediately: unacknowledgedByteCount >= 2 * receiveMaximumSegmentSize, at: now)
            }
            if !wasReadable, receiveBuffer.readableCount > 0 {
                outputs.append(.event(.readable))
            }
        }
        if text.fin {
            // ACK FIN immediately. If preceded by a gap, record only its position and consume it when the gap is filled
            // (SHLD-31). Waiting for the peer to retransmit FIN would delay closure by an RTO.
            scheduleAcknowledgment(immediately: true, at: now)
            pendingFinSequence = text.sequence.advanced(by: UInt32(text.payload.count))
        }
        // Has all data before the recorded FIN arrived without gaps? This segment may have filled the gap.
        guard let finSequence = pendingFinSequence, finSequence.precedesOrEquals(receiveBuffer.nextSequence) else { return }
        pendingFinSequence = nil
        scheduleAcknowledgment(immediately: true, at: now)
        finReceived = true
        outputs.append(.event(.endOfStream))
        switch state {
        case .established:
            state = .closeWait
        case .finWait1:
            if finAcknowledged { enterTimeWait(at: now) } else { state = .closing }
        case .finWait2:
            enterTimeWait(at: now)
        default:
            break
        }
    }

    // MARK: State Transitions

    /// FIN-WAIT-2. A connection on which `close` was called ends if the peer's FIN does not arrive within 60 seconds (contract behavior T6).
    mutating func enterFinWait2(at now: ContinuousClock.Instant) {
        state = .finWait2
        if readClosed {
            timers[.finWait2Linger] = now + Self.finWait2Linger
        }
    }

    /// TIME-WAIT. Clear all other timers and start 60 seconds (step eight of RFC 9293 §3.10.7.4, contract behavior T6).
    /// Keep the delayed ACK for FIN.
    mutating func enterTimeWait(at now: ContinuousClock.Instant) {
        state = .timeWait
        let acknowledgment = timers[.acknowledgment]
        timers.removeAll()
        timers[.acknowledgment] = acknowledgment
        timers[.timeWait] = now + Self.timeWaitDuration
        timeWaitEnteredAt = now
        roundTripSample = nil
    }

    /// Reset keep-alive to 2 hours on receiving anything (contract behavior T8). Disable it in other states.
    mutating func refreshKeepalive(at now: ContinuousClock.Instant) {
        keepaliveProbeCount = 0
        switch state {
        case .established, .closeWait, .finWait2:
            timers[.keepalive] = now + Self.keepaliveIdle
        default:
            timers[.keepalive] = nil
        }
    }

    /// Challenge ACK (RFC 5961 §§3.2 and 4.2), `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`. Up to 10 per 5 seconds (contract behavior X4).
    mutating func sendChallengeAcknowledgment(at now: ContinuousClock.Instant) {
        if challengeLimiter.permit(at: now) {
            scheduleAcknowledgment(immediately: true, at: now)
        }
    }
}
