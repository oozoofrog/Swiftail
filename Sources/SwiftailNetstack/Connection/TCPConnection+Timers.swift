/// Handles expired timers one at a time in deadline order.
///
/// Each handler clears its timer or reschedules it after `now`. Retransmission, probes, and keep-alive measure the next
/// interval from `now`. This ensures the `advance(to:)` loop terminates and the resulting `nextDeadline` is always
/// after `now` or `nil`.
extension TCPConnection {
    /// The earliest timer deadline. Returns `nil` for an ended connection.
    package var nextDeadline: ContinuousClock.Instant? {
        state == .closed ? nil : timers.earliest?.deadline
    }

    /// Processes all timers due by `now`. Also emits delayed ACKs.
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        while state != .closed, let (kind, deadline) = timers.earliest, deadline <= now {
            timers[kind] = nil
            fire(kind, at: now, into: &outputs)
        }
        return outputs
    }

    private mutating func fire(_ kind: ConnectionTimers.Kind, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch kind {
        case .timeWait:
            terminate(.finished, into: &outputs)
        case .finWait2Linger:
            terminate(.timedOut, into: &outputs)
        case .retransmission:
            retransmissionTimerExpired(at: now, into: &outputs)
        case .zeroWindowProbe:
            sendZeroWindowProbe(at: now, into: &outputs)
        case .sillyWindowOverride:
            transmit(at: now, overridingSillyWindowAvoidance: true, into: &outputs)
        case .keepalive:
            sendKeepalive(at: now, into: &outputs)
        case .acknowledgment:
            sendAcknowledgment(into: &outputs)
        }
    }

    /// Retransmission timer expiration (RFC 6298 §§5.4~5.6, contract behaviors R3, R4, and R7).
    ///
    /// Retransmits SYN and SYN-ACK up to 7 times and ends the connection on the following expiration (247 seconds).
    /// Retransmits data and FIN up to 15 times. Doubles RTO, reports to congestion control (cwnd of 1 segment), then
    /// retransmits from `SND.UNA` as slow start allows (go-back-N).
    ///
    /// If the peer reduced its window to 0 with data in flight and ACKed after the last expiration, that expiration
    /// does not count toward the 15. The peer is alive and merely rejects out-of-window data (RFC 9293 §3.8.6 SHLD-17
    /// says not to close because data outside the window goes unacknowledged, and MUST-35 requires probing a zero
    /// window). In this case gVisor switches to zero-window probes and ignores the retransmission count (`snd.go:556`).
    /// The retransmitted segment doubles as a probe. For connections the application released with `close`, count
    /// without this exception and send RST at the limit so the peer releases its state too. This is the same rationale
    /// as the zero-window probe limit (`sendZeroWindowProbe`).
    private mutating func retransmissionTimerExpired(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch state {
        case .synSent, .synReceived:
            guard retransmissionCount < Self.synchronizeRetransmissionLimit else {
                terminate(.timedOut, into: &outputs)
                return
            }
            retransmissionCount += 1
            retransmissionEstimator.retransmissionTimerExpired(forSYN: true)
            timers[.retransmission] = now + retransmissionTimeout
            outputs.append(.segment(synchronizeSegment()))
        default:
            guard hasOutstandingData else { return }
            let peerIsAnswering = sendWindow == 0 && acknowledgedSinceRetransmissionTimeout
            acknowledgedSinceRetransmissionTimeout = false
            if !peerIsAnswering || readClosed {
                guard retransmissionCount < Self.dataRetransmissionLimit else {
                    if peerIsAnswering {
                        outputs.append(.segment(resetSegment(sequence: sendNext)))
                    }
                    terminate(.timedOut, into: &outputs)
                    return
                }
                retransmissionCount += 1
            }
            retransmissionEstimator.retransmissionTimerExpired()
            statistics.retransmissionTimeouts += 1
            let threshold = congestionControl.slowStartThreshold
            congestionControl.retransmissionTimerExpired(sendUnacknowledged: sendUnacknowledged, sendNext: sendNext)
            if congestionControl.slowStartThreshold < threshold { statistics.slowStartThresholdReductions += 1 }
            roundTripSample = nil
            transmitNext = sendUnacknowledged
            timers[.retransmission] = now + retransmissionTimeout
            transmit(at: now, into: &outputs)
        }
    }

    /// Zero-window probe (RFC 9293 §3.8.6.1, contract behavior F8). Sends one zero byte with
    /// `<SEQ=SND.UNA−1><ACK=RCV.NXT><CTL=ACK>` (same format as gVisor `snd.go:1009-1034`). The number has already been
    /// acknowledged, so the peer does not accept it as data and replies with an ACK carrying its current window. Keeps
    /// the connection open while the peer ACKs (MUST-37) and ends it after 15 probes without an ACK. Intervals double
    /// from RTO up to 60 seconds (SHLD-30).
    ///
    /// A connection released by the application with `close` sends RST and ends after 15 probes without progress, even
    /// if the peer replies (contract behavior F8). If the peer leaves the window at 0 and merely ACKs probes, the
    /// ownerless connection holds a slot and the send buffer indefinitely. This exception to MUST-37 is the resource
    /// management referred to in RFC 9293 §3.8.6.1 (RFC 6429 §§3 and 4 allow the OS to close ownerless connections).
    private mutating func sendZeroWindowProbe(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard zeroWindowProbeCount < Self.zeroWindowProbeLimit else {
            if readClosed {
                outputs.append(.segment(resetSegment(sequence: sendNext)))
            }
            terminate(.timedOut, into: &outputs)
            return
        }
        zeroWindowProbeCount += 1
        outputs.append(
            .segment(acknowledgingSegment(sequence: sendUnacknowledged.advanced(by: .max), flags: [.ack], payload: [0])))
        zeroWindowProbeInterval = min(zeroWindowProbeInterval * 2, Self.maximumZeroWindowProbeInterval)
        timers[.zeroWindowProbe] = now + zeroWindowProbeInterval
    }

    /// Keep-alive (contract behavior T8, RFC 9293 §3.8.4). After 2 hours without receiving anything, sends
    /// `<SEQ=SND.NXT−1><ACK=RCV.NXT><CTL=ACK>` every 75 seconds and ends the connection if 9 sends get no reply. With
    /// unacknowledged data or something to send, retransmission and probe timers handle it, so no keep-alive probe is
    /// sent (MUST-26).
    private mutating func sendKeepalive(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch state {
        case .established, .closeWait, .finWait2: break
        default: return
        }
        if hasOutstandingData || unsentDataCount > 0 || (finRequested && !finSent) {
            timers[.keepalive] = now + Self.keepaliveIdle
            return
        }
        guard keepaliveProbeCount < Self.keepaliveProbeLimit else {
            terminate(.timedOut, into: &outputs)
            return
        }
        keepaliveProbeCount += 1
        outputs.append(.segment(acknowledgingSegment(sequence: sendNext.advanced(by: .max), flags: [.ack])))
        timers[.keepalive] = now + Self.keepaliveInterval
    }
}
