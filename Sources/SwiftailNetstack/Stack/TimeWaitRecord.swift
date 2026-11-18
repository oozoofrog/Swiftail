/// The record that replaces a connection in TIME-WAIT (contract behavior S6).
///
/// The side that closed first stays in TIME-WAIT to ACK retransmissions of the peer's FIN and keep late segments from
/// the previous connection out of a new connection with the same 4-tuple (RFC 9293 §3.6.1, MUST-13). To avoid holding a
/// connection and its buffers for 60 seconds, retains only the 4-tuple (the table key), two sequence numbers, and the
/// deadline. A record is not discarded before the deadline, except when the per-peer limit is exceeded (see
/// `TCPStack.addTimeWaitRecord`).
struct TimeWaitRecord: Sendable, Equatable {
    /// SND.NXT, the sequence number after the local FIN.
    var sendNext: SequenceNumber
    /// RCV.NXT, the sequence number after the peer's FIN.
    var receiveNext: SequenceNumber
    /// The time at which the record expires.
    var deadline: ContinuousClock.Instant
    /// The latest possible `deadline`, the time the connection entered TIME-WAIT + 2MSL
    /// (`TCPConnection.maximumTimeWaitLifetime`, 240 seconds, RFC 9293 §3.6.1 MUST-13). If FIN retransmissions simply
    /// reset the deadline, a peer could hold the record forever by retransmitting FIN every 59 seconds (M6 review A).
    let lifetimeEnd: ContinuousClock.Instant

    /// Returns the reply to a segment for this 4-tuple, or `nil` if no reply is due. A retransmitted FIN resets the
    /// deadline to 60 seconds later, capped at `lifetimeEnd`.
    ///
    /// - Ignores RST. Step two of RFC 9293 §3.10.7.4 says to enter CLOSED on an RST in TIME-WAIT, but contract behavior
    ///   S6 keeps the record until its deadline. gVisor also ignores RST in TIME-WAIT (TCP notes §4.2). This prevents
    ///   the TIME-WAIT assassination described in RFC 1337.
    /// - ACKs a retransmission of the peer's already consumed FIN (`SEG.SEQ + data length = RCV.NXT − 1`) and resets
    ///   the deadline (TIME-WAIT in steps five and eight of RFC 9293 §3.10.7.4, contract behavior T6). Uses the same
    ///   condition as the TIME-WAIT exception in `TCPConnection`.
    /// - Replies to SYN with a challenge ACK (RFC 5961 §4.2, RFC 9293 §3.10.7.4 step four). Does not immediately open a
    ///   new connection on the same 4-tuple and does not use the MAY in RFC 9293 §3.6.1.
    /// - ACKs other segments that consume sequence numbers (data, other FINs), following the sequence check rule to ACK
    ///   unacceptable segments.
    /// - Does not reply to ACKs without data, preventing an ACK loop. At most one reply per received segment means
    ///   there is no amplification (contract behavior X8).
    ///
    /// Replies with `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` and a window of 0 because this connection receives no more data.
    mutating func reply(to segment: TCPSegment, at now: ContinuousClock.Instant) -> TCPSegment? {
        let flags = segment.flags
        if flags.contains(.rst) { return nil }
        let isFinRetransmission =
            flags.contains(.fin) && !flags.contains(.syn)
            && segment.sequenceNumber.advanced(by: UInt32(clamping: segment.payload.count))
                == receiveNext.advanced(by: .max)  // RCV.NXT − 1
        if isFinRetransmission {
            deadline = min(now + TCPConnection.timeWaitDuration, lifetimeEnd)
        } else if segment.sequenceLength == 0 {
            return nil
        }
        return TCPSegment(
            source: segment.destination, destination: segment.source, sequenceNumber: sendNext,
            acknowledgmentNumber: receiveNext, flags: [.ack])
    }
}
