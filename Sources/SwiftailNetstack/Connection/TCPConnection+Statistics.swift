extension TCPConnection {
    /// Transmission statistics for one connection. When it ends, the stack includes these in the `.closed` event, and
    /// the node logs them on one line (contract “Connection close statistics log”). Used to decide whether to enable
    /// sender-side SACK recovery (M6-10b, contract M6-10b S1).
    ///
    /// Each value is counted once where the event occurs. Contains no addresses, ports, or data.
    package struct Statistics: Sendable, Equatable {
        /// The time the first SYN (active open) or SYN-ACK (passive open) was sent. Lifetime is the end time minus this time.
        package let openedAt: ContinuousClock.Instant
        /// The peer's SYN contained SACK-Permitted. The local side always sends it for an active open and sends it for
        /// a passive open only if the peer did, so this means both sides negotiated it.
        package var sackPermitted = false
        /// Data bytes sent for the first time, excluding SYN and FIN.
        package var sentBytes = 0
        /// Retransmitted data bytes (go-back-N after RTO, fast retransmit, partial ACK). Excludes the 1 byte of a zero-window probe.
        package var retransmittedBytes = 0
        /// The number of retransmission timer expirations for data or FIN. Excludes SYN and SYN-ACK expirations.
        package var retransmissionTimeouts = 0
        /// The number of entries into fast retransmit after three duplicate ACKs (RFC 5681 §3.2).
        package var fastRetransmits = 0
        /// The number of single-segment retransmissions triggered by a partial ACK during fast recovery (RFC 6582 §3.2 step 3).
        package var partialAcknowledgmentRetransmits = 0
        /// The number of duplicate ACKs received (definition in RFC 5681 §2).
        package var duplicateAcknowledgments = 0
        /// The number of received segments that passed the ACK check (RFC 5961 §5.2) and carried a SACK option. The
        /// blocks are not used yet (M6-10b).
        package var acknowledgmentsWithSACK = 0
        /// The peak cwnd in bytes immediately after new data is acknowledged outside fast recovery. Excludes inflated values during recovery.
        package var maximumCongestionWindow = 0
        /// The number of times ssthresh fell due to loss (three duplicate ACKs, first RTO expiration).
        package var slowStartThresholdReductions = 0

        package init(openedAt: ContinuousClock.Instant) {
            self.openedAt = openedAt
        }
    }
}
