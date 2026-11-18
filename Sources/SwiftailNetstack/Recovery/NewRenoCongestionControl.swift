/// NewReno congestion control for one connection, including slow start, congestion avoidance, fast retransmit, and fast
/// recovery (RFC 5681, RFC 6582).
///
/// A value type with only numeric inputs and outputs (byte counts, sequence numbers, and time). It has no socket or
/// clock. For each ACK, the connection **first distinguishes duplicate ACKs from ACKs of new data** and calls the
/// appropriate method. RFC 5681 §2 defines a duplicate ACK as one received with data in flight, no data or SYN or FIN
/// in the ACK, an ACK number equal to the highest seen so far, and an advertised window unchanged from the previous
/// one. This type reports the amount that can be sent now (`sendableBytes(peerWindow:flightSize:)`) and the instruction
/// to retransmit one segment from `SND.UNA` (`Instruction`). The connection starts and stops the retransmission timer.
/// Restarting the timer on the first partial ACK (RFC 6582 §3.2) is already covered by restarting it on every ACK of
/// new data (RFC 6298 §5.3), so there is no separate instruction.
///
/// There is no SACK (contract lead session decision N3). When multiple segments are lost in one window, recovery
/// retransmits one segment per partial ACK.
///
/// When the connection calls each method
/// - Immediately after establishing the connection, call `init(maximumSegmentSize:initialSequenceNumber:)`. ACKs of SYN
///   and SYN-ACK do not grow the window (RFC 6928 §2).
/// - Before first sending new data, call `restartAfterIdle(idleDuration:retransmissionTimeout:)`.
/// - On an ACK of new data, call `acknowledgeNewData(bytes:ackNumber:sendNext:)`.
/// - On a duplicate ACK, call `receiveDuplicateACK(ackNumber:sendNext:)`.
/// - On a retransmission timer expiration for data, call `retransmissionTimerExpired(sendUnacknowledged:sendNext:)`.
///   Skip SYN expirations because this type is created after the connection is established.
package struct NewRenoCongestionControl: Sendable, Equatable {
    /// An action the connection must take in response to an input.
    package enum Instruction: Sendable, Equatable {
        /// No instruction.
        case none
        /// Retransmit one segment from `SND.UNA` (RFC 5681 §3.2 step 3, partial ACK in RFC 6582 §3.2 step 3).
        case retransmitFirstUnacknowledgedSegment
    }

    /// The cwnd cap. Even with window scaling, the window is less than 2³⁰ (RFC 7323 §2.3), so a larger cwnd is
    /// unusable. Capping cwnd also prevents addition overflow from inflation or large inputs.
    package static let maximumWindow = 1 << 30
    /// The duplicate ACK count that triggers fast retransmit (RFC 5681 §3.2).
    package static let duplicateACKThreshold = 3
    /// The MSS option is 16 bits.
    private static let maximumSegmentSizeRange = 1...65_535

    /// SMSS, the advertised MSS capped by the local MTU (contract behavior T5).
    package let maximumSegmentSize: Int
    /// cwnd in bytes.
    package private(set) var congestionWindow: Int
    /// ssthresh in bytes. Initially effectively infinite (arbitrarily high per RFC 5681 §3.1).
    package private(set) var slowStartThreshold = NewRenoCongestionControl.maximumWindow
    /// The number of consecutive duplicate ACKs with SND.UNA unchanged. Resets to 0 on an ACK of new data or a timeout.
    package private(set) var duplicateACKCount = 0
    /// Whether fast recovery is in progress.
    package private(set) var isInFastRecovery = false
    /// RFC 6582's `recover`, represented as `SND.NXT` when fast recovery started or the RTO expired (one past the
    /// highest number sent at that point).
    ///
    /// RFC 6582 §3.2 defines `recover` as the highest number sent so far and compares `ACK − 1 > recover`. Storing the
    /// next number makes the equivalent test `ACK > recover`. A literal application would miss fast retransmit for a
    /// loss in the first window (ACK = ISS + 1) with the initial value ISS. When an ACK of new data passes `recover`,
    /// advance `recover` to just before the ACK. Sequence numbers wrap at 2³², so an old `recover` more than 2³¹ away
    /// reverses the ordering (4GiB transfer, contract test 6).
    package private(set) var recover: SequenceNumber

    /// The first sequence number of the segment retransmitted by the latest RTO expiration. Distinguishes repeated
    /// expirations for the same segment (RFC 5681 §3.1). Cleared when new data is acknowledged.
    private var lastTimeoutSegment: SequenceNumber?
    private let initialWindow: Int

    /// - Parameters: - maximumSegmentSize: SMSS. Clamped to 1…65535. - initialSequenceNumber: The local ISS, the
    ///   initial value of `recover` (RFC 6582 §3.2 step 1).
    package init(maximumSegmentSize: Int, initialSequenceNumber: SequenceNumber) {
        let size = Self.clamped(maximumSegmentSize)
        self.maximumSegmentSize = size
        initialWindow = Self.initialWindow(maximumSegmentSize: size)
        congestionWindow = initialWindow
        recover = initialSequenceNumber
    }

    /// The initial window, `min(10·MSS, max(2·MSS, 14600))` (RFC 6928 §2 equation 1).
    package static func initialWindow(maximumSegmentSize: Int) -> Int {
        let size = clamped(maximumSegmentSize)
        return min(10 * size, max(2 * size, 14_600))
    }

    /// The number of bytes that can be sent now, `min(cwnd, SND.WND) − FlightSize`, floored at 0. A shrinking window
    /// does not cause new data to be sent (RFC 9293 MUST-34).
    ///
    /// - Parameters: - peerWindow: `SND.WND`, the peer's advertised window after applying scaling. - flightSize:
    ///   `SND.NXT − SND.UNA`.
    package func sendableBytes(peerWindow: Int, flightSize: Int) -> Int {
        max(0, min(congestionWindow, max(0, peerWindow)) - max(0, flightSize))
    }

    // MARK: ACKs of New Data

    /// Handles an ACK of new data, with `SND.UNA` having advanced to `ackNumber`.
    ///
    /// Outside fast recovery, uses slow start (`cwnd < ssthresh`) with `cwnd += min(N, SMSS)` (RFC 5681 equation 2) or
    /// congestion avoidance (`cwnd >= ssthresh`) with `cwnd += SMSS·SMSS/cwnd` (equation 3). If integer division in
    /// equation 3 yields 0, increases by 1 byte (the SHOULD in §3.1). The RFC allows either approach when
    /// `cwnd == ssthresh`. This uses congestion avoidance.
    ///
    /// During fast recovery, follows RFC 6582 §3.2 step 3. If the ACK acknowledges everything through `recover` (full
    /// ACK), sets `cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS)` and exits recovery. This is the first of the two
    /// methods, which avoids bursting the new window all at once. Otherwise (partial ACK), requests retransmission of
    /// the first unacknowledged segment, subtracts the acknowledged amount from cwnd, adds SMSS if at least 1 SMSS was
    /// acknowledged, and stays in recovery.
    ///
    /// - Parameters: - bytes: The number of newly acknowledged bytes (N). Does nothing for 0 or less, which is not an
    ///   ACK of new data. - ackNumber: The ACK number. This is `SND.UNA` after the call. - sendNext: `SND.NXT`.
    package mutating func acknowledgeNewData(bytes: Int, ackNumber: SequenceNumber, sendNext: SequenceNumber) -> Instruction {
        guard bytes > 0 else { return .none }
        duplicateACKCount = 0
        lastTimeoutSegment = nil
        var instruction = Instruction.none
        if isInFastRecovery {
            if ackNumber.precedes(recover) {
                // Partial ACK (RFC 6582 §3.2 step 3). Deflates cwnd by the acknowledged amount, with a floor of 1 segment.
                congestionWindow = max(maximumSegmentSize, congestionWindow - bytes)
                if bytes >= maximumSegmentSize { grow(by: maximumSegmentSize) }
                instruction = .retransmitFirstUnacknowledgedSegment
            } else {
                // full ACK.
                let flightSize = Self.flightSize(from: ackNumber, to: sendNext)
                congestionWindow = min(slowStartThreshold, max(flightSize, maximumSegmentSize) + maximumSegmentSize)
                isInFastRecovery = false
            }
        } else if congestionWindow < slowStartThreshold {
            grow(by: min(bytes, maximumSegmentSize))
        } else {
            grow(by: max(1, maximumSegmentSize * maximumSegmentSize / congestionWindow))
        }
        if !isInFastRecovery, recover.precedes(ackNumber) {
            recover = ackNumber.advanced(by: .max)   // ACK − 1
        }
        return instruction
    }

    // MARK: Duplicate ACKs

    /// Handles a duplicate ACK.
    ///
    /// Only counts the first and second duplicate ACKs. Limited transmit from RFC 5681 §3.2 step 1 is excluded
    /// (contract exclusions table). On the third, if the ACK passes `recover` (RFC 6582 §3.2 step 2), performs fast
    /// retransmit. Sets `ssthresh = max(FlightSize/2, 2·SMSS)` (equation 4), `cwnd = ssthresh + 3·SMSS`, and
    /// `recover = SND.NXT`, then requests retransmission of one segment (steps 2 and 3). Otherwise, it leaves ssthresh
    /// unchanged
    /// and stays out of recovery, since the duplicate ACK might be from an unnecessary retransmission after RTO (RFC
    /// 6582 §4). Each duplicate ACK during fast recovery applies `cwnd += SMSS` (step 4).
    ///
    /// - Parameters: - ackNumber: The ACK number (= `SND.UNA`). - sendNext: `SND.NXT`.
    package mutating func receiveDuplicateACK(ackNumber: SequenceNumber, sendNext: SequenceNumber) -> Instruction {
        if duplicateACKCount < Int.max { duplicateACKCount += 1 }
        if isInFastRecovery {
            // shortcut: Omits the RFC 5681 §3.2 step 4 MAY that caps inflation by the number of segments in flight.
            // SND.WND and 2³⁰ limit how much can be sent.
            grow(by: maximumSegmentSize)
            return .none
        }
        guard duplicateACKCount == Self.duplicateACKThreshold, recover.precedes(ackNumber) else { return .none }
        slowStartThreshold = lossThreshold(flightSize: Self.flightSize(from: ackNumber, to: sendNext))
        recover = sendNext
        congestionWindow = min(slowStartThreshold + 3 * maximumSegmentSize, Self.maximumWindow)
        isInFastRecovery = true
        return .retransmitFirstUnacknowledgedSegment
    }

    // MARK: RTO Expiration

    /// Handles expiration of the data retransmission timer. The connection retransmits one segment from `SND.UNA`.
    ///
    /// On the first expiration, sets `ssthresh = max(FlightSize/2, 2·SMSS)` (equation 4). On repeated expirations for
    /// the same segment, keeps ssthresh (RFC 5681 §3.1). In either case, `cwnd` becomes 1 segment (the loss window),
    /// and slow start reopens the window. Exits fast recovery if active and sets `recover` to `SND.NXT` (RFC 6582 §3.2
    /// step 4).
    ///
    /// - Parameters: - sendUnacknowledged: `SND.UNA`. Used to distinguish repeated expirations of the same segment. -
    ///   sendNext: `SND.NXT`.
    package mutating func retransmissionTimerExpired(sendUnacknowledged: SequenceNumber, sendNext: SequenceNumber) {
        if lastTimeoutSegment != sendUnacknowledged {
            slowStartThreshold = lossThreshold(flightSize: Self.flightSize(from: sendUnacknowledged, to: sendNext))
        }
        lastTimeoutSegment = sendUnacknowledged
        congestionWindow = maximumSegmentSize
        duplicateACKCount = 0
        isInFastRecovery = false
        recover = sendNext
    }

    // MARK: After Idle

    /// Restarts sending after a period without sending data. Call before sending. If the idle period exceeded the RTO,
    /// reduces the window to `cwnd = min(IW, cwnd)` (RW in RFC 5681 §4.1).
    ///
    /// - Parameters: - idleDuration: The time since data was last sent (RFC 5681 §4.1 refers to time without sending).
    ///   - retransmissionTimeout: The current RTO.
    package mutating func restartAfterIdle(idleDuration: Duration, retransmissionTimeout: Duration) {
        if idleDuration > retransmissionTimeout {
            congestionWindow = min(initialWindow, congestionWindow)
        }
    }

    // MARK: Helpers

    /// Equation 4, `max(FlightSize/2, 2·SMSS)`.
    private func lossThreshold(flightSize: Int) -> Int {
        max(flightSize / 2, 2 * maximumSegmentSize)
    }

    private mutating func grow(by increment: Int) {
        congestionWindow = min(congestionWindow + increment, Self.maximumWindow)
    }

    /// The distance from `from` to `to`. Returns 0 if `to` precedes `from`.
    private static func flightSize(from: SequenceNumber, to: SequenceNumber) -> Int {
        Int(max(0, to.distance(from: from)))
    }

    private static func clamped(_ size: Int) -> Int {
        min(max(size, maximumSegmentSizeRange.lowerBound), maximumSegmentSizeRange.upperBound)
    }
}
