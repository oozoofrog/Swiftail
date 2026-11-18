/// The timer deadlines held by one connection.
///
/// Timers are deadlines (instants) without a clock. The connection reports the earliest one through `nextDeadline` and
/// processes expired deadlines one at a time when the caller invokes `advance(to:)` at that time.
struct ConnectionTimers: Sendable, Equatable {
    /// Timer kinds. For deadlines at the same time, process in this order so timers that send data segments run before
    /// ACK timers and piggyback the delayed ACK (step seven in RFC 9293 §3.10.7.4).
    enum Kind: CaseIterable, Sendable {
        /// The end of TIME-WAIT (contract behavior T6, 60 seconds).
        case timeWait
        /// The limit on time in FIN-WAIT-2 after `close` (contract behavior T6, 60 seconds).
        case finWait2Linger
        /// Retransmission of SYN, SYN-ACK, data, or FIN (RFC 6298 §5).
        case retransmission
        /// Zero-window probe (RFC 9293 §3.8.6.1, contract behavior F8).
        case zeroWindowProbe
        /// Sender SWS avoidance override (RFC 9293 §3.8.6.2.1, contract behavior F7, 200ms).
        case sillyWindowOverride
        /// Keep-alive (contract behavior T8).
        case keepalive
        /// Delayed ACK (RFC 9293 §3.8.6.3, contract behavior F5). An immediate ACK is due now and goes out at the end
        /// of the `receive` or application call that set its deadline.
        case acknowledgment
    }

    private var deadlines: [Kind: ContinuousClock.Instant] = [:]

    subscript(kind: Kind) -> ContinuousClock.Instant? {
        get { deadlines[kind] }
        set { deadlines[kind] = newValue }
    }

    /// The earliest deadline and its kind. For ties, chooses the first in `Kind` declaration order.
    var earliest: (kind: Kind, deadline: ContinuousClock.Instant)? {
        var result: (kind: Kind, deadline: ContinuousClock.Instant)?
        for kind in Kind.allCases {
            guard let deadline = deadlines[kind] else { continue }
            if let current = result, current.deadline <= deadline { continue }
            result = (kind, deadline)
        }
        return result
    }

    mutating func removeAll() {
        deadlines.removeAll()
    }
}
