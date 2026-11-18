/// Estimates the retransmission timer value (RTO) from RTT samples (RFC 6298).
///
/// Has no socket or clock. Inputs are measured round-trip times (`Duration`) and timer expiration events. The output is
/// `retransmissionTimeout` for the next timer. The connection decides when to start and stop the timer (RFC 6298
/// §§5.1~5.3, 5.6) and how many expirations to allow (contract behavior R4).
///
/// **The connection enforces Karn's rule (RFC 6298 §3).** Only the connection holding the send buffer knows which
/// segment was retransmitted. `recordSample(_:)` therefore assumes it receives RTTs from segments that were never
/// retransmitted. The caller must discard samples from retransmitted segments.
///
/// Uses the values in contract `docs/contracts/SwiftailNetstack.md` behavior R1. The initial value is 1 second, the
/// lower bound is 200ms (different from the 1 second SHOULD in RFC 6298 §2.4, lead session decision N4), the upper
/// bound is 120 seconds (under §2.5, an upper bound, if imposed, must be at least 60 seconds), and clock granularity G is 0.
package struct RTOEstimator: Sendable, Equatable {
    /// The RTO before any measurement (RFC 6298 §2.1).
    package static let initialTimeout = Duration.seconds(1)
    /// The RTO lower bound. RFC 6298 §2.4 says to raise it to 1 second (SHOULD), but this uses 200ms, as gVisor does
    /// (lead session decision N4).
    package static let minimumTimeout = Duration.milliseconds(200)
    /// The RTO upper bound (RFC 6298 §2.5 permits a cap of at least 60 seconds).
    package static let maximumTimeout = Duration.seconds(120)
    /// The minimum RTO after establishment if a SYN timer ever expired (RFC 6298 §5.7).
    package static let timeoutAfterSYNRetransmission = Duration.seconds(3)

    /// SRTT. `nil` before the first sample.
    package private(set) var smoothedRoundTripTime: Duration?
    /// RTTVAR. 0 before the first sample.
    package private(set) var roundTripTimeVariation = Duration.zero
    /// The RTO to use for the current timer. Doubles on each expiration (backoff) and returns to the formula when a sample arrives.
    package private(set) var retransmissionTimeout = RTOEstimator.initialTimeout

    private var synTimerHasExpired = false

    /// Creates an estimator before any measurements. The RTO is `initialTimeout` (1 second).
    package init() {}

    /// Updates SRTT, RTTVAR, and RTO using round-trip time `sample` from a segment that was never retransmitted (RFC 6298 §§2.2 and 2.3).
    ///
    /// For the first sample R, sets `SRTT = R` and `RTTVAR = R/2`. For later samples R', first computes
    /// `RTTVAR = 3/4·RTTVAR + 1/4·|SRTT − R'|` using the old SRTT, then `SRTT = 7/8·SRTT + 1/8·R'` (α = 1/8, β = 1/4).
    /// The RTO is `SRTT + max(G, 4·RTTVAR)`, with G equal to 0. A new calculation replaces the backed-off RTO
    /// (the discussion below RFC 6298 §5.7).
    ///
    /// Treats negative samples as 0 and samples above the upper bound as the upper bound. Neither is an actual
    /// round-trip time, and clamping prevents overflow in the subsequent `Duration` arithmetic.
    package mutating func recordSample(_ sample: Duration) {
        let measured = min(max(sample, .zero), Self.maximumTimeout)
        if let smoothed = smoothedRoundTripTime {
            let deviation = smoothed > measured ? smoothed - measured : measured - smoothed
            roundTripTimeVariation = (roundTripTimeVariation * 3 + deviation) / 4
            smoothedRoundTripTime = (smoothed * 7 + measured) / 8
        } else {
            smoothedRoundTripTime = measured
            roundTripTimeVariation = measured / 2
        }
        retransmissionTimeout = Self.bounded((smoothedRoundTripTime ?? measured) + roundTripTimeVariation * 4)
    }

    /// Handles a retransmission timer expiration. Doubles the RTO up to the upper bound (RFC 6298 §5.5).
    ///
    /// - Parameter forSYN: `true` if the expired timer was waiting for acknowledgment of a SYN or SYN-ACK. Remembers
    ///   this so `handshakeCompleted()` can raise the RTO to 3 seconds after establishment (RFC 6298 §5.7).
    package mutating func retransmissionTimerExpired(forSYN: Bool = false) {
        retransmissionTimeout = Self.bounded(retransmissionTimeout * 2)
        if forSYN { synTimerHasExpired = true }
    }

    /// Handles completion of the three-way handshake and the start of data sending. If a SYN timer expired and the RTO
    /// is less than 3 seconds, raises it to 3 seconds (RFC 6298 §5.7). Keeps any value already above it.
    package mutating func handshakeCompleted() {
        if synTimerHasExpired {
            retransmissionTimeout = max(retransmissionTimeout, Self.timeoutAfterSYNRetransmission)
            synTimerHasExpired = false
        }
    }

    private static func bounded(_ timeout: Duration) -> Duration {
        min(max(timeout, minimumTimeout), maximumTimeout)
    }
}
