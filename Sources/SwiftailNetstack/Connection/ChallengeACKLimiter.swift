/// Rate-limits challenge ACKs (RFC 5961 §7, contract behavior X4).
///
/// Allows up to 10 ACKs per 5-second window. As in RFC 5961 §7, keeps only the window start and a count, with no timer.
/// The connection uses this for challenge ACKs (RST and SYN checks) and ACKs in response to out-of-window segments
/// without data or out-of-range ACKs (behaviors X2 and X3). Even if the peer floods it with invalid segments, this
/// connection sends at most 10 replies per 5 seconds, preventing ACK loops.
struct ChallengeACKLimiter: Sendable, Equatable {
    /// The window duration (example in RFC 5961 §7).
    static let interval = Duration.seconds(5)
    /// The number of ACKs that can be sent in one window (example in RFC 5961 §7).
    static let limit = 10

    private var windowStart: ContinuousClock.Instant?
    private var sentInWindow = 0

    /// Counts one and returns `true` if it can be sent at `now`.
    mutating func permit(at now: ContinuousClock.Instant) -> Bool {
        if let start = windowStart, now - start < Self.interval {
            guard sentInWindow < Self.limit else { return false }
        } else {
            windowStart = now
            sentInWindow = 0
        }
        sentInWindow += 1
        return true
    }
}
