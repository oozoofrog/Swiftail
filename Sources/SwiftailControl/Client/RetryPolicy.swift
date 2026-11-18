import Foundation

/// The retry delay specified by the control server. Computes it without a clock or randomness.
///
/// - Ordinary backoff: Uses `Backoff.delay` with a 30-second cap. `ControlClient` resets its consecutive failure count on a usable netmap.
/// - 429, or 503 with `Retry-After`: Waits the server-specified time. If the value is missing, at or below 0, above 1 hour, or unparseable,
///   uses `5s + [0, 5s)`. Both cases are capped at 5 minutes.
///
/// `docs/protocol-notes/control-map.md` §4.4, Chapter 5
/// (origin: tailscale.com `util/backoff/backoff.go`, `parseRateLimitError` in `control/controlclient/direct.go`,
/// `control/controlclient/auto.go` `maxRetryWindow`, BSD-3-Clause).
enum RetryPolicy {
    static let maximumBackoff = Duration.seconds(30)
    static let maximumRetryAfter = Duration.seconds(5 * 60)

    /// The delay for a `Retry-After` header value (integer seconds or HTTP-date). `jitter` is a random value in [0, 1).
    static func retryAfter(_ header: String?, now: Date, jitter: Double) -> Duration {
        let fallback = Duration.seconds(5) + Duration.seconds(5) * jitter
        let value = header?.trimmingCharacters(in: .whitespaces) ?? ""
        let parsed: Duration?
        if let seconds = Int(value) {
            parsed = .seconds(seconds)
        } else if let date = httpDate(value) {
            // Check the range before converting to an integer. Converting a distant date directly could exceed Int64 and trap.
            let interval = date.timeIntervalSince(now)
            parsed = interval > 0 && interval <= 3_600 ? .milliseconds(Int64((interval * 1_000).rounded(.down))) : nil
        } else {
            parsed = nil
        }
        guard let parsed, parsed > .zero, parsed <= .seconds(3_600) else { return fallback }
        return min(parsed, maximumRetryAfter)
    }

    /// The IMF-fixdate in RFC 9110 §5.6.7 (`Sun, 06 Nov 1994 08:49:37 GMT`). Also accepts the legacy formats
    /// Go's `http.ParseTime` accepts (RFC 850 and asctime).
    private static func httpDate(_ text: String) -> Date? {
        for format in ["EEE, dd MMM yyyy HH:mm:ss 'GMT'", "EEEE, dd-MMM-yy HH:mm:ss 'GMT'", "EEE MMM d HH:mm:ss yyyy"] {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "GMT")
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }
}
