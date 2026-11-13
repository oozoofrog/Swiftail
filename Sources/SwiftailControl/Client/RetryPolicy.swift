import Foundation

/// 실패 뒤 다시 시도하기까지 기다릴 시간. 시계도 난수도 갖지 않는 순수 계산이다.
///
/// - 일반 물러나기: 연속 실패 n번째에 `min(n² × 10ms, 30s) × [0.5, 1.5)`. 2ⁿ보다 완만하게 늘고,
///   곱하는 난수가 여러 노드가 한꺼번에 다시 붙는 것을 흩는다. 전체 netmap을 받으면 n을 0으로 되돌린다.
/// - 429와 `Retry-After`가 붙은 503: 서버가 정한 시간만큼 기다린다. 값이 없거나 0 이하·1시간 초과·해석 불가면
///   `5s + [0, 5s)`를 쓰고, 어느 쪽이든 5분을 넘기지 않는다.
///
/// `docs/protocol-notes/control-map.md` 4.4, 5장
/// (출처: tailscale.com `util/backoff/backoff.go`, `control/controlclient/direct.go` `parseRateLimitError`,
/// `control/controlclient/auto.go` `maxRetryWindow`, BSD-3-Clause).
enum RetryPolicy {
    static let maximumBackoff = Duration.seconds(30)
    static let maximumRetryAfter = Duration.seconds(5 * 60)

    /// 연속 실패 `failures`번째 뒤의 대기. `jitter`는 [0, 1)의 난수다.
    static func backoff(failures: Int, jitter: Double) -> Duration {
        let n = min(max(failures, 0), 1_000)
        let base = min(Duration.milliseconds(n * n * 10), maximumBackoff)
        return base * (0.5 + jitter)
    }

    /// `Retry-After` 헤더 값(정수 초 또는 HTTP-date)에 따른 대기. `jitter`는 [0, 1)의 난수다.
    static func retryAfter(_ header: String?, now: Date, jitter: Double) -> Duration {
        let fallback = Duration.seconds(5) + Duration.seconds(5) * jitter
        let value = header?.trimmingCharacters(in: .whitespaces) ?? ""
        let parsed: Duration?
        if let seconds = Int(value) {
            parsed = .seconds(seconds)
        } else if let date = httpDate(value) {
            // 정수로 바꾸기 전에 범위를 본다. 먼 날짜를 그대로 바꾸면 Int64를 넘어 트랩할 수 있다.
            let interval = date.timeIntervalSince(now)
            parsed = interval > 0 && interval <= 3_600 ? .milliseconds(Int64((interval * 1_000).rounded(.down))) : nil
        } else {
            parsed = nil
        }
        guard let parsed, parsed > .zero, parsed <= .seconds(3_600) else { return fallback }
        return min(parsed, maximumRetryAfter)
    }

    /// RFC 9110 5.6.7의 IMF-fixdate(`Sun, 06 Nov 1994 08:49:37 GMT`). Go `http.ParseTime`이 받는
    /// 옛 형식(RFC 850, asctime)도 받는다.
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
