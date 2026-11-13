import Foundation
import Testing

@testable import SwiftailControl

@Suite("물러나기와 Retry-After")
struct RetryPolicyTests {
    @Test("n² × 10ms를 30초에서 자르고 [0.5, 1.5)를 곱한다", arguments: [
        (1, Duration.milliseconds(10)),
        (2, .milliseconds(40)),
        (10, .seconds(1)),
        (54, .milliseconds(29_160)),
        (55, .seconds(30)),
        (1_000_000, .seconds(30)),
    ])
    func backoff(failures: Int, base: Duration) {
        #expect(RetryPolicy.backoff(failures: failures, jitter: 0) == base * 0.5)
        #expect(RetryPolicy.backoff(failures: failures, jitter: 0.5) == base)
        #expect(RetryPolicy.backoff(failures: failures, jitter: 0.999) < base * 1.5)
    }

    @Test("실패가 없으면 기다리지 않는다")
    func noFailures() {
        #expect(RetryPolicy.backoff(failures: 0, jitter: 0.7) == .zero)
        #expect(RetryPolicy.backoff(failures: -3, jitter: 0.7) == .zero)
    }

    private let now = Date(timeIntervalSince1970: 1_700_000_000)   // 2023-11-14T22:13:20Z

    @Test("정수 초")
    func seconds() {
        #expect(RetryPolicy.retryAfter("7", now: now, jitter: 0) == .seconds(7))
        #expect(RetryPolicy.retryAfter(" 120 ", now: now, jitter: 0) == .seconds(120))
    }

    @Test("HTTP-date는 지금과의 차이")
    func httpDate() {
        #expect(RetryPolicy.retryAfter("Tue, 14 Nov 2023 22:13:50 GMT", now: now, jitter: 0) == .seconds(30))
        #expect(RetryPolicy.retryAfter("Tuesday, 14-Nov-23 22:14:20 GMT", now: now, jitter: 0) == .seconds(60))
        #expect(RetryPolicy.retryAfter("Tue Nov 14 22:13:30 2023", now: now, jitter: 0) == .seconds(10))
    }

    @Test("5분을 넘지 않는다")
    func capped() {
        #expect(RetryPolicy.retryAfter("600", now: now, jitter: 0) == .seconds(300))
        #expect(RetryPolicy.retryAfter("3600", now: now, jitter: 0) == .seconds(300))
    }

    @Test("없음·0 이하·1시간 초과·해석 불가는 5초 + [0, 5초)", arguments: [
        nil, "", "0", "-5", "3601", "soon", "Tue, 14 Nov 2023 22:00:00 GMT", "99999999999999999999999",
    ] as [String?])
    func fallback(header: String?) {
        #expect(RetryPolicy.retryAfter(header, now: now, jitter: 0) == .seconds(5))
        #expect(RetryPolicy.retryAfter(header, now: now, jitter: 0.5) == .milliseconds(7_500))
    }

    /// 날짜를 밀리초 정수로 바꾸기 전에 범위를 본다. 해석기가 받는 가장 먼 날짜(99999년)와 받지 않는 더 먼 날짜,
    /// 정수 초의 끝값을 같이 본다.
    @Test("먼 미래·먼 과거의 날짜와 정수 끝값도 죽지 않고 대체값", arguments: [
        "Sun, 06 Nov 99999 08:49:37 GMT",
        "Sun Nov 6 08:49:37 99999",
        "Sun, 06 Nov 999999 08:49:37 GMT",
        "Sun, 06 Nov 999999999 08:49:37 GMT",
        "Sun, 06 Nov 999999999999 08:49:37 GMT",
        "Sun, 06 Nov 0001 08:49:37 GMT",
        "Sun Nov 6 08:49:37 999999999",
        "9223372036854775807",
        "-9223372036854775808",
    ])
    func extremes(header: String) {
        #expect(RetryPolicy.retryAfter(header, now: now, jitter: 0) == .seconds(5))
    }
}
