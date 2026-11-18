import Foundation
import Testing

@testable import SwiftailControl

@Suite("Retry-After")
struct RetryPolicyTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)   // 2023-11-14T22:13:20Z

    @Test("Integer seconds")
    func seconds() {
        #expect(RetryPolicy.retryAfter("7", now: now, jitter: 0) == .seconds(7))
        #expect(RetryPolicy.retryAfter(" 120 ", now: now, jitter: 0) == .seconds(120))
    }

    @Test("HTTP-date is relative to the current time")
    func httpDate() {
        #expect(RetryPolicy.retryAfter("Tue, 14 Nov 2023 22:13:50 GMT", now: now, jitter: 0) == .seconds(30))
        #expect(RetryPolicy.retryAfter("Tuesday, 14-Nov-23 22:14:20 GMT", now: now, jitter: 0) == .seconds(60))
        #expect(RetryPolicy.retryAfter("Tue Nov 14 22:13:30 2023", now: now, jitter: 0) == .seconds(10))
    }

    @Test("Does not exceed 5 minutes")
    func capped() {
        #expect(RetryPolicy.retryAfter("600", now: now, jitter: 0) == .seconds(300))
        #expect(RetryPolicy.retryAfter("3600", now: now, jitter: 0) == .seconds(300))
    }

    @Test("Missing, nonpositive, over 1 hour, or unparseable values fall back to 5 seconds + [0, 5 seconds)", arguments: [
        nil, "", "0", "-5", "3601", "soon", "Tue, 14 Nov 2023 22:00:00 GMT", "99999999999999999999999",
    ] as [String?])
    func fallback(header: String?) {
        #expect(RetryPolicy.retryAfter(header, now: now, jitter: 0) == .seconds(5))
        #expect(RetryPolicy.retryAfter(header, now: now, jitter: 0.5) == .milliseconds(7_500))
    }

    /// Check the date range before converting to integer milliseconds. Cover the farthest date the parser accepts (year 99999), a later date it rejects,
    /// and the limits of integer seconds together.
    @Test("Dates in the distant future or past and integer limits fall back without crashing", arguments: [
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
