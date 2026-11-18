import Testing

@testable import SwiftailIO

@Suite("Backoff")
struct BackoffTests {
    @Test("Caps n² × 10ms at the limit and multiplies by [0.5, 1.5)", arguments: [
        (1, Duration.milliseconds(10)),
        (2, .milliseconds(40)),
        (10, .seconds(1)),
        (54, .milliseconds(29_160)),
        (55, .seconds(30)),
        (1_000_000, .seconds(30)),
    ])
    func delay(failures: Int, base: Duration) {
        let maximum = Duration.seconds(30)
        #expect(Backoff.delay(failures: failures, maximum: maximum, jitter: 0) == base * 0.5)
        #expect(Backoff.delay(failures: failures, maximum: maximum, jitter: 0.5) == base)
        #expect(Backoff.delay(failures: failures, maximum: maximum, jitter: 0.999) < base * 1.5)
    }

    @Test("Caps the delay at a smaller limit")
    func smallMaximum() {
        let maximum = Duration.seconds(5)
        #expect(Backoff.delay(failures: 10, maximum: maximum, jitter: 0.5) == .seconds(1))
        #expect(Backoff.delay(failures: 1_000, maximum: maximum, jitter: 0.5) == maximum)
    }

    @Test("Does not wait when there are no failures")
    func noFailures() {
        #expect(Backoff.delay(failures: 0, maximum: .seconds(30), jitter: 0.7) == .zero)
        #expect(Backoff.delay(failures: -3, maximum: .seconds(30), jitter: 0.7) == .zero)
    }
}
