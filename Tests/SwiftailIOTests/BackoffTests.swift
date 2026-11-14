import Testing

@testable import SwiftailIO

@Suite("물러나기")
struct BackoffTests {
    @Test("n² × 10ms를 상한에서 자르고 [0.5, 1.5)를 곱한다", arguments: [
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

    @Test("상한이 작으면 거기서 자른다")
    func smallMaximum() {
        let maximum = Duration.seconds(5)
        #expect(Backoff.delay(failures: 10, maximum: maximum, jitter: 0.5) == .seconds(1))
        #expect(Backoff.delay(failures: 1_000, maximum: maximum, jitter: 0.5) == maximum)
    }

    @Test("실패가 없으면 기다리지 않는다")
    func noFailures() {
        #expect(Backoff.delay(failures: 0, maximum: .seconds(30), jitter: 0.7) == .zero)
        #expect(Backoff.delay(failures: -3, maximum: .seconds(30), jitter: 0.7) == .zero)
    }
}
