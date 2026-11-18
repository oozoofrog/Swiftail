import Testing

@testable import SwiftailNetstack

/// Retransmission timer RTO estimation (RFC 6298). Contract `docs/contracts/SwiftailNetstack.md` behaviors R1~R3 and test 7.
/// Expected values are calculated by hand from the RFC 6298 2.2·2.3 formulas (G = 0, K = 4, α = 1/8, β = 1/4).
@Suite("RTO estimator")
struct RTOEstimatorTests {
    @Test("Before measurement, the RTO is 1 second (2.1)")
    func initialTimeout() {
        let estimator = RTOEstimator()
        #expect(estimator.retransmissionTimeout == .seconds(1))
        #expect(estimator.smoothedRoundTripTime == nil)
        #expect(estimator.roundTripTimeVariation == .zero)
    }

    @Test("First sample R: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4·RTTVAR (2.2)")
    func firstSample() {
        var estimator = RTOEstimator()
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(100))
        #expect(estimator.roundTripTimeVariation == .milliseconds(50))
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
    }

    @Test("Next sample R': updates RTTVAR first using the old SRTT, then updates SRTT (2.3)")
    func laterSamples() {
        var estimator = RTOEstimator()
        estimator.recordSample(.milliseconds(100))
        // RTTVAR = (3·50 + |100 − 180|)/4 = 57.5ms, SRTT = (7·100 + 180)/8 = 110ms, RTO = 110 + 4·57.5 = 340ms
        estimator.recordSample(.milliseconds(180))
        #expect(estimator.roundTripTimeVariation == .microseconds(57_500))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(110))
        #expect(estimator.retransmissionTimeout == .milliseconds(340))
        // If the sample equals SRTT, only RTTVAR drops to 3/4: 43.125ms, RTO = 110 + 172.5 = 282.5ms
        estimator.recordSample(.milliseconds(110))
        #expect(estimator.roundTripTimeVariation == .microseconds(43_125))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(110))
        #expect(estimator.retransmissionTimeout == .microseconds(282_500))
    }

    @Test("A sample below SRTT also uses |SRTT − R'| to update RTTVAR")
    func sampleBelowSmoothedValue() {
        var estimator = RTOEstimator()
        estimator.recordSample(.seconds(1))
        #expect(estimator.retransmissionTimeout == .seconds(3))
        // RTTVAR = (3·500 + 600)/4 = 525ms, SRTT = (7·1000 + 400)/8 = 925ms, RTO = 925 + 2100 = 3025ms
        estimator.recordSample(.milliseconds(400))
        #expect(estimator.roundTripTimeVariation == .milliseconds(525))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(925))
        #expect(estimator.retransmissionTimeout == .milliseconds(3025))
    }

    @Test("200ms floor: raises a value just below the boundary and leaves a value just above it alone")
    func lowerBound() {
        var tiny = RTOEstimator()
        tiny.recordSample(.milliseconds(10))   // 10 + 4·5 = 30ms
        #expect(tiny.smoothedRoundTripTime == .milliseconds(10))
        #expect(tiny.retransmissionTimeout == .milliseconds(200))

        var below = RTOEstimator()
        below.recordSample(.nanoseconds(66_666_666))   // 3R = 199_999_998ns
        #expect(below.retransmissionTimeout == .milliseconds(200))

        var above = RTOEstimator()
        above.recordSample(.nanoseconds(66_666_667))   // 3R = 200_000_001ns
        #expect(above.retransmissionTimeout == .nanoseconds(200_000_001))
    }

    @Test("120-second cap: lowers a value just above the boundary and leaves a value just below it alone")
    func upperBound() {
        var exact = RTOEstimator()
        exact.recordSample(.seconds(40))   // 3R = 120 seconds
        #expect(exact.retransmissionTimeout == .seconds(120))

        var below = RTOEstimator()
        below.recordSample(.nanoseconds(39_999_999_999))
        #expect(below.retransmissionTimeout == .nanoseconds(119_999_999_997))

        var above = RTOEstimator()
        above.recordSample(.nanoseconds(40_000_000_001))
        #expect(above.retransmissionTimeout == .seconds(120))
    }

    @Test("Treats zero and negative samples as 0")
    func zeroAndNegativeSamples() {
        var zero = RTOEstimator()
        zero.recordSample(.zero)
        #expect(zero.smoothedRoundTripTime == .zero)
        #expect(zero.roundTripTimeVariation == .zero)
        #expect(zero.retransmissionTimeout == .milliseconds(200))

        var negative = RTOEstimator()
        negative.recordSample(.milliseconds(-5))
        #expect(negative.smoothedRoundTripTime == .zero)
        #expect(negative.retransmissionTimeout == .milliseconds(200))
    }

    @Test("Caps an extremely large sample so that RTO reaches the cap without overflowing")
    func hugeSamples() {
        var estimator = RTOEstimator()
        estimator.recordSample(.seconds(Int64.max))
        #expect(estimator.smoothedRoundTripTime == .seconds(120))
        #expect(estimator.retransmissionTimeout == .seconds(120))
        estimator.recordSample(.seconds(Int64.max))
        estimator.recordSample(.seconds(Int64.min))
        #expect(estimator.retransmissionTimeout <= .seconds(120))
        #expect(estimator.retransmissionTimeout >= .milliseconds(200))
    }

    @Test("Doubles RTO on every expiration and caps it at 120 seconds (5.5)")
    func backOff() {
        var estimator = RTOEstimator()
        var seen: [Duration] = []
        for _ in 0..<9 {
            estimator.retransmissionTimerExpired()
            seen.append(estimator.retransmissionTimeout)
        }
        #expect(seen == [2, 4, 8, 16, 32, 64, 120, 120, 120].map { Duration.seconds($0) })
    }

    @Test("backoff leaves SRTT and RTTVAR alone, and a new sample restores formula-based RTO (5.5, note below 5.7)")
    func backOffReleasedByNewSample() {
        var estimator = RTOEstimator()
        estimator.recordSample(.milliseconds(100))   // RTO 300ms
        estimator.retransmissionTimerExpired()
        estimator.retransmissionTimerExpired()
        estimator.retransmissionTimerExpired()
        #expect(estimator.retransmissionTimeout == .milliseconds(2400))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(100))
        #expect(estimator.roundTripTimeVariation == .milliseconds(50))
        // If the same sample arrives again, RTTVAR = 37.5ms, SRTT = 100ms, RTO = 250ms
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.retransmissionTimeout == .milliseconds(250))
    }

    @Test("The first sample uses formula 2.2 even if RTO backed off without samples")
    func firstSampleAfterBackOff() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired()
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
    }

    @Test("If the SYN timer has expired, raises RTO to 3 seconds after establishment (5.7)")
    func synRetransmissionRaisesToThreeSeconds() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired(forSYN: true)   // 1 → 2 seconds
        #expect(estimator.retransmissionTimeout == .seconds(2))
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(3))
    }

    @Test("5.7 does not lower an already larger RTO")
    func synRuleNeverLowers() {
        var estimator = RTOEstimator()
        for _ in 0..<3 { estimator.retransmissionTimerExpired(forSYN: true) }   // 8 seconds
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(8))
    }

    @Test("RTO stays the same after establishment if SYN was not retransmitted")
    func noSynExpiry() {
        var estimator = RTOEstimator()
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(1))
    }

    @Test("The 3 seconds raised by SYN expiration apply once, and a later sample restores formula-based RTO")
    func synRuleAppliesOnce() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired(forSYN: true)
        estimator.handshakeCompleted()
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
    }

    @Test("Data timer expiration does not trigger 5.7")
    func dataExpiryDoesNotArmSynRule() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired()
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(2))
    }
}
