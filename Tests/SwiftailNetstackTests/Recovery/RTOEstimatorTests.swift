import Testing

@testable import SwiftailNetstack

/// 재전송 타이머의 RTO 추정(RFC 6298). 계약 `docs/contracts/SwiftailNetstack.md` 동작 R1~R3과 시험 7.
/// 기대값은 RFC 6298 2.2·2.3의 식을 손으로 계산한 것이다(G = 0, K = 4, α = 1/8, β = 1/4).
@Suite("RTO 추정기")
struct RTOEstimatorTests {
    @Test("측정 전의 RTO는 1초다(2.1)")
    func initialTimeout() {
        let estimator = RTOEstimator()
        #expect(estimator.retransmissionTimeout == .seconds(1))
        #expect(estimator.smoothedRoundTripTime == nil)
        #expect(estimator.roundTripTimeVariation == .zero)
    }

    @Test("첫 표본 R: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4·RTTVAR(2.2)")
    func firstSample() {
        var estimator = RTOEstimator()
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(100))
        #expect(estimator.roundTripTimeVariation == .milliseconds(50))
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
    }

    @Test("다음 표본 R': RTTVAR를 먼저, 낡은 SRTT로 고치고 SRTT를 고친다(2.3)")
    func laterSamples() {
        var estimator = RTOEstimator()
        estimator.recordSample(.milliseconds(100))
        // RTTVAR = (3·50 + |100 − 180|)/4 = 57.5ms, SRTT = (7·100 + 180)/8 = 110ms, RTO = 110 + 4·57.5 = 340ms
        estimator.recordSample(.milliseconds(180))
        #expect(estimator.roundTripTimeVariation == .microseconds(57_500))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(110))
        #expect(estimator.retransmissionTimeout == .milliseconds(340))
        // 표본이 SRTT와 같으면 RTTVAR만 3/4로 준다: 43.125ms, RTO = 110 + 172.5 = 282.5ms
        estimator.recordSample(.milliseconds(110))
        #expect(estimator.roundTripTimeVariation == .microseconds(43_125))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(110))
        #expect(estimator.retransmissionTimeout == .microseconds(282_500))
    }

    @Test("SRTT보다 작은 표본도 |SRTT − R'|로 RTTVAR를 고친다")
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

    @Test("하한 200ms: 경계 바로 아래는 올리고 바로 위는 그대로 둔다")
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

    @Test("상한 120초: 경계 바로 위는 내리고 바로 아래는 그대로 둔다")
    func upperBound() {
        var exact = RTOEstimator()
        exact.recordSample(.seconds(40))   // 3R = 120초
        #expect(exact.retransmissionTimeout == .seconds(120))

        var below = RTOEstimator()
        below.recordSample(.nanoseconds(39_999_999_999))
        #expect(below.retransmissionTimeout == .nanoseconds(119_999_999_997))

        var above = RTOEstimator()
        above.recordSample(.nanoseconds(40_000_000_001))
        #expect(above.retransmissionTimeout == .seconds(120))
    }

    @Test("0과 음수 표본은 0으로 본다")
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

    @Test("터무니없이 큰 표본은 상한으로 묶여 넘침 없이 상한 RTO가 된다")
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

    @Test("만료마다 RTO를 두 배로 하고 120초에서 멈춘다(5.5)")
    func backOff() {
        var estimator = RTOEstimator()
        var seen: [Duration] = []
        for _ in 0..<9 {
            estimator.retransmissionTimerExpired()
            seen.append(estimator.retransmissionTimeout)
        }
        #expect(seen == [2, 4, 8, 16, 32, 64, 120, 120, 120].map { Duration.seconds($0) })
    }

    @Test("backoff는 SRTT·RTTVAR를 건드리지 않고, 새 표본이 오면 식으로 되돌린다(5.5, 5.7 아래 주석)")
    func backOffReleasedByNewSample() {
        var estimator = RTOEstimator()
        estimator.recordSample(.milliseconds(100))   // RTO 300ms
        estimator.retransmissionTimerExpired()
        estimator.retransmissionTimerExpired()
        estimator.retransmissionTimerExpired()
        #expect(estimator.retransmissionTimeout == .milliseconds(2400))
        #expect(estimator.smoothedRoundTripTime == .milliseconds(100))
        #expect(estimator.roundTripTimeVariation == .milliseconds(50))
        // 같은 표본이 다시 오면 RTTVAR = 37.5ms, SRTT = 100ms, RTO = 250ms
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.retransmissionTimeout == .milliseconds(250))
    }

    @Test("표본 없이 backoff한 RTO도 첫 표본이 오면 2.2의 식으로 정해진다")
    func firstSampleAfterBackOff() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired()
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
    }

    @Test("SYN의 타이머가 만료된 적이 있으면 맺어진 뒤 RTO를 3초로 올린다(5.7)")
    func synRetransmissionRaisesToThreeSeconds() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired(forSYN: true)   // 1 → 2초
        #expect(estimator.retransmissionTimeout == .seconds(2))
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(3))
    }

    @Test("5.7은 이미 큰 RTO를 낮추지 않는다")
    func synRuleNeverLowers() {
        var estimator = RTOEstimator()
        for _ in 0..<3 { estimator.retransmissionTimerExpired(forSYN: true) }   // 8초
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(8))
    }

    @Test("SYN이 재전송되지 않았으면 맺어져도 RTO는 그대로다")
    func noSynExpiry() {
        var estimator = RTOEstimator()
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(1))
    }

    @Test("SYN 만료로 올린 3초는 한 번만 적용되고, 이후 표본이 RTO를 식으로 되돌린다")
    func synRuleAppliesOnce() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired(forSYN: true)
        estimator.handshakeCompleted()
        estimator.recordSample(.milliseconds(100))
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .milliseconds(300))
    }

    @Test("데이터 타이머의 만료는 5.7을 켜지 않는다")
    func dataExpiryDoesNotArmSynRule() {
        var estimator = RTOEstimator()
        estimator.retransmissionTimerExpired()
        estimator.handshakeCompleted()
        #expect(estimator.retransmissionTimeout == .seconds(2))
    }
}
