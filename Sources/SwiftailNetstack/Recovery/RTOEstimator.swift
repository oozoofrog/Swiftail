/// 재전송 타이머의 값(RTO)을 RTT 표본에서 추정한다(RFC 6298).
///
/// 소켓도 시계도 없다. 입력은 잰 왕복 시간(`Duration`)과 타이머 만료 사건뿐이고, 출력은 다음 타이머를 맞출 `retransmissionTimeout`이다.
/// 타이머를 켜고 끄는 때(RFC 6298 5.1~5.3, 5.6)와 만료 횟수의 한도(계약 동작 R4)는 연결이 정한다.
///
/// **Karn의 규칙(RFC 6298 3)은 연결이 지킨다.** 어느 세그먼트가 재전송됐는지는 보내는 쪽 버퍼를 쥔 연결만 안다.
/// 그래서 `recordSample(_:)`는 재전송되지 않은 세그먼트의 왕복 시간만 받는다는 전제를 두고, 재전송된 세그먼트의 표본을 버리는 판단은 부르는 쪽 몫이다.
///
/// 값은 계약 `docs/contracts/SwiftailNetstack.md` 동작 R1의 것이다: 처음 1초, 하한 200ms(RFC 6298 2.4의 SHOULD인 1초와 다르다. 총괄 확정 N4), 상한 120초(2.5는 60초 이상을 요구한다), 시계 단위 G는 0.
package struct RTOEstimator: Sendable, Equatable {
    /// 측정 전의 RTO(RFC 6298 2.1).
    package static let initialTimeout = Duration.seconds(1)
    /// RTO의 하한. RFC 6298 2.4는 1초로 올리라고 하지만(SHOULD) 200ms를 쓴다. gVisor와 같다(총괄 확정 N4).
    package static let minimumTimeout = Duration.milliseconds(200)
    /// RTO의 상한(RFC 6298 2.5는 60초 이상을 요구한다).
    package static let maximumTimeout = Duration.seconds(120)
    /// SYN의 타이머가 만료된 적이 있을 때 맺어진 뒤 RTO가 적어도 이 값이 되게 한다(RFC 6298 5.7).
    package static let timeoutAfterSYNRetransmission = Duration.seconds(3)

    /// SRTT. 첫 표본 전에는 `nil`.
    package private(set) var smoothedRoundTripTime: Duration?
    /// RTTVAR. 첫 표본 전에는 0.
    package private(set) var roundTripTimeVariation = Duration.zero
    /// 지금 타이머에 쓸 RTO. 만료마다 두 배가 되고(backoff), 표본이 오면 식으로 되돌아온다.
    package private(set) var retransmissionTimeout = RTOEstimator.initialTimeout

    private var synTimerHasExpired = false

    package init() {}

    /// 재전송되지 않은 세그먼트의 왕복 시간 `sample`로 SRTT·RTTVAR·RTO를 고친다(RFC 6298 2.2·2.3).
    ///
    /// 첫 표본 R은 `SRTT = R`, `RTTVAR = R/2`다. 그 뒤 R'은 `RTTVAR = 3/4·RTTVAR + 1/4·|SRTT − R'|`을 먼저, 낡은 SRTT로 계산하고
    /// `SRTT = 7/8·SRTT + 1/8·R'`을 그다음에 계산한다(α = 1/8, β = 1/4). RTO는 `SRTT + max(G, 4·RTTVAR)`이고 G는 0이다.
    /// 이 계산이 backoff로 키운 RTO를 되돌린다(RFC 6298 5.7 아래의 설명).
    ///
    /// 음수 표본은 0으로, 상한보다 큰 표본은 상한으로 본다. 어느 쪽도 실제 왕복이 아니고, 이렇게 묶어 두면 이어지는 `Duration` 계산이 넘치지 않는다.
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

    /// 재전송 타이머가 만료됐다. RTO를 두 배로 하고 상한에서 멈춘다(RFC 6298 5.5).
    ///
    /// - Parameter forSYN: 만료된 타이머가 SYN(또는 SYN-ACK)의 확인을 기다리던 것이면 `true`.
    ///   맺어진 뒤 `handshakeCompleted()`가 RTO를 3초로 올리도록 기억한다(RFC 6298 5.7).
    package mutating func retransmissionTimerExpired(forSYN: Bool = false) {
        retransmissionTimeout = Self.bounded(retransmissionTimeout * 2)
        if forSYN { synTimerHasExpired = true }
    }

    /// 세 방향 핸드셰이크가 끝나 데이터를 보내기 시작한다.
    /// SYN의 타이머가 만료된 적이 있고 RTO가 3초보다 작으면 3초로 올린다(RFC 6298 5.7). 이미 더 큰 값은 낮추지 않는다.
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
