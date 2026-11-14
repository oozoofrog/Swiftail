/// 연결 하나가 쥔 타이머의 기한들.
///
/// 타이머는 시계를 갖지 않는 기한(시각)일 뿐이다. 연결은 `nextDeadline`으로 가장 이른 기한을 알리고,
/// 호출하는 쪽이 그 시각에 `advance(to:)`를 부르면 지난 기한을 하나씩 처리한다.
struct ConnectionTimers: Sendable, Equatable {
    /// 타이머의 종류. 같은 시각이면 이 순서로 처리한다: 데이터 세그먼트를 내는 타이머가 ACK보다 앞서야
    /// 미뤄 둔 ACK가 그 세그먼트에 실려 나간다(RFC 9293 3.10.7.4 일곱째의 piggyback).
    enum Kind: CaseIterable, Sendable {
        /// TIME-WAIT의 끝(계약 동작 T6, 60초).
        case timeWait
        /// `close` 뒤 FIN-WAIT-2에 머무는 한도(계약 동작 T6, 60초).
        case finWait2Linger
        /// SYN·SYN-ACK·데이터·FIN의 재전송(RFC 6298 5).
        case retransmission
        /// 0 창 탐침(RFC 9293 3.8.6.1, 계약 동작 F8).
        case zeroWindowProbe
        /// 보내는 쪽 SWS 회피의 override(RFC 9293 3.8.6.2.1, 계약 동작 F7, 200ms).
        case sillyWindowOverride
        /// keep-alive(계약 동작 T8).
        case keepalive
        /// 미뤄 둔 ACK(RFC 9293 3.8.6.3, 계약 동작 F5). "곧바로" 보낼 ACK는 기한을 지금으로 두고, 그 기한을 둔 `receive`나
        /// 응용 호출의 끝에서 나간다.
        case acknowledgment
    }

    private var deadlines: [Kind: ContinuousClock.Instant] = [:]

    subscript(kind: Kind) -> ContinuousClock.Instant? {
        get { deadlines[kind] }
        set { deadlines[kind] = newValue }
    }

    /// 가장 이른 기한과 그 종류. 같은 시각이면 `Kind`의 선언 순서가 앞선 것.
    var earliest: (kind: Kind, deadline: ContinuousClock.Instant)? {
        var result: (kind: Kind, deadline: ContinuousClock.Instant)?
        for kind in Kind.allCases {
            guard let deadline = deadlines[kind] else { continue }
            if let current = result, current.deadline <= deadline { continue }
            result = (kind, deadline)
        }
        return result
    }

    mutating func removeAll() {
        deadlines.removeAll()
    }
}
