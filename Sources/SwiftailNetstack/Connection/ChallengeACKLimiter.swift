/// challenge ACK의 속도 제한(RFC 5961 7, 계약 동작 X4).
///
/// 5초 창 안에서 10개까지만 허락한다. RFC 5961 7이 말하듯 타이머 없이 창의 시작 시각과 세는 값만 둔다.
/// 연결은 challenge ACK(RST·SYN 검사)와, 데이터 없는 창 밖 세그먼트·범위 밖 ACK에 답하는 ACK(동작 X2, X3)에 이것을 쓴다.
/// 피어가 틀린 세그먼트를 쏟아부어도 이 연결이 내는 답은 5초에 10개를 넘지 않는다(ACK 고리를 막는다).
struct ChallengeACKLimiter: Sendable, Equatable {
    /// 창의 길이(RFC 5961 7의 예).
    static let interval = Duration.seconds(5)
    /// 창 하나에서 보낼 수 있는 수(RFC 5961 7의 예).
    static let limit = 10

    private var windowStart: ContinuousClock.Instant?
    private var sentInWindow = 0

    /// `now`에 하나를 보내도 되면 세고 `true`.
    mutating func permit(at now: ContinuousClock.Instant) -> Bool {
        if let start = windowStart, now - start < Self.interval {
            guard sentInWindow < Self.limit else { return false }
        } else {
            windowStart = now
            sentInWindow = 0
        }
        sentInWindow += 1
        return true
    }
}
