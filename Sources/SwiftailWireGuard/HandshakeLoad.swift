/// 받는 쪽이 부하 상태인지 판정한다. 부하 상태에서만 핸드셰이크 메시지에 mac2를 요구한다.
///
/// node 공개 키는 비밀이 아니므로 mac1이 맞는 메시지는 누구나 만들 수 있고, 받는 쪽은 그때마다 X25519를 계산한다.
/// wireguard-go는 핸드셰이크 큐가 문턱만큼 밀렸는지로 부하를 본다(`IsUnderLoad`). 이 장치에는 큐가 없고 메시지를
/// 받은 자리에서 처리하므로, 대신 "최근 `window` 안에 mac1을 통과한 핸드셰이크 메시지가 `threshold`개에 이르렀는가"로
/// 본다. 한 번 감지하면 Go와 같이 `underLoadAfterTime`(1초) 동안 부하 상태로 머문다.
///
/// 문턱의 근거는 `docs/contracts/SwiftailWireGuard.md` "cookie reply 보내기"에 적는다.
/// 출처: wireguard-go `device/device.go` `IsUnderLoad`, `docs/protocol-notes/wireguard.md` "부하 상태 판정".
struct HandshakeLoad {
    /// 이 수의 메시지가 `window` 안에 오면 부하 상태다.
    static let threshold = 128
    /// 문턱을 세는 시간 창.
    static let window: Duration = .seconds(1)

    /// 마지막 `threshold`개 메시지의 시각. 가득 차면 `oldest`가 가장 오래된 칸이고 거기부터 덮어쓴다.
    private var arrivals: [ContinuousClock.Instant] = []
    private var oldest = 0
    /// 이 시각 전까지는 부하 상태다. 시험은 이 값을 직접 정해 부하 상태를 만든다.
    var underLoadUntil: ContinuousClock.Instant?

    /// mac1을 통과한 핸드셰이크 메시지 하나를 세고, 지금 부하 상태인지 돌려준다.
    ///
    /// 이 메시지로 `window`보다 짧은 간격 안에 `threshold`개가 모이면 부하를 감지하고 `now + 1초`까지 부하 상태로
    /// 둔다. 아니면 이전에 감지한 기간이 아직 남았는지 본다(Go와 같이 그 시각 정각에는 끝난다).
    mutating func record(at now: ContinuousClock.Instant) -> Bool {
        if arrivals.count < Self.threshold {
            arrivals.append(now)
        } else {
            arrivals[oldest] = now
            oldest = (oldest + 1) % Self.threshold
        }
        if arrivals.count == Self.threshold, now - arrivals[oldest] < Self.window {
            underLoadUntil = now + Constants.underLoadAfterTime
            return true
        }
        return underLoadUntil.map { now < $0 } ?? false
    }
}
