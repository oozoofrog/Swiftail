/// WireGuard 프로토콜 상수.
///
/// 값은 `docs/protocol-notes/wireguard.md`의 "상수와 타이머" 표를 따른다
/// (출처: wireguard-go `device/constants.go`, `device/tun.go`).
enum Constants {
    /// 이 수를 넘게 보낸 keypair는 송신 뒤 새 핸드셰이크를 시작한다. 2^60.
    static let rekeyAfterMessages: UInt64 = 1 << 60
    /// 이 값 이상의 counter는 보내지도 받지도 않는다. 2^64 − 2^13 − 1.
    static let rejectAfterMessages: UInt64 = .max - (1 << 13)
    /// 초기자 keypair가 이보다 오래되면 송신 뒤 새 핸드셰이크를 시작한다.
    static let rekeyAfterTime: Duration = .seconds(120)
    /// 핸드셰이크 메시지 송신 사이의 최소 간격이자 재시도 간격.
    static let rekeyTimeout: Duration = .seconds(5)
    /// 재시도·새 핸드셰이크 타이머에 더하는 지터의 상한(ms, 미포함).
    static let rekeyTimeoutJitterMaxMilliseconds = 334
    /// 재시도 횟수가 이 값을 넘으면 포기한다. RekeyAttemptTime(90초) / RekeyTimeout(5초).
    static let maxTimerHandshakes = 18
    /// 이보다 오래된 keypair로는 보내지도 받지도 않는다.
    static let rejectAfterTime: Duration = .seconds(180)
    /// 데이터를 받고 이 시간 동안 보낼 것이 없으면 keepalive를 보낸다.
    static let keepaliveTimeout: Duration = .seconds(10)
    /// 받은 cookie를 mac2에 쓰는 기간. 받는 쪽이 cookie를 만드는 비밀도 이 주기로 바꾼다.
    static let cookieRefreshTime: Duration = .seconds(120)
    /// 부하를 감지한 뒤 부하 상태로 머무는 시간(`UnderLoadAfterTime`).
    static let underLoadAfterTime: Duration = .seconds(1)
    /// 한 피어의 initiation을 이보다 짧은 간격으로 다시 소비하지 않는다(flood 방지).
    static let handshakeInitiationRate: Duration = .milliseconds(20)
    /// 전송 평문을 이 배수로 패딩한다.
    static let paddingMultiple = 16
    /// UDP 페이로드 상한(wireguard-go 기본 플랫폼의 `MaxSegmentSize`).
    static let maxSegmentSize = 65535
    /// 보낼 IP 패킷의 상한. 머리 16 + 태그 16 + 여유 8을 뺀다(`MaxContentSize`).
    static let maxContentSize = maxSegmentSize - 32 - 8
    /// 패딩 계산에 쓰는 MTU. TUN이 MTU를 주지 못할 때 wireguard-go가 쓰는 값(`DefaultMTU`).
    static let defaultMTU = 1420
    /// 세션이 서기 전 피어마다 쌓아 두는 IP 패킷 수. 넘치면 가장 오래된 것을 버린다(계약 값).
    static let maxStagedPackets = 64
}
