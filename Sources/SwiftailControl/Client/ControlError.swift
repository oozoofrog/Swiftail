/// 제어 클라이언트의 실패.
///
/// `ControlClient.run()`은 다시 시도하면 나아질 수 있는 실패(`connection`, `http`)를 안에서 물러났다가
/// 다시 시도하고, 다시 시도해도 소용없는 실패만 던진다. 메시지에는 키·인증 키·파일 경로를 넣지 않는다.
///
/// `docs/contracts/SwiftailControl.md` 단위 4, `docs/protocol-notes/control-map.md` 4.4.
public enum ControlError: Error, Sendable {
    /// 설정이 잘못되었다(서버 URL, 호스트 이름).
    case invalidConfiguration(String)
    /// 신원 파일을 읽거나 쓰지 못했다.
    case storage(String)
    /// 연결·전송 계층의 실패. 다시 시도한다.
    case connection(String)
    /// 200이 아닌 응답. 429와 `Retry-After`가 붙은 503의 대기는 안에서 처리한다.
    case http(status: Int)
    /// 서버가 등록을 거절했다(`RegisterResponse.Error`).
    case registrationRejected(String)
    /// 새 node 키로 다시 등록해도 만료라고 한다.
    case nodeKeyExpired
    /// tailnet lock이 켜진 tailnet이다. 지원하지 않는다.
    case tailnetLockEnabled
}

extension ControlError {
    /// 물러났다가 다시 시도할 실패인가.
    var isRetryable: Bool {
        switch self {
        case .connection, .http: true
        case .invalidConfiguration, .storage, .registrationRejected, .nodeKeyExpired, .tailnetLockEnabled: false
        }
    }
}
