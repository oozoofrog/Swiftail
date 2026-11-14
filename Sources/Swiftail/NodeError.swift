import SwiftailControl

/// `TailnetNode.run()`이 던지는 실패. 다시 시도해도 소용없는 것만 던진다.
///
/// 메시지에는 키·인증 키·파일 경로를 넣지 않는다.
public enum NodeError: Error, Sendable {
    /// 제어 클라이언트가 끝낸 실패(등록 거절, 신원 파일, tailnet lock 등).
    case control(ControlError)
    /// 설정이 잘못되었다(상태 디렉터리, 제어 서버 URL, 호스트 이름). `run()`을 두 번 부른 것도 여기다.
    case invalidConfiguration(String)
    /// UDP 소켓을 열거나 묶지 못했다. 메시지에는 errno 이름만 담는다(예: `EADDRINUSE`).
    case udpUnavailable(String)
}

extension NodeError {
    /// 제어 클라이언트의 실패를 노드의 실패로 옮긴다. 설정 오류는 설정 오류로 둔다.
    init(_ error: ControlError) {
        if case let .invalidConfiguration(message) = error {
            self = .invalidConfiguration(message)
        } else {
            self = .control(error)
        }
    }
}
