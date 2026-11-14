import SwiftailControl

/// `TailnetNode`의 실패. `init`이 설정 오류를, `run()`이 다시 켜도 소용없는 실패를 던진다.
///
/// 일시적인 실패(연결 끊김, 서버의 일시 오류, 시간 초과)는 던지지 않는다. 노드가 안에서 물러났다가 다시 시도한다.
/// 메시지에는 키·인증 키·파일 경로·기술자 번호를 넣지 않는다. 앱은 사용자 문구를 종류로 고르고, 연관 문자열은 진단에만 쓴다.
public enum NodeError: Error, Sendable {
    /// 제어 클라이언트가 끝낸 실패: 인증 키를 실은 등록 거절(`authKeyRejected`), 인증 키 없는 등록 거절
    /// (`registrationRejected`), 새 키로도 node 키 만료(`nodeKeyExpired`), tailnet lock(`tailnetLockEnabled`),
    /// 신원 파일(`storage`).
    case control(ControlError)
    /// 설정이 잘못되었다: 상태 디렉터리, 제어 서버 URL, 호스트 이름, utun 기술자, MTU. `run()`을 두 번 부른 것도 여기다.
    case invalidConfiguration(String)
    /// UDP 소켓을 열거나 묶지 못했다. 메시지에는 errno 이름만 담는다(예: `EADDRINUSE`).
    case udpUnavailable(String)
    /// 같은 프로세스의 다른 노드가 이 상태 디렉터리로 돌고 있다.
    case stateDirectoryInUse
    /// 터널 장치를 더 읽을 수 없다(utun 읽기 오류나 끝). 메시지에는 errno 이름(끝은 `EOF`)만 담는다.
    case tunnelDeviceClosed(String)
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
