/// 제어 전송 계층(업그레이드, Noise 핸드셰이크, 레코드, early payload)이 입력을 거절한 이유.
///
/// 어느 경우든 연결은 더 쓸 수 없다. 오류를 던진 상태 기계는 그 뒤의 호출에 `closed`를 던진다.
/// 오류에는 키 재료나 서버가 보낸 문자열을 싣지 않는다.
///
/// `docs/protocol-notes/control-transport.md` 3장, 4.4·4.5·4.6절.
public enum ControlTransportError: Error, Sendable, Equatable {
    /// 길이·type·형식이 규격과 다르다.
    case malformed
    /// 업그레이드 응답의 상태가 101이 아니다.
    case upgradeRejected(status: Int)
    /// 핸드셰이크 실패: response 복호화 실패, 서버의 error 메시지, 0 공유 비밀.
    case handshakeFailed
    /// 전송 단계 레코드의 복호화 실패. 연결을 버려야 한다.
    case authenticationFailed
    /// 레코드·early payload·업그레이드 응답 머리가 한도를 넘는다.
    case messageTooLarge
    /// 실패했거나 이미 끝난 상태 기계를 다시 불렀다.
    case closed
}
