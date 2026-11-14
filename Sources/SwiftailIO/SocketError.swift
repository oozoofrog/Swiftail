/// `NetworkSocket`의 실패. 메시지에는 Network 프레임워크의 오류 설명만 담기고, 보낸·받은 바이트나 비밀은 들어가지 않는다.
///
/// 보내기 실패는 따로 내지 않는다(`send`·`write` 모두). 연결이 실패 상태가 되고, 그 사실은 다음 `receive()`가
/// `readFailed`로 알린다.
package enum SocketError: Error, Sendable, Equatable {
    /// 연결을 만들지 못했거나 연결하는 동안 취소되었다.
    case connectFailed(String)
    /// 읽는 동안 실패했거나 취소되었다. 상대가 정상적으로 닫은 것은 오류가 아니다(`receive()`가 nil).
    case readFailed(String)
}
