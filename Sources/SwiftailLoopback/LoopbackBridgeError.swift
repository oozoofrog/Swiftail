/// `LoopbackBridge.forward(_:toLoopbackPort:)`가 잇지 못한 까닭. 어느 경우든 tailnet 연결은 RST로 끊긴 뒤다.
///
/// 잇기 시작한 뒤 한쪽이 끊기거나 실패한 것(`reset`, `timedOut`, `peerRemoved`, 루프백의 실패, 노드가 멈춤)은 오류가
/// 아니다. 다리는 두 연결을 정리하고 돌아온다. 메시지에는 주소·이름을 담지 않는다(계약 동작 K).
public enum LoopbackBridgeError: Error, Sendable, Equatable {
    /// 상대 주소의 신원을 netmap에서 찾지 못했다.
    case unknownPeer
    /// 다리가 잇고 있는 연결이 상한(256)에 닿았다.
    case limitReached
    /// 루프백 포트에 걸지 못했다(듣는 쪽이 없다, 시간 초과, 토큰을 표에 적거나 보내지 못했다).
    case loopbackUnavailable(String)
    /// 부른 Task가 취소되었다.
    case cancelled
}
