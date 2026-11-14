/// DERP 연결이 실패하거나 요청을 거절한 이유.
///
/// 서버가 보낸 바이트에서 비롯된 실패(`malformed` ~ `tooManyPendingReplies`)는 연결을 끝낸다. 그 뒤의 호출은
/// `closed`다. `packetTooLarge`와 `notReady`는 부르는 쪽의 잘못이므로 연결을 끝내지 않는다.
///
/// `docs/protocol-notes/derp-stun.md` 3장, 4.2~4.3절.
public enum DERPError: Error, Sendable, Equatable {
    /// 프레임·응답 머리·JSON이 규격과 다르다. 생성 인자(`host`, nonce)가 잘못된 경우도 여기다.
    case malformed
    /// 업그레이드 응답의 상태가 101이 아니다.
    case upgradeRejected(status: Int)
    /// ServerKey 검증에 실패했거나 ServerInfo를 열지 못했다.
    case handshakeFailed
    /// 받은 프레임 본문이 한도를 넘는다.
    case frameTooLarge
    /// 답해야 할 Ping이 한도를 넘게 쌓였다. 서버가 읽지 않거나 Ping을 퍼붓는 것이다.
    case tooManyPendingReplies
    /// 보낼 패킷이 `MaxPacketSize`(65,536바이트)를 넘는다.
    case packetTooLarge
    /// 핸드셰이크가 끝나기 전에 `send`를 불렀다.
    case notReady
    /// 이미 실패한 연결에 대한 호출이다.
    case closed
}
