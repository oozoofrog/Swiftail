/// `WireGuardDevice`가 데이터그램·IP 패킷을 거절한 이유.
///
/// wireguard-go는 이런 입력을 조용히 버린다. 여기서는 호출하는 쪽이 지표나 로그를 남길 수 있게
/// 이유를 돌려준다. 어느 경우든 상대에게 보낼 것은 없다.
///
/// `send`·`receive`가 던지거나, 인증된 transport 안의 IP 패킷을 버릴 때
/// `WireGuardDevice.Output.rejectedIPPacket`에 실린다.
public enum WireGuardError: Error, Sendable, Equatable {
    /// 길이·type·예약 바이트가 규격과 다르다. 복호화한 IP 패킷의 머리가 틀린 경우도 포함한다.
    case malformed
    /// 등록되지 않은 피어, 또는 모르는 receiver index.
    case unknownPeer
    /// mac1이나 AEAD 태그가 맞지 않는다.
    case authenticationFailed
    /// 핸드셰이크 timestamp·flood 검사, 이미 소비한 response, 또는 전송 카운터 재사용.
    case replayed
    /// 쓸 수 있는 keypair가 없다(만료 포함).
    case noSession
    /// 복호화한 IP 패킷의 출발 주소가 피어의 AllowedIPs 밖이다. `rejectedIPPacket`으로만 나온다.
    case disallowedSource
    /// 보낼 IP 패킷이 한 transport 메시지에 담을 수 있는 크기를 넘는다.
    case packetTooLarge
}
