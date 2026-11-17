/// 짝 맺기와 짝 목록의 실패(`PairingHost`, `PairingJoiner`). 계약 `docs/contracts/SwiftailPairing.md` 5·6절.
///
/// 메시지에는 무엇이 잘못됐는지만 담는다. 비밀·인증 키·확인 숫자·이름·주소·경로는 담지 않는다.
public enum PairingError: Error, Sendable, Equatable {
    /// 쓸 수 없는 값이다: 노드의 장치가 `.inProcess`가 아님, 포트가 0이거나 이미 쓰는 중, 수명이 1~3600초 밖, 기기 이름이
    /// 1~64바이트의 표시할 수 있는 글이 아님.
    case invalidConfiguration(String)
    /// `openOffer`에 준 인증 키가 링크에 실을 수 있는 모양이 아니다(감싼 키 포함. 계약 동작 O2).
    case invalidAuthKey
    /// 노드에 자기 FQDN이 아직 없거나 노드의 `run()`이 끝났다.
    case notRunning
    /// 짝 목록 파일이 있지만 읽지 못했다. 빈 목록으로 덮어쓰지 않는다.
    case storeUnreadable
    /// 같은 디렉터리를 쓰는 `PairingHost`가 이 프로세스에 이미 있다.
    case storeInUse
    /// 짝 목록 파일을 쓰지 못했다.
    case storeWriteFailed
    /// 60초 안에 여는 쪽의 `challenge`를 받지 못했다(이름을 찾지 못함, 경로가 없음, 여는 쪽이 이 노드를 아직 모름).
    case unreachable
    /// OS 소켓으로 건 연결의 두 끝이 tailnet 주소가 아니다. 터널이 연결되지 않았거나 이름이 다른 곳으로 풀렸다.
    case notOnTailnet
    /// 여는 쪽이 받아 주지 않았다: 열린 제안이 없다, 만료됐다, 이미 쓰였다, 비밀이 틀렸다.
    case rejected
    /// 상대가 제안의 비밀을 안다는 것을 보이지 못했다(`accepted`나 `decision`의 HMAC이 틀림). 프로세스 안 노드로 들어올
    /// 때는 `decision`의 `StableID`가 연결 상대의 것과 다른 경우도 이것이다.
    case hostNotVerified
    /// 여는 쪽이 거절했다(사용자의 거절, 승인할 때 이 노드의 신원이 달라짐, 짝 목록이 가득 참, 저장 실패).
    case denied
    /// 승인이 기한 안에 오지 않았다.
    case timedOut
    /// 상대가 절차와 다른 바이트를 보냈거나, 결정을 보내지 않고 연결을 닫았다.
    case protocolViolation
    /// 호출한 Task가 취소되었다.
    case cancelled
}
