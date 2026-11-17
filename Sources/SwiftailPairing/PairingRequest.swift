import Swiftail

/// 여는 쪽 앱에게 묻는 승인 하나(`PairingHost`의 `decide`). 계약 동작 P5.
///
/// 상대는 제안의 비밀을 안다는 것을 이미 보였다. 그래도 링크를 먼저 얻은 다른 기기일 수 있으므로, 승인 화면은 확인 숫자를
/// 보여 주고 사용자가 들어오는 기기 화면의 숫자와 같을 때 승인하게 한다.
public struct PairingRequest: Sendable {
    /// 연결의 상대. WireGuard가 인증한 주소로 netmap에서 찾은 신원이다.
    public let peer: PeerIdentity
    /// 상대가 **스스로 밝힌** 기기 이름. 확인된 값이 아니다. 같은 OAuth 클라이언트의 키로 들어온 노드들은 로그인 이름도
    /// 같으므로, 이름만으로 기기를 가리지 않는다.
    public let deviceName: String
    /// 확인 숫자 6자리. 들어오는 쪽의 `awaitingApproval`이 받는 값과 같다.
    public let confirmationCode: String
}
