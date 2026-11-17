import Foundation

/// 들어오는 쪽이 짝이 된 여는 쪽(`PairingJoiner.pair`의 결과). 보관은 앱이 한다(`Codable`).
///
/// 프로세스 안 노드로 들어온 앱은 뒤의 연결에서 `whoIs(상대 주소)?.stableID`를 `stableID`와 견줘 상대가 이 짝인지 본다.
/// OS 소켓으로 들어온 앱은 그럴 길이 없어 `host`의 이름 풀이(MagicDNS)와 WireGuard를 믿는다.
public struct PairedHost: Sendable, Equatable, Codable {
    /// 여는 노드의 MagicDNS FQDN(제안의 `host`).
    public let host: String
    /// 여는 노드의 `StableID`. 여는 쪽이 `decision`에 실어 보냈고 제안의 비밀로 인증됐다.
    public let stableID: String
    /// 여는 쪽의 표시 이름. 표시용이다.
    public let name: String
    /// 짝이 된 때.
    public let pairedAt: Date
}
