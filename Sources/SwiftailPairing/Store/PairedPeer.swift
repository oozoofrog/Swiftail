import Foundation
import Swiftail

/// 여는 쪽의 짝 하나(계약 동작 S1).
///
/// 열쇠는 `peer.stableID`다. 뒤의 연결이 짝의 것인지는 `StableID`로만 가린다. 이름들은 표시용이고 짝을 맺을 때의 사본이라
/// 그 뒤에 바뀐 이름을 따라가지 않는다. 노드가 지워졌다 다시 등록되면 `StableID`가 바뀌어 짝이 아니게 된다.
public struct PairedPeer: Sendable, Equatable {
    /// 짝을 맺을 때의 신원.
    public let peer: PeerIdentity
    /// 상대가 스스로 밝힌 기기 이름.
    public let deviceName: String
    /// 짝이 된 때.
    public let pairedAt: Date
}
