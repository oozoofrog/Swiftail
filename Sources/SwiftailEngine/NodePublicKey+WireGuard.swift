import SwiftailBase
import SwiftailWireGuard

/// tailcfg의 node 공개 키와 WireGuard 장치의 피어 키는 같은 Curve25519 공개 키 32바이트다.
/// 엔진은 바깥에 node 키로 말하고 장치에는 WireGuard 키로 말하므로, 그 사이를 바꾼다.

extension PublicKey {
    init(_ key: NodePublicKey) {
        // 두 타입 모두 32바이트만 담는다.
        guard let value = PublicKey(rawValue: key.rawValue) else { preconditionFailure("node 키는 32바이트다") }
        self = value
    }
}

extension NodePublicKey {
    init(_ key: PublicKey) {
        guard let value = NodePublicKey(rawValue: key.rawValue) else { preconditionFailure("WireGuard 키는 32바이트다") }
        self = value
    }
}
