import Foundation

/// 관리 API가 만든 1회용 인증 키(계약 `docs/contracts/SwiftailPairing.md` 4절 K1).
///
/// `key`는 tailnet에 노드 하나를 들이는 비밀이므로 `description`과 `dump`에서 가린다. 쓰지 않은 키는 `expires`까지
/// 살아 있다(K8).
public struct IssuedAuthKey: Sendable {
    /// 인증 키(`tskey-auth-…`). 노드의 `NodeConfiguration.authKey`에 넣는다.
    public let key: String
    /// 이 시각이 지나면 키로 들어올 수 없다.
    public let expires: Date
}

extension IssuedAuthKey: CustomStringConvertible, CustomReflectable {
    /// 키를 가린다.
    public var description: String {
        "IssuedAuthKey(key: <가림>, expires: \(expires))"
    }

    /// `dump`는 `description`을 거치지 않으므로 여기서도 키를 가린다.
    public var customMirror: Mirror {
        Mirror(self, children: ["key": "<가림>", "expires": expires])
    }
}
