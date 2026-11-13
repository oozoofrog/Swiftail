import CryptoKit

/// 노드의 신원: 기기를 가리키는 machine 키와 WireGuard에 쓰는 node 키.
///
/// machine 키는 제어 서버와의 Noise 연결을 인증하고 기기가 바뀌지 않는 한 그대로다. node 키는 등록을 마쳐야
/// 확정되고, 만료되거나 대화형 로그인을 새로 하면 바뀐다. 다시 시작해도 같은 노드로 뜨려면 둘 다 저장해야 한다
/// (`NodeIdentityStore`).
///
/// 개인 키를 담으므로 `description`과 `dump`에는 공개 키만 드러낸다.
/// `docs/protocol-notes/control-map.md` 4.1.
public struct NodeIdentity: Sendable {
    public var machineKey: Curve25519.KeyAgreement.PrivateKey
    /// 등록을 마친 node 키. 아직 등록한 적이 없으면 nil.
    public var nodeKey: Curve25519.KeyAgreement.PrivateKey?

    /// 새 machine 키를 만들고 node 키는 비워 둔다.
    public init() {
        machineKey = Curve25519.KeyAgreement.PrivateKey()
        nodeKey = nil
    }

    init(machineKey: Curve25519.KeyAgreement.PrivateKey, nodeKey: Curve25519.KeyAgreement.PrivateKey?) {
        self.machineKey = machineKey
        self.nodeKey = nodeKey
    }

    public var machinePublicKey: MachinePublicKey { PrefixedKey(machineKey.publicKey) }

    public var nodePublicKey: NodePublicKey? { nodeKey.map { PrefixedKey($0.publicKey) } }
}

extension NodeIdentity: CustomStringConvertible, CustomReflectable {
    /// 공개 키만 보인다. 신원 값을 그대로 로그에 찍어도 개인 키가 새지 않게 한다.
    public var description: String {
        "NodeIdentity(machine: \(machinePublicKey), node: \(nodePublicKey?.description ?? "없음"))"
    }

    public var customMirror: Mirror {
        Mirror(self, children: ["machinePublicKey": machinePublicKey, "nodePublicKey": nodePublicKey as Any])
    }
}

extension PrefixedKey {
    /// CryptoKit 공개 키를 접두사 붙은 키로 바꾼다.
    init(_ key: Curve25519.KeyAgreement.PublicKey) {
        // Curve25519 공개 키의 원시 표현은 늘 32바이트다. 실패하면 CryptoKit의 계약이 깨진 것이다.
        guard let value = Self(rawValue: key.rawRepresentation) else {
            preconditionFailure("Curve25519 공개 키는 32바이트다")
        }
        self = value
    }
}
