import CryptoKit
import SwiftailBase

/// 노드의 신원: 기기를 가리키는 machine 키, WireGuard에 쓰는 node 키, tailnet lock 키(NL 키).
///
/// machine 키는 제어 서버와의 Noise 연결을 인증하고 기기가 바뀌지 않는 한 그대로다. node 키는 등록을 마쳐야
/// 확정되고, 만료되거나 대화형 로그인을 새로 하면 바뀐다. NL 키는 한 번 만들면 바꾸지 않는다: 이 노드가 node 키를 바꿀 때
/// 옛 서명 위에 이 키로 다시 서명하므로, 잃으면 서명 기기가 다시 서명할 때까지 lock을 지키는 피어와 통신하지 못한다.
/// 다시 시작해도 같은 노드로 뜨려면 셋 다 저장해야 한다(`NodeIdentityStore`).
///
/// 개인 키를 담으므로 `description`과 `dump`에는 공개 키만 드러낸다.
/// `docs/protocol-notes/control-map.md` 4.1, `docs/protocol-notes/tailnet-lock.md` 4.6 1.
public struct NodeIdentity: Sendable {
    public var machineKey: Curve25519.KeyAgreement.PrivateKey
    /// 등록을 마친 node 키. 아직 등록한 적이 없으면 nil.
    public var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    /// tailnet lock 키(NL 키). 공개 키를 등록 요청의 `NLKey`에 싣고, 서버가 재서명을 요청하면 이 키로 서명한다.
    public var lockKey: Curve25519.Signing.PrivateKey

    /// 새 machine 키와 NL 키를 만들고 node 키는 비워 둔다.
    public init() {
        self.init(machineKey: .init(), nodeKey: nil)
    }

    init(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        nodeKey: Curve25519.KeyAgreement.PrivateKey?,
        lockKey: Curve25519.Signing.PrivateKey = .init()
    ) {
        self.machineKey = machineKey
        self.nodeKey = nodeKey
        self.lockKey = lockKey
    }

    public var machinePublicKey: MachinePublicKey { PrefixedKey(machineKey.publicKey) }

    public var nodePublicKey: NodePublicKey? { nodeKey.map { PrefixedKey($0.publicKey) } }

    /// NL 키의 공개 키.
    public var lockPublicKey: NLPublicKey { PrefixedKey(lockKey.publicKey) }
}

extension NodeIdentity: CustomStringConvertible, CustomReflectable {
    /// 공개 키만 보인다. 신원 값을 그대로 로그에 찍어도 개인 키가 새지 않게 한다.
    public var description: String {
        "NodeIdentity(machine: \(machinePublicKey), node: \(nodePublicKey?.description ?? "없음"), lock: \(lockPublicKey))"
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "machinePublicKey": machinePublicKey,
            "nodePublicKey": nodePublicKey as Any,
            "lockPublicKey": lockPublicKey,
        ])
    }
}
