import CryptoKit
import SwiftailBase

/// A node's identity: the machine key identifying the device, the node key for WireGuard, and the tailnet lock key (NL key).
///
/// The machine key authenticates the Noise connection to the control server and stays the same as long as the device stays the same. The node key
/// is committed after successful registration and changes on expiration or when the user starts a new interactive login. The NL key stays the same once created. When the node rotates its node key,
/// it extends the old signature chain with this key. Losing it prevents communication with peers that enforce the lock until a signing device signs again.
/// Persist all three to start as the same node after a restart (`NodeIdentityStore`).
///
/// Holds private keys, so exposes only public keys to `description` and `dump`.
/// `docs/protocol-notes/control-map.md` 4.1, `docs/protocol-notes/tailnet-lock.md` 4.6 1.
public struct NodeIdentity: Sendable {
    public var machineKey: Curve25519.KeyAgreement.PrivateKey
    /// The registered node key, or nil before any registration.
    public var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    /// The tailnet lock key (NL key). Includes its public key in the registration request's `NLKey` and uses this key when the server requests re-signing.
    public var lockKey: Curve25519.Signing.PrivateKey

    /// Creates a fresh machine key and NL key and leaves the node key absent.
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

    /// The public key of the NL key.
    public var lockPublicKey: NLPublicKey { PrefixedKey(lockKey.publicKey) }
}

extension NodeIdentity: CustomStringConvertible, CustomReflectable {
    /// Shows only public keys so logging the identity value as is does not leak private keys.
    public var description: String {
        "NodeIdentity(machine: \(machinePublicKey), node: \(nodePublicKey?.description ?? "none"), lock: \(lockPublicKey))"
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "machinePublicKey": machinePublicKey,
            "nodePublicKey": nodePublicKey as Any,
            "lockPublicKey": lockPublicKey,
        ])
    }
}
