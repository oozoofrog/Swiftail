import SwiftailBase
import SwiftailWireGuard

/// The tailcfg node public key and the WireGuard device's peer key are the same 32-byte Curve25519 public key.
/// The engine uses node keys externally and WireGuard keys with the device, so these conversions bridge the two.

extension PublicKey {
    init(_ key: NodePublicKey) {
        // Both types hold exactly 32 bytes.
        guard let value = PublicKey(rawValue: key.rawValue) else { preconditionFailure("The node key must be 32 bytes") }
        self = value
    }
}

extension NodePublicKey {
    init(_ key: PublicKey) {
        guard let value = NodePublicKey(rawValue: key.rawValue) else { preconditionFailure("The WireGuard key must be 32 bytes") }
        self = value
    }
}
