import CryptoKit
import SwiftailBase

/// A 32-byte Curve25519 public key. Used to identify a peer.
///
/// Public keys are public, so ordinary equality via `==` and hashing suffice.
public struct PublicKey: Hashable, Sendable, CustomStringConvertible {
    /// The 32 key bytes.
    public let rawValue: [UInt8]

    /// Returns `nil` unless the input is 32 bytes long.
    public init?(rawValue: some Collection<UInt8>) {
        let bytes = Array(rawValue)
        guard bytes.count == 32 else { return nil }
        self.rawValue = bytes
    }

    /// A short representation for logs. The first 8 base-16 digits + "…".
    public var description: String { String(rawValue.hex.prefix(8)) + "…" }

    /// A CryptoKit public key is always 32 bytes, so no length check is needed.
    init(_ key: Curve25519.KeyAgreement.PublicKey) {
        rawValue = Array(key.rawRepresentation)
    }
}
