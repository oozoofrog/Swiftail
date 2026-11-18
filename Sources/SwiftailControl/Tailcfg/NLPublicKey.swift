import CryptoKit
import SwiftailBase

/// The public key of a tailnet lock key (NL key). The wire (JSON) text is `"nlpub:" + 64 hexadecimal digits`.
///
/// A node always includes its NL public key in the registration request's `NLKey`. A signing device can add it as a trusted key or
/// include it as `WrappingPubkey` in a signature for this node's node key, enabling the node to re-sign its own key after changing it.
/// `docs/protocol-notes/tailnet-lock.md` §3.8, §3.9, §4.6 item 1 (origin: tailscale.com `types/key/nl.go`, BSD-3-Clause).
public enum NLKeyKind: KeyKind { public static let prefix = "nlpub:" }

public typealias NLPublicKey = PrefixedKey<NLKeyKind>

extension PrefixedKey where Kind == NLKeyKind {
    /// Converts a CryptoKit Ed25519 public key to an NL public key.
    public init(_ key: Curve25519.Signing.PublicKey) {
        // An Ed25519 public key's raw representation is always 32 bytes. Failure would violate CryptoKit's contract.
        guard let value = Self(rawValue: key.rawRepresentation) else {
            preconditionFailure("Ed25519 public keys are 32 bytes")
        }
        self = value
    }

    /// The command-line text `"tlpub:" + 64 hexadecimal digits` (Go `NLPublic.CLIString`). The signing device's `tailscale lock sign` accepts it.
    ///
    /// Go reads both prefixes. Swiftail reads only the wire prefix `nlpub:` (`init?(_:)`) because it has no other input for NL public keys.
    public var commandLineDescription: String { "tlpub:" + rawValue.hex }
}
