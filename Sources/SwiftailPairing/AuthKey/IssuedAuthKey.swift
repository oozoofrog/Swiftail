import Foundation

/// A single-use auth key from the admin API (contract `docs/contracts/SwiftailPairing.md` §4 K1).
///
/// `key` is a secret that admits one node to the tailnet, so `description` and `dump` redact it. An unused key stays valid until `expires`
/// (K8).
public struct IssuedAuthKey: Sendable {
    /// The auth key (`tskey-auth-…`). Set it on the node's `NodeConfiguration.authKey`.
    public let key: String
    /// The time after which the key cannot be used to join.
    public let expires: Date
}

extension IssuedAuthKey: CustomStringConvertible, CustomReflectable {
    /// Redacts the key.
    public var description: String {
        "IssuedAuthKey(key: <redacted>, expires: \(expires))"
    }

    /// `dump` bypasses `description`, so redact the key here too.
    public var customMirror: Mirror {
        Mirror(self, children: ["key": "<redacted>", "expires": expires])
    }
}
