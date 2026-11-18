import Foundation

/// The host paired with the joiner, as returned by `PairingJoiner.pair`. The app stores it (`Codable`).
///
/// An app that joined using an in-process node compares `whoIs(peer address)?.stableID` to `stableID` on later connections to identify this paired peer.
/// An app that joined using an OS socket has no such check and relies on name resolution for `host` (MagicDNS) and WireGuard.
public struct PairedHost: Sendable, Equatable, Codable {
    /// The host node's MagicDNS FQDN (the offer's `host`).
    public let host: String
    /// The host node's `StableID`. The host sent it in `decision` and authenticated it with the offer secret.
    public let stableID: String
    /// The host's display name, for display only.
    public let name: String
    /// The time pairing succeeded.
    public let pairedAt: Date
}
