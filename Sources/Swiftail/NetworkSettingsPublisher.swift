import SwiftailEngine

/// A value type that selects tunnel settings to publish to the app. Uses the first adopter's rules as written
/// (`docs/contracts/SwiftailTunnel.md` behavior E).
///
/// - Skips nil computed settings (no local addresses). Also skips empty settings while waiting for login or approval.
/// - Skips a value identical to the last published value, including list order. Prevents the loop of applying settings
///   → utun link change → applying again. Publishes even when only DNS changes.
///
/// The stream buffer (`.bufferingNewest(1)`) replaces unread settings with newer ones (behavior E 3).
struct NetworkSettingsPublisher: Sendable, Equatable {
    /// The last published settings. Becomes `NodeStatus.networkSettings`.
    private(set) var published: TunnelNetworkSettings?

    /// Decides whether to publish newly computed settings. If they should be published, returns them and remembers the value.
    mutating func publish(_ settings: TunnelNetworkSettings?) -> TunnelNetworkSettings? {
        guard let settings, settings != published else { return nil }
        published = settings
        return settings
    }
}
