import SwiftailBase

/// The path to a peer. Equivalent to `CurAddr` in Go's `ipnstate.PeerStatus` (last line of notes 6.3 and notes 7.1).
public enum PeerPath: Sendable, Equatable {
    /// Sends only to a direct UDP address while its trust period is active.
    case direct(IPEndpoint)
    /// Uses DERP. This includes sending over DERP and to a direct address whose trust has expired (`bestAddr`).
    /// - Parameter derpRegion: The peer's home DERP region, or 0 if unknown.
    case relayed(derpRegion: Int64)
}
