import SwiftailTKA

/// The tailnet lock action to take when a netmap arrives (the branches of Go `tkaSyncIfNeeded`). Makes the decision without I/O.
///
/// | Local state | Capability | Server | Action |
/// | --- | --- | --- | --- |
/// | Absent | Absent | Any | None (no filtering, as in Go) |
/// | Absent | Present | Disabled | None |
/// | Absent | Present | Enabled (including unknown head) | `bootstrap` |
/// | Present | Irrelevant | Enabled, matching head | None |
/// | Present | Irrelevant | Enabled, different or unknown head | `synchronize` |
/// | Present | Irrelevant | Disabled | `verifyDisablement` |
///
/// "Enabled, head unknown" means `TKAInfo` arrived without `Disabled`, and `Head` is absent or unreadable (`ServerLockState`, §5 TL-11b
/// item 3).
///
/// Contract `docs/contracts/SwiftailTailnetLock.md` behavior N2, `docs/protocol-notes/tailnet-lock.md` §4.7 and §4.12
/// (origin: `tkaSyncIfNeeded` in tailscale.com `ipn/ipnlocal/tailnet-lock.go`, BSD-3-Clause).
enum TailnetLockPlan: Equatable {
    case nothing
    /// Receives the checkpoint via the bootstrap RPC, verifies and stores it, then synchronizes immediately.
    case bootstrap
    /// Exchanges AUMs with the server to align heads.
    case synchronize
    /// Verifies the disablement secret supplied by the server. Deletes local state only if it matches.
    case verifyDisablement

    /// - Parameters:
    ///   - localHead: The head of the local signing authority state, or nil when absent.
    ///   - hasCapability: Whether the self node has the `tailnet-lock` capability.
    ///   - server: The state the server reported in this map session.
    init(localHead: AUMHash?, hasCapability: Bool, server: ServerLockState) {
        switch (localHead, server.isEnabled) {
        case (nil, true): self = hasCapability ? .bootstrap : .nothing
        case (nil, false): self = .nothing
        // Compare the head's 32 bytes because two text forms with different last characters can represent the same hash. An unknown head (nil) differs.
        case (let head?, true): self = head == server.head ? .nothing : .synchronize
        case (_?, false): self = .verifyDisablement
        }
    }
}

extension Node {
    /// The node capability that enables tailnet lock on the self node (`nodecap.TailnetLock`).
    static let tailnetLockCapability = "https://tailscale.com/cap/tailnet-lock"

    /// Whether this node has the `tailnet-lock` capability. Checks the union of the legacy `Capabilities` list and `CapMap` keys
    /// (Go `mapSession.lastCapSet`, `control/controlclient/map.go`).
    var hasTailnetLockCapability: Bool {
        capMap[Self.tailnetLockCapability] != nil || capabilities.contains(Self.tailnetLockCapability)
    }
}
