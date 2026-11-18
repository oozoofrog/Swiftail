// The rules for choosing the active key from the netmap and TSMP keys are ported from the Go implementation.
// Origin: tailscale.com v1.104.7 `wgengine/magicsock/endpoint.go` (`endpointDisco`, `updateDiscoKey`,
// `updateTSMPDiscoKey`, `checkAndUpdateDiscoKey`), `wgengine/magicsock/magicsock.go` (`HandleDiscoKeyAdvertisement`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// A peer’s two disco keys and which one is active (contract “TSMP Disco Key Advertisement (2026-11-16),” behavior T4, notes §4.10, item 2).
///
/// Holds the key learned from the netmap and the key learned from a TSMP advertisement separately. Seals outgoing disco messages with the one active key. The rules match Go.
/// - When a TSMP advertisement arrives, its key becomes active even if the netmap supplied a newer key.
/// - Changing the netmap key leaves the active TSMP key active. The netmap key becomes active only if there is no TSMP key or
///   a Ping or CallMeMaybe sealed with the inactive key arrives (`noteSeen`).
///
/// A mutating entry point returns true when its Go counterpart does. It can return true even if the active key's value did not change (when the first advertisement
/// matches the netmap key, or when the netmap key changes while the TSMP key is active). On true, the caller triggers path rediscovery (Go
/// `changedActiveDiscoLocked`, `PeerPathState.resetForNewDiscoKey`).
///
/// Keys of 0 are omitted. The caller passes nil for a netmap key of 0 or one whose shared key cannot be computed (behavior B1). Whether another peer
/// holds the same key has no bearing on this value (multiple peers can hold one key).
struct PeerDiscoKeys: Sendable, Equatable {
    /// The key learned from netmap. Go `controlKey`.
    private(set) var netmap: DiscoPublicKey?
    /// The key learned from a TSMP advertisement. Go `tsmpKey`.
    private(set) var tsmp: DiscoPublicKey?
    /// Whether the TSMP key is active. Go `tsmpActive`.
    private(set) var tsmpActive = false

    /// The key for sealing outgoing disco messages. Nil if both keys are absent (DERP only, no disco).
    var active: DiscoPublicKey? {
        tsmpActive ? tsmp : netmap
    }

    /// The key supplied by netmap (Go `updateFromNode` → `updateDiscoKey`). Does nothing if the netmap key is unchanged.
    ///
    /// If nil, clears the netmap key and makes the TSMP key active if present. Otherwise the TSMP key stays active only if it already was.
    mutating func updateNetmap(_ key: DiscoPublicKey?) -> Bool {
        guard key != netmap else { return false }
        tsmpActive = tsmpActive || key == nil
        netmap = key
        normalize()
        return true
    }

    /// The key supplied by a TSMP advertisement (Go `updateTSMPDiscoKey`). If it matches the previous TSMP key, changes nothing even when the netmap key is active (Go
    /// `HandleDiscoKeyAdvertisement` first filters that case as "unchanged"). The TSMP key is never cleared (Go also rejects
    /// keys of 0 in advertisements). Discards it with this entire value when the peer is removed.
    mutating func updateTSMP(_ key: DiscoPublicKey) -> Bool {
        guard key != tsmp else { return false }
        tsmp = key
        tsmpActive = true
        return true
    }

    /// The sender key of a disco message confirmed to be from this peer (Go `checkAndUpdateDiscoKey`).
    ///
    /// - Returns: `known` indicates whether the key was one of the peer's two keys, and `changed` indicates whether it was inactive and
    ///   became active.
    mutating func noteSeen(_ key: DiscoPublicKey) -> (known: Bool, changed: Bool) {
        if active == key { return (true, false) }
        let inactive = tsmpActive ? netmap : tsmp
        guard inactive == key else { return (false, false) }
        tsmpActive.toggle()
        return (true, true)
    }

    /// Resets to the initial state if both keys are absent (Go sets `endpointDisco` to nil).
    private mutating func normalize() {
        if netmap == nil, tsmp == nil {
            tsmpActive = false
        }
    }
}
