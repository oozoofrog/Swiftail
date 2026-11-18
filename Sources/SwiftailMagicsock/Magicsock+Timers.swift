// The idleness rule for periodic ReSTUN follows the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`shouldDoPeriodicReSTUNLocked`, `sessionActiveTimeout`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Deadlines and STUN rounds (contract behaviors D7, E, G1, and G3, notes 4.6 3, 4.8 3, and 4.9 5).
///
/// `Magicsock` combines deadlines from its components, including each peer's Ping deadlines, heartbeat, and trust expiration (`PeerPathState`),
/// the STUN round's next request, cutoff, and period (`Netcheck`), and the time when each peer becomes idle (behavior G3). The node calls
/// `advance(to:)` at `nextDeadline`. `advance` runs only due components. At that deadline, `advance` emits
/// `.pathChanged(.relayed)` for a peer whose trust expired or `.pathChanged(nil)` for a peer that became idle.
///
/// Converts each STUN round result (`Netcheck.Action`) to outputs here as well. When a round completes and endpoints are refreshed, sends deferred
/// CallMeMaybe messages.
extension Magicsock {
    /// Synchronizes candidate home regions. Starts a STUN round immediately if they changed. Immediately selects a fallback home if there is no home.
    public mutating func setRegions(_ regions: [Region], at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return setRegions(regions, at: now, using: &random)
    }

    /// Processes timers due by now (Ping deadlines, heartbeat, trust expiration, STUN round).
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return advance(to: now, using: &random)
    }

    /// The next time to call `advance`, or nil if no timer is armed.
    ///
    /// Includes each peer path state machine's deadline and when a reported path becomes idle and turns nil (behavior G3). The node calls this on each processing step,
    /// so it does not allocate an array.
    public var nextDeadline: ContinuousClock.Instant? {
        var earliest = netcheck.nextDeadline
        for entry in peers.values {
            earliest = earliest.earlier(entry.path.nextDeadline).earlier(Self.idleDeadline(of: entry))
        }
        return earliest
    }

    /// Equivalent to `setRegions(_:at:)`, drawing random values from `generator`.
    mutating func setRegions(
        _ regions: [Region],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        handle(netcheck.setRegions(regions, at: now, using: &generator), at: now, using: &generator)
    }

    /// Equivalent to `advance(to:)`, drawing random values from `generator`.
    ///
    /// Runs peers in `setPeers` order, then runs the STUN round. Leaves components that are not due untouched.
    mutating func advance(to now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Output] {
        var outputs: [Output] = []
        for key in peerOrder {
            guard let entry = peers[key] else { continue }
            let pathDue = entry.path.nextDeadline.map { $0 <= now } ?? false
            let idleDue = Self.idleDeadline(of: entry).map { $0 <= now } ?? false
            guard pathDue || idleDue else { continue }
            if pathDue, let actions = peers[key]?.path.advance(to: now, using: &generator) {
                outputs += handle(actions, for: key, at: now, using: &generator)
            }
            reportPathChange(of: key, at: now, into: &outputs)
        }
        if let deadline = netcheck.nextDeadline, deadline <= now {
            let actions = netcheck.advance(to: now, isActive: isActive(at: now), using: &generator)
            outputs += handle(actions, at: now, using: &generator)
        }
        return outputs
    }

    /// Whether usage warrants continuing periodic rounds (behavior E5). There must be peers, and some peer must have sent within the last 45 seconds.
    ///
    /// Go checks idle time for sending and receiving on the TUN (stopping when `idleFor > sessionActiveTimeout`). This type uses the WireGuard send time
    /// instead (contract E5).
    func isActive(at now: ContinuousClock.Instant) -> Bool {
        peers.values.contains { entry in
            entry.path.lastSend.map { now - $0 <= PeerPathState.sessionActiveTimeout } ?? false
        }
    }

    /// Converts STUN round actions into outputs. Sends deferred CallMeMaybe messages if endpoints were refreshed (behavior F2).
    mutating func handle(
        _ actions: [Netcheck.Action],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        var outputs: [Output] = []
        for action in actions {
            switch action {
            case .sendSTUN(let request, let server):
                outputs.append(.udp(request, to: server))
            case .endpointsChanged(let endpoints):
                outputs.append(.endpointsChanged(endpoints))
            case .homeRegionChanged(let region):
                outputs.append(.homeRegionChanged(region))
            case .endpointsRefreshed:
                outputs += sendPendingCallMeMaybe(at: now, using: &generator)
            }
        }
        return outputs
    }
}

extension Optional<ContinuousClock.Instant> {
    /// The earlier of two deadlines. Nil means no deadline, so the other one wins. Used to compute deadlines without allocating an array.
    func earlier(_ other: ContinuousClock.Instant?) -> ContinuousClock.Instant? {
        guard let self else { return other }
        guard let other else { return self }
        return Swift.min(self, other)
    }
}
