// Rebinding follows the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`Rebind`, `resetEndpointStates`, `ReSTUN`),
// `wgengine/magicsock/endpoint.go` (`noteConnectivityChange`). Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Rebinding and rerunning STUN after a network change (`SwiftailTunnel` contract behavior N 2 and 3.3, notes 4.11).
///
/// The node calls `rebind` after opening and binding a new UDP socket, and `restartSTUN` when only the link changes while interfaces and addresses stay the same.
/// This type does not open sockets. The node opens the socket, calls `rebind`, processes its outputs, and calls
/// `advance` at `nextDeadline`, in that order.
extension Magicsock {
    /// Reports that a new UDP socket was bound. Discards all peers' direct paths and immediately starts a STUN round.
    ///
    /// - Replaces the inputs for the local endpoints. Recomputes the endpoint list at the end of the round. Emits `.endpointsChanged` only when
    ///   the endpoint set changes.
    /// - Clears all peers' `bestAddr`, trust, and Ping history (`PeerPathState.noteConnectivityChange`). Emits
    ///   `.pathChanged` for peers whose paths changed. Idle peers still have a nil path and emit no event (behavior G3).
    /// - Discards any in-progress round. Late responses from the old round yield `.dropped(.unexpectedSTUN)`.
    /// - Outputs path events in peer order, then STUN requests.
    ///
    /// - Parameters:
    ///   - localPort: The port the new socket is bound to.
    ///   - localAddresses: Interface IPv4 addresses excluding loopback. As in `init`.
    ///   - loopbackAddresses: Loopback IPv4 addresses. As in `init`.
    ///   - now: The current time. Must be at least as recent as the previous call.
    public mutating func rebind(
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        at now: ContinuousClock.Instant
    ) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return rebind(
            localPort: localPort, localAddresses: localAddresses, loopbackAddresses: loopbackAddresses,
            at: now, using: &random
        )
    }

    /// Restarts a STUN round when only the link changes and the socket stays the same (Go `ReSTUN`, “Same” in behavior N 2). Leaves path state as is.
    ///
    /// Does nothing if a round is already active or there are no regions. If endpoints changed, emits
    /// `.endpointsChanged` when the round ends.
    ///
    /// shortcut: Go schedules another round after the active one ends if one is already running (`wantEndpointsUpdate`). Here the active
    /// round (at most 3 seconds) measures the same interfaces and addresses, so its results are used. Schedule another round if real-device testing shows
    /// that the active round returns stale results after a link change and yields incorrect endpoints.
    public mutating func restartSTUN(at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return restartSTUN(at: now, using: &random)
    }

    /// Equivalent to `rebind(localPort:localAddresses:loopbackAddresses:at:)`, drawing random values from `generator`.
    mutating func rebind(
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        var outputs: [Output] = []
        for key in peerOrder {
            peers[key]?.path.noteConnectivityChange()
            reportPathChange(of: key, at: now, into: &outputs)
        }
        let actions = netcheck.rebind(
            localPort: localPort, localAddresses: localAddresses, loopbackAddresses: loopbackAddresses,
            at: now, using: &generator
        )
        return outputs + handle(actions, at: now, using: &generator)
    }

    /// Equivalent to `restartSTUN(at:)`, drawing random values from `generator`.
    mutating func restartSTUN(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Output] {
        handle(netcheck.reSTUN(at: now, using: &generator), at: now, using: &generator)
    }
}
