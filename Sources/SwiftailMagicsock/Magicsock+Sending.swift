// The conditions for sending and deferring CallMeMaybe follow the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`enqueueCallMeMaybe`, `endpointsFreshEnoughDuration`),
// `wgengine/magicsock/endpoint.go` (`send`). Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Sending WireGuard datagrams and disco messages (contract behaviors D3, D4, and F, notes 4.5 and 4.8 4).
///
/// The peer's `PeerPathState` selects the path. If the direct address is trusted, send only over UDP. Otherwise send to both the direct address (if any) and the peer's home DERP
/// while rediscovering the path. This file converts that plan into output, seals any disco Pings in the plan, and fills CallMeMaybe with
/// local endpoints. If the endpoints are stale, defers CallMeMaybe and sends it after a STUN round completes.
extension Magicsock {
    /// If the local endpoints to put in CallMeMaybe are at least this old, rerun the round before sending.
    /// `endpointsFreshEnoughDuration` (`magicsock.go:4112`, notes 4.8 4.1).
    static let endpointsFreshness: Duration = .seconds(27)

    /// Sends a WireGuard datagram from the engine to a peer, choosing its path.
    public mutating func send(_ datagram: [UInt8], to peer: NodePublicKey, at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return send(datagram, to: peer, at: now, using: &random)
    }

    /// Equivalent to `send(_:to:at:)`, drawing random values from `generator`.
    ///
    /// Emits the datagram over UDP and then DERP as applicable, followed by associated disco Pings and CallMeMaybe, STUN requests from restarting periodic rounds, and path events.
    /// If there is no direct address or DERP region, discards the datagram with `noRouteToPeer` and sends the Pings as usual.
    mutating func send(
        _ datagram: [UInt8],
        to peer: NodePublicKey,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let plan = peers[peer]?.path.planSend(at: now, using: &generator) else { return [.dropped(.noRouteToPeer)] }

        var outputs: [Output] = []
        if let udp = plan.udp {
            outputs.append(.udp(datagram, to: udp))
        }
        if plan.derpRegion != 0 {
            outputs.append(.derp(datagram, to: peer, region: plan.derpRegion))
        }
        if outputs.isEmpty {
            outputs.append(.dropped(.noRouteToPeer))
        }
        outputs += handle(plan.actions, for: peer, at: now, using: &generator)
        // The next send re-arms periodic rounds paused due to idleness (behavior E5).
        if netcheck.nextDeadline == nil {
            outputs += handle(netcheck.reSTUN(at: now, using: &generator), at: now, using: &generator)
        }
        reportPathChange(of: peer, at: now, into: &outputs)
        return outputs
    }

    /// Converts a peer path state machine's actions into outputs. Seals Pings and sends them over UDP, and handles CallMeMaybe via `callMeMaybe(to:)`.
    mutating func handle(
        _ actions: [PeerPathState.Action],
        for peer: NodePublicKey,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let discoKey = peers[peer]?.discoKey else { return [] }
        var outputs: [Output] = []
        for action in actions {
            switch action {
            case .ping(let txID, let destination):
                if let ping = seal(.ping(txID, nodeKey: nodeKey), to: discoKey, using: &generator) {
                    outputs.append(.udp(ping, to: destination))
                }
            case .callMeMaybe:
                outputs += callMeMaybe(to: peer, at: now, using: &generator)
            }
        }
        return outputs
    }

    /// Sends a CallMeMaybe containing all local endpoints to the peer over its home DERP (behavior F1).
    ///
    /// If local endpoints are at least 27 seconds old or have never been determined, add the peer to the deferred list (one slot per peer) and start a round.
    /// When the round ends, `sendPendingCallMeMaybe` sends it (behavior F2). Endpoint types are omitted (notes 4.8 4.2).
    mutating func callMeMaybe(
        to peer: NodePublicKey,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let entry = peers[peer], let discoKey = entry.discoKey, entry.path.homeDERP != 0 else { return [] }
        guard let refreshed = netcheck.endpointsRefreshedAt, now - refreshed < Self.endpointsFreshness else {
            if !pendingCallMeMaybe.contains(peer) {
                pendingCallMeMaybe.append(peer)
            }
            return handle(netcheck.reSTUN(at: now, using: &generator), at: now, using: &generator)
        }
        let message = DiscoMessage.callMeMaybe(netcheck.endpoints.map(\.address))
        guard let packet = seal(message, to: discoKey, using: &generator) else { return [] }
        return [.derp(packet, to: peer, region: entry.path.homeDERP)]
    }

    /// Sends deferred CallMeMaybe messages once endpoints have been refreshed.
    mutating func sendPendingCallMeMaybe(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Output] {
        let waiting = pendingCallMeMaybe
        pendingCallMeMaybe = []
        var outputs: [Output] = []
        for peer in waiting {
            outputs += callMeMaybe(to: peer, at: now, using: &generator)
        }
        return outputs
    }
}
