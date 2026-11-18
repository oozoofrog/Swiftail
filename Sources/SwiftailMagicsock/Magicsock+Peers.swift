// The disco key table and rules for receiving TSMP disco key advertisements follow the Go implementation.
// Origin: tailscale.com v1.104.7 `wgengine/magicsock/peermap.go` (`nodesOfDisco`, `upsertEndpoint`,
// `cleanFromNodesOfDisco`), `wgengine/magicsock/magicsock.go` (`HandleDiscoKeyAdvertisement`, `upsertPeerLocked`),
// `wgengine/magicsock/endpoint.go` (`checkAndUpdateDiscoKey`, `changedActiveDiscoLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// The peer and disco key tables (contract behaviors B and T, notes 3.2 5, 4.4, and 4.10).
///
/// The node passes the entire peer list whenever the netmap changes. When a peer sends a TSMP disco key advertisement through the tunnel, the node passes
/// that peer's node key and the advertised key. This file uses those inputs to synchronize three things.
/// - **Disco key table.** Multiple peers can hold one disco key (Go `nodesOfDisco`). A peer holds one netmap key and one TSMP key,
///   and one of them is active (`PeerDiscoKeys`). A peer can change only its own key. The netmap updates each peer's
///   netmap key, and an advertisement updates its sender's TSMP key. Other holders of the same key are unaffected. The owner of an incoming disco message
///   is resolved per message by `+Receiving` using the same rules as Go.
/// - **Shared key cache.** Runs X25519 once per disco key in the table and discards keys with no holders. Junk
///   UDP or DERP traffic claiming an unknown key cannot trigger computation. Low-order keys for which computation fails are treated as absent. TSMP advertisements only arrive
///   from WireGuard-authenticated peers and trigger computation only for a changed key (as in Go `discoInfoForKnownPeerLocked`).
/// - **Per-peer path state.** Creates new peers, applies netmap values to retained peers, and discards trust and in-flight Pings for peers
/// whose keys changed (notes §4.4, item 3). Removes peers absent from the new list and emits `.pathChanged(key, nil)` if a path had been reported.

extension Magicsock {
    /// Synchronizes netmap peers. The node supplies them in node ID order, which determines peer table and output order.
    ///
    /// If a node key appears twice, uses only the first entry. If several peers advertise the same disco key, all of them use that key for disco
    /// (as in Go). Preserves TSMP keys for retained peers. Outputs `.pathChanged(_, nil)` for removed peers, then `.pathChanged` in list order
    /// for peers whose paths changed. New peers have not sent anything, so they are idle (nil) and emit no event (behavior G3).
    public mutating func setPeers(_ newPeers: [Peer], at now: ContinuousClock.Instant) -> [Output] {
        var table: [DiscoPublicKey: DiscoKeyHolders] = [:]
        var entries: [NodePublicKey: PeerEntry] = [:]
        var order: [NodePublicKey] = []
        for peer in newPeers where entries[peer.key] == nil {
            let netmapKey = hold(peer.discoKey, for: peer.key, in: &table)
            // Always reacquire a held TSMP key because its shared key is cached.
            _ = hold(peers[peer.key]?.discoKeys.tsmp, for: peer.key, in: &table)
            entries[peer.key] = updatedEntry(peers[peer.key], with: peer, netmapKey: netmapKey, at: now)
            order.append(peer.key)
        }

        var outputs: [Output] = []
        // Do not report removal if nil (idle) was already reported for the peer (behavior G2).
        for key in peerOrder where entries[key] == nil && peers[key]?.reportedPath != nil {
            outputs.append(.pathChanged(key, nil))
        }
        peers = entries
        peerOrder = order
        discoPeers = table
        pendingCallMeMaybe.removeAll { entries[$0]?.discoKey == nil }
        for key in order {
            reportPathChange(of: key, at: now, into: &outputs)
        }
        return outputs
    }

    /// A TSMP disco key advertisement sent by `peer` through the WireGuard tunnel (behaviors T3~T5, Go `HandleDiscoKeyAdvertisement`).
    ///
    /// The node passes only advertisements authenticated by WireGuard that passed the source check (engine `.discoKeyAdvertised`). This becomes the
    /// TSMP key for `peer` and is made active. Accept it even if another peer holds it, leaving that peer unchanged (as in Go). A key of 0, an unknown
    /// peer, the same key as the previous TSMP key, or a key for which the shared key cannot be computed changes nothing. On change, discard that peer's trust and in-flight
    /// Pings (notes 4.4 3) and emit `.pathChanged` if the path changed.
    ///
    /// shortcut: A peer with no netmap key (a key of 0) did not retain netmap endpoints as candidates. If an advertisement supplies a key, candidates still come from
    /// the next netmap, CallMeMaybe, or received Ping. This will be needed when peers with no disco key in the netmap are actually observed
    /// sending advertisements.
    public mutating func receiveDiscoKeyAdvertisement(
        _ key: DiscoPublicKey,
        from peer: NodePublicKey,
        at now: ContinuousClock.Instant
    ) -> [Output] {
        guard !key.isZero, var entry = peers[peer], entry.discoKeys.tsmp != key,
              let sharedKey = sharedKey(for: key)
        else { return [] }
        let previous = entry.discoKeys.tsmp
        if entry.discoKeys.updateTSMP(key) {
            entry.path.resetForNewDiscoKey()
        }
        peers[peer] = entry
        var holders = discoPeers[key] ?? DiscoKeyHolders(sharedKey: sharedKey, nodes: [])
        if !holders.nodes.contains(peer) {
            holders.nodes.append(peer)
        }
        discoPeers[key] = holders
        // Keep the old TSMP key in the table if it is still the peer's netmap key (Go removes it here and drops disco messages using that key, contract T5).
        if let previous, previous != entry.discoKeys.netmap {
            release(previous, from: peer)
        }
        var outputs: [Output] = []
        reportPathChange(of: peer, at: now, into: &outputs)
        return outputs
    }

    /// Matches the sender key of a disco message confirmed to be from `peer` against that peer's keys (Go `checkAndUpdateDiscoKey`).
    ///
    /// If it was inactive, makes it active and discards trust and in-flight Pings. Only `peer`'s state changes.
    ///
    /// - Returns: Whether it was the peer's key, active or inactive.
    mutating func noteDiscoKeySeen(_ key: DiscoPublicKey, from peer: NodePublicKey) -> Bool {
        guard let seen = peers[peer]?.discoKeys.noteSeen(key) else { return false }
        if seen.changed {
            peers[peer]?.path.resetForNewDiscoKey()
        }
        return seen.known
    }

    /// Adds `node` to `table` as a peer holding `key`. Returns nil without adding it for a key of 0 or when its shared key cannot be computed (a low-order key).
    private func hold(_ key: DiscoPublicKey?, for node: NodePublicKey, in table: inout [DiscoPublicKey: DiscoKeyHolders]) -> DiscoPublicKey? {
        guard let key, !key.isZero else { return nil }
        if table[key] == nil {
            guard let sharedKey = sharedKey(for: key) else { return nil }
            table[key] = DiscoKeyHolders(sharedKey: sharedKey, nodes: [])
        }
        if table[key]?.nodes.contains(node) == false {
            table[key]?.nodes.append(node)
        }
        return key
    }

    /// Releases `key` from `node`. If no holders remain, discards the shared key too (Go `cleanFromNodesOfDisco`).
    private mutating func release(_ key: DiscoPublicKey, from node: NodePublicKey) {
        discoPeers[key]?.nodes.removeAll { $0 == node }
        if discoPeers[key]?.nodes.isEmpty == true {
            discoPeers[key] = nil
        }
    }

    /// The shared key for `key`. Reuses it from the old table if present and computes it only if absent. Returns nil for a low-order key.
    private func sharedKey(for key: DiscoPublicKey) -> DiscoSharedKey? {
        if let cached = discoPeers[key]?.sharedKey { return cached }
        return try? DiscoSharedKey(privateKey: discoPrivateKey, peerPublicKey: key)
    }

    /// The next state of one peer. Peers that do not use disco get no candidates, so no Pings go out (DERP only).
    private func updatedEntry(
        _ existing: PeerEntry?,
        with peer: Peer,
        netmapKey: DiscoPublicKey?,
        at now: ContinuousClock.Instant
    ) -> PeerEntry {
        var keys = existing?.discoKeys ?? PeerDiscoKeys()
        let changed = keys.updateNetmap(netmapKey)
        let endpoints = keys.active == nil ? [] : peer.endpoints
        guard var entry = existing else {
            return PeerEntry(discoKeys: keys, path: PeerPathState(homeDERP: peer.homeDERP, endpoints: endpoints))
        }
        if changed {
            if keys.active == nil {
                // When disco stops, no more Pongs arrive, so discard all traces of a direct path.
                entry.path = PeerPathState(homeDERP: peer.homeDERP, endpoints: [])
            } else {
                entry.path.resetForNewDiscoKey()
            }
        }
        entry.path.update(homeDERP: peer.homeDERP, endpoints: endpoints, at: now)
        entry.discoKeys = keys
        return entry
    }
}
