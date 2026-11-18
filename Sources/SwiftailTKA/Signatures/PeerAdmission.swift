// Decisions for a set of peers, including signature checks and keys superseded by rotation. Notes §4.9, contract behaviors P1–P5.
// Ported from Go `tailscale.com` v1.104.7 `ipn/ipnlocal/tailnet-lock.go:189-338` (filtering in `tkaFilterNetmapLocked` and `rotationTracker`).
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailBase

/// Input for the decision about one peer (only the fields used from the netmap `Node`).
package struct PeerCredential: Sendable {
    /// `Node.Key`, the node key the signature must authorize.
    package var nodeKey: NodePublicKey
    /// The `Node.KeySignature` bytes. Empty means no signature.
    package var keySignature: [UInt8]
    /// `Node.UnsignedPeerAPIOnly`. Skips signature verification but, as in Go, is removed if another peer's rotation supersedes the key.
    package var unsignedPeerAPIOnly: Bool

    /// The three values used to decide whether to admit a netmap `Node`. Signature decoding takes place in `AuthorityState.admitted(_:)` at decision time.
    package init(nodeKey: NodePublicKey, keySignature: [UInt8], unsignedPeerAPIOnly: Bool) {
        self.nodeKey = nodeKey
        self.keySignature = keySignature
        self.unsignedPeerAPIOnly = unsignedPeerAPIOnly
    }
}

extension AuthorityState {
    /// Determines whether each peer stays in the netmap (the peer portion of Go `tkaFilterNetmapLocked`). Results follow input order.
    ///
    /// Removes peers with no signature or whose signatures fail `authorize` (`UnsignedPeerAPIOnly` is exempt) and any peer whose node key was
    /// superseded by rotation (including `UnsignedPeerAPIOnly`). Superseded keys include all `previousNodeKeys` from verified rotations and
    /// current node keys from rotations with shorter histories in each group of rotations with a direct `initialSignature` and the same `WrappingPubkey`. If two or more
    /// tie for longest, the whole group is superseded. Chains starting from credential are not grouped (multiple nodes join with a reusable auth key).
    ///
    /// Groups are considered in the order of the first peer in each group. Go has no fixed order because it iterates a map. One group's decision affects
    /// another's only when the same node key appears in groups with different rotation keys.
    package func admitted(_ peers: [PeerCredential]) -> [Bool] {
        var rejected = [Bool](repeating: false, count: peers.count)
        var obsolete: Set<NodePublicKey> = []
        var groups: [(rotationKey: [UInt8], members: [(nodeKey: NodePublicKey, previousKeyCount: Int)])] = []
        for (index, peer) in peers.enumerated() where !peer.unsignedPeerAPIOnly {
            let details: RotationDetails?
            do {
                // An empty signature (Go's "missing signature") fails decoding, so no separate check is needed.
                details = try authorize(peer.nodeKey, keySignature: peer.keySignature)
            } catch {
                rejected[index] = true
                continue
            }
            guard let details else { continue }
            obsolete.formUnion(details.previousNodeKeys)
            guard details.initialSignature.kind == NodeKeySignature.Kind.direct else { continue }
            let member = (nodeKey: peer.nodeKey, previousKeyCount: details.previousNodeKeys.count)
            let rotationKey = details.initialSignature.wrappingPublicKey
            if let group = groups.firstIndex(where: { $0.rotationKey == rotationKey }) {
                groups[group].members.append(member)
            } else {
                groups.append((rotationKey, [member]))
            }
        }
        for group in groups {
            // Skip comparison for keys another signature already superseded.
            let members = group.members.filter { !obsolete.contains($0.nodeKey) }
            guard let longest = members.map(\.previousKeyCount).max() else { continue }
            let isUnique = members.count(where: { $0.previousKeyCount == longest }) == 1
            obsolete.formUnion(members.filter { !isUnique || $0.previousKeyCount != longest }.map(\.nodeKey))
        }
        return peers.indices.map { !rejected[$0] && !obsolete.contains(peers[$0].nodeKey) }
    }
}
