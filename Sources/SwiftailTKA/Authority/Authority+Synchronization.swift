// Synchronization calculations: offers and AUMs the peer lacks. Notes §4.8, contract behaviors Y1 and Y4, decision L8, §5 TL-11a item 3.
//
// The ancestor list, order of head and tail intersection, and iteration limits follow the Go implementation.
// Origin: tailscale.com v1.104.7 `tka/sync.go` (`SyncOffer`, `computeSyncIntersection`, `MissingAUMs`), `tka/limits.go`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// An offer exchanged during synchronization, with the head and ancestors for finding an intersection (Go `tka.SyncOffer`).
package struct SyncOffer: Sendable, Equatable {
    /// That side's head.
    package var head: AUMHash
    /// Newest first. The last entry is the oldest AUM in that side's store.
    package var ancestors: [AUMHash]

    /// Creates an offer from a head and ancestors. `Authority.missingAUMs(for:)` handles duplicate ancestors and the ancestor count, so this initializer does not check received offers.
    package init(head: AUMHash, ancestors: [AUMHash]) {
        self.head = head
        self.ancestors = ancestors
    }
}

extension Authority {
    /// The fast-forward limit for synchronization (Go `maxSyncIter`).
    static let maximumSyncIterations = 2_000
    /// The backward traversal limit from the head (Go `maxSyncHeadIntersectionIter`).
    static let maximumSyncHeadIntersectionIterations = 1_000
    /// The maximum number of peer ancestors examined, equal to the largest offer Go emits. Go `SyncOffer` takes up to 1,000 steps backward from the head and includes
    /// the checkpoints it encounters (at most one each time) and the oldest AUM at the end (`tka/sync.go:88-109`).
    static let maximumSyncAncestorCount = maximumSyncHeadIntersectionIterations + 1

    /// The offer to send to the server (Go `SyncOffer`, behavior Y1).
    ///
    /// `ancestors` contains checkpoint hashes encountered while looking back up to 1,000 AUMs from the head (newest first, excluding the root), then the root at the end.
    package func syncOffer() -> SyncOffer {
        var ancestors: [AUMHash] = []
        var cursor = head
        for _ in 0..<Self.maximumSyncHeadIntersectionIterations {
            guard cursor != bootstrap, let position = positions[cursor] else { break }
            let aum = aums[position]
            if aum.messageKind == AUM.Kind.checkpoint { ancestors.append(cursor) }
            guard let parent = aum.parentHash else { break }
            cursor = parent
        }
        ancestors.append(bootstrap)
        return SyncOffer(head: head, ancestors: ancestors)
    }

    /// Returns local AUMs the peer lacks based on its offer, with parents first (Go `MissingAUMs`, behavior Y4).
    ///
    /// Returns an empty list for identical heads. Throws `noIntersection` if there is no intersection or `iterationLimit` if the limit is reached.
    /// If this throws, the caller ends synchronization without admitting the peer's AUMs.
    ///
    /// Deduplicates the peer's ancestors and examines only the first 1,001 (`maximumSyncAncestorCount`, TL-11a item 3). Each ancestor requires walking backward
    /// to a checkpoint and reapplying updates, so a control server that repeats AUMs from a losing branch could amplify the work in a single response. Repeated ancestors
    /// produce the same answer as the first occurrence, and Go offers contain at most 1,001 entries, so the decision matches Go.
    package func missingAUMs(for remote: SyncOffer) throws(TKAError) -> [AUM] {
        guard remote.head != head else { return [] }
        var seen: Set<AUMHash> = []
        var ancestors: [AUMHash] = []
        for ancestor in remote.ancestors {
            guard ancestors.count < Self.maximumSyncAncestorCount else { break }
            if seen.insert(ancestor).inserted { ancestors.append(ancestor) }
        }
        let intersection = try intersection(with: SyncOffer(head: remote.head, ancestors: ancestors))
        let start = try state(at: intersection, iterationLimit: Self.maximumSyncIterations)
        var missing: [AUM] = []
        _ = try fastForward(from: intersection, state: start, iterationLimit: Self.maximumSyncIterations) { hash in
            if hash != intersection, let position = positions[hash] { missing.append(aums[position]) }
            return false
        }
        return missing
    }

    /// The AUM shared with the peer (Go `computeSyncIntersection`). The list to send begins after the intersection AUM.
    ///
    /// For head intersection, if the peer's head exists locally, look backward from the local head up to 1,000 AUMs. For tail intersection, examine the peer's
    /// ancestors in order and take the first whose state fast-forwards to the local head (up to 2,000 iterations). Skip ancestors absent locally and throw
    /// immediately on other failures (the iteration limit).
    private func intersection(with remote: SyncOffer) throws(TKAError) -> AUMHash {
        if positions[remote.head] != nil {
            var cursor = head
            for _ in 0..<Self.maximumSyncHeadIntersectionIterations {
                guard let position = positions[cursor] else { break }
                if cursor == remote.head { return cursor }
                guard let parent = aums[position].parentHash else { break }
                cursor = parent
            }
        }
        for ancestor in remote.ancestors where positions[ancestor] != nil {
            let start = try state(at: ancestor, iterationLimit: Self.maximumSyncIterations)
            let end = try fastForward(from: ancestor, state: start, iterationLimit: Self.maximumSyncIterations) {
                $0 == head
            }
            if end.head == head { return ancestor }
        }
        throw .noIntersection
    }
}
