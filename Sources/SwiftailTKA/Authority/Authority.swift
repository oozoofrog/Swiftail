// Signing authority state machine (Go `tka.Authority`). Notes §§4.1–4.3, contract behaviors F and M, decisions L7, L10, and L14, §5
// "Independent review fixes for pure logic (TL-11a, 2026-11-15)" items 1, 2, and 4.
//
// Bootstrap, admission (`Inform`) order and failure rules, fork resolution (`pickNextAUM`), fast-forward (`fastForward`), state at an AUM
// (`computeStateAt`), and their iteration limits were ported from Go. The store is limited to one root, so `Open`'s ancestor selection was
// omitted (behavior F6).
// Origin: tailscale.com v1.104.7 `tka/tka.go` (`Bootstrap`, `InformIdempotent`, `pickNextAUM`, `fastForwardWithAdvancer`,
// `computeStateAt`), `tka/limits.go`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// The tailnet's signing authority state. This value type holds admitted AUMs and the head and trust state computed from them.
///
/// Owns no sockets, files, or clock. The edge (`TailnetLockStore`) persists `aums` and `bootstrap`. Without compaction,
/// the root is always the single bootstrapped checkpoint and all other AUMs have parents in the store (decision L7). AUMs outside the active chain
/// are discarded at the limit (TL-11a item 1), so `aums` contains the retained subset of admitted AUMs.
package struct Authority: Sendable {
    /// The hash of the AUM reached by following the fork resolution rules (behavior F1) from the root to the end (behavior F2).
    package private(set) var head: AUMHash
    /// The trust state after applying updates through `head`. `lastAUMHash` equals `head`.
    package private(set) var state: AuthorityState
    /// The hash of the bootstrapped AUM. It is the store's only root.
    package let bootstrap: AUMHash
    /// The retained AUMs (the entire active chain and forks retained within the limits). Parents always precede children. This is what gets persisted.
    package private(set) var aums: [AUM]

    /// Hashes at the same positions as `aums`.
    private(set) var hashes: [AUMHash]
    /// Maps a hash to its position in `aums`.
    private(set) var positions: [AUMHash: Int]
    /// Maps a parent hash to its children's positions.
    private var children: [AUMHash: [Int]] = [:]
    /// Canonical byte counts at the same positions as `aums`.
    private var byteCounts: [Int]
    /// The root checkpoint's own state (`lastAUMHash` is the root). The starting point for recomputing the head.
    private let rootState: AuthorityState

    /// The upper limits on AUM count and total canonical bytes (behavior M, decisions L7 and L16, TL-11a item 1).
    ///
    /// Reject an entire batch if the **active chain** (root to head) exceeds either limit. If all retained AUMs together exceed a limit, discard AUMs outside
    /// the active chain until within the limit (`discardInactiveAUMs()`). Applying the limit to the total would let the control server fill it with
    /// signature-list variants that require no signing key and block even a later RemoveKey.
    static let maximumAUMCount = 4_096
    static let maximumByteCount = 16 * 1_024 * 1_024
    /// The maximum number of AUMs admitted at once (behavior M).
    static let maximumBatchCount = 4_096
    /// The backward iteration limit for locating a parent state (Go `maxScanIterations`, behavior F7).
    static let maximumScanIterations = 2_000

    /// Starts from the single checkpoint supplied by the server (Go `Bootstrap`, behavior F5).
    ///
    /// Uses the checkpoint's **own state** as its parent state for static checks and signature verification. Ignores the parent hash so it can accept
    /// later checkpoints as well as genesis. Initial trust in what the control server supplied is TOFU.
    package init(bootstrappingWith checkpoint: AUM) throws(TKAError) {
        guard checkpoint.messageKind == AUM.Kind.checkpoint, let checkpointState = checkpoint.state else {
            throw .notACheckpoint
        }
        try checkpointState.verify(checkpoint, isBootstrap: true)
        let bytes = checkpoint.serialized()
        guard bytes.count <= Self.maximumByteCount else { throw .limitExceeded }
        let hash = AUMHash(hashing: bytes)
        var rootState = checkpointState
        rootState.lastAUMHash = hash

        self.rootState = rootState
        head = hash
        state = rootState
        bootstrap = hash
        aums = [checkpoint]
        hashes = [hash]
        positions = [hash: 0]
        byteCounts = [bytes.count]
    }

    /// Recomputes state from persisted AUMs (Go `Open`, behaviors F6 and T3).
    ///
    /// Checks the storage limits and requires unique AUMs, `bootstrap` as the sole root, and a stored parent for every other AUM.
    /// Limit breaches produce `limitExceeded`. Violations of the other invariants produce `corruptStore`. Below the root, recheck **the parent, signatures, and last-key
    /// removal rule** before applying state (TL-11a item 2, which narrowed decision L14). Signature verification detects changes to signed data and throws
    /// the specific failure. Static checks run only on admission. Canonical encoding omits empty `Meta`, so even an AUM accepted on admission can fail on reopening (Go `Open` does no revalidation).
    /// The root follows bootstrap checks. Recomputing from root to head has no iteration limit (behavior F7). The storage limit bounds it.
    package init(opening stored: [AUM], bootstrap: AUMHash) throws(TKAError) {
        guard stored.count <= Self.maximumAUMCount else { throw .limitExceeded }
        var hashes: [AUMHash] = []
        var byteCounts: [Int] = []
        var positions: [AUMHash: Int] = [:]
        var storedChildren: [AUMHash: [Int]] = [:]
        for (position, aum) in stored.enumerated() {
            let bytes = aum.serialized()
            let hash = AUMHash(hashing: bytes)
            guard positions.updateValue(position, forKey: hash) == nil else { throw .corruptStore }
            hashes.append(hash)
            byteCounts.append(bytes.count)
            if hash != bootstrap, let parent = aum.parentHash {
                storedChildren[parent, default: []].append(position)
            }
        }
        guard byteCounts.reduce(0, +) <= Self.maximumByteCount else { throw .limitExceeded }
        guard let rootPosition = positions[bootstrap] else { throw .corruptStore }

        // Walk from the root down to its children, verifying against parent state before admission. Admission is depth-first with parents first.
        var authority = try Authority(bootstrappingWith: stored[rootPosition])
        var pending = (storedChildren[bootstrap] ?? []).map { (position: $0, parentState: authority.rootState) }
        while let child = pending.popLast() {
            let aum = stored[child.position]
            let hash = hashes[child.position]
            try child.parentState.verifyParentAndSignatures(of: aum, isBootstrap: false)
            let state = try child.parentState.applying(aum, hash: hash)
            authority.append(aum, hash: hash, byteCount: byteCounts[child.position])
            pending += (storedChildren[hash] ?? []).map { (position: $0, parentState: state) }
        }
        // Any AUM unreachable from the root has a parent absent from the store or has no parent.
        guard authority.aums.count == stored.count else { throw .corruptStore }
        try authority.recomputeHead()
        self = authority
    }

    /// Admits an AUM batch in received order (Go `Inform`, behavior F4).
    ///
    /// The sender supplies parents first since there is no sort. Skips already retained AUMs. Each AUM's parent state comes from an earlier AUM in the
    /// batch, the current head, or a backward lookup in the store (behavior F3, 2,000 iterations).
    /// **If any AUM fails, nothing changes.** If all pass, recompute the head and reject with `limitExceeded` if the active chain exceeds the limits.
    /// If the retained total exceeds the limits, discard AUMs outside the active chain (TL-11a item 1).
    package mutating func inform(_ updates: [AUM]) throws(TKAError) {
        guard !updates.isEmpty else { throw .emptyUpdate }
        guard updates.count <= Self.maximumBatchCount else { throw .limitExceeded }
        // The remaining count of AUMs in the batch using each hash as a parent. Release the state at 0, since retaining full state for every AUM would
        // grow memory with the square of batch size (TL-11a item 4).
        var pendingChildren: [AUMHash: Int] = [:]
        for update in updates {
            if let parent = update.parentHash { pendingChildren[parent, default: 0] += 1 }
        }

        var next = self
        var stateAt: [AUMHash: AuthorityState] = [head: state]
        for update in updates {
            let bytes = update.serialized()
            let hash = AUMHash(hashing: bytes)
            let parent = update.parentHash
            defer {
                if let parent, let remaining = pendingChildren[parent] {
                    pendingChildren[parent] = remaining > 1 ? remaining - 1 : nil
                    if remaining == 1 { stateAt[parent] = nil }
                }
            }
            if next.positions[hash] != nil { continue }

            guard let parentBytes = update.prevAUMHash, !parentBytes.isEmpty else { throw .missingParent }
            // A parent hash other than 32 bytes cannot equal any state's `lastAUMHash` (Go rejects it during application).
            guard let parent else { throw .rejectedUpdate }
            let parentState: AuthorityState
            if let known = stateAt[parent] {
                parentState = known
            } else {
                guard next.positions[parent] != nil else { throw .missingParent }
                parentState = try next.state(at: parent, iterationLimit: Self.maximumScanIterations)
                stateAt[parent] = parentState
            }

            try parentState.verify(update, isBootstrap: false)
            let updatedState = try parentState.applying(update, hash: hash)
            if pendingChildren[hash] != nil { stateAt[hash] = updatedState }
            next.append(update, hash: hash, byteCount: bytes.count)
        }
        guard next.aums.count > aums.count else { return }
        try next.recomputeHead()
        try next.discardInactiveAUMs()
        self = next
    }

    // MARK: Chain

    /// Adds a verified AUM to the store. The caller is responsible for enforcing the limits (behavior M).
    private mutating func append(_ aum: AUM, hash: AUMHash, byteCount count: Int) {
        let position = aums.count
        aums.append(aum)
        hashes.append(hash)
        positions[hash] = position
        byteCounts.append(count)
        if let parent = aum.parentHash {
            children[parent, default: []].append(position)
        }
    }

    /// Checks that the active chain is within the limits (behavior M). If the retained total exceeds the limits, discards AUMs outside the active chain **most recently admitted first**
    /// (TL-11a item 1). Throws `limitExceeded` if the active chain exceeds the limits. Call after recomputing the head.
    ///
    /// Discarding preserves the current and future head and state as in Go. Fork resolution (behavior F1, Go `pickNextAUM`) is a total order comparing
    /// only siblings under their parent state, without considering descendants. An AUM on the active chain keeps the same parent state, so a sibling that once lost cannot
    /// win again if a new sibling arrives (the total order makes the winner either the current winner or the new one), or if it gains descendants. If a fork point on the
    /// active chain loses to a new sibling, everything below it leaves the active chain and cannot return for the same reason. Thus AUMs outside the active chain do not
    /// affect decisions (synchronization intersections also come only from the active chain). The only difference comes if a later AUM has a discarded AUM as its parent,
    /// which makes it an "AUM with an unknown parent" (behavior F4).
    ///
    /// Discarding the most recently admitted AUMs first means the discarded AUM's children (always positioned after their parent) have already been discarded, so every retained AUM keeps its parent.
    private mutating func discardInactiveAUMs() throws(TKAError) {
        var active: Set<Int> = []
        var activeByteCount = 0
        var cursor = positions[head]
        while let position = cursor {
            active.insert(position)
            activeByteCount += byteCounts[position]
            cursor = hashes[position] == bootstrap ? nil : aums[position].parentHash.flatMap { positions[$0] }
        }
        guard active.count <= Self.maximumAUMCount, activeByteCount <= Self.maximumByteCount else { throw .limitExceeded }

        var count = aums.count
        var byteCount = byteCounts.reduce(0, +)
        var discarded: Set<Int> = []
        for position in aums.indices.reversed() {
            guard count > Self.maximumAUMCount || byteCount > Self.maximumByteCount else { break }
            guard !active.contains(position) else { continue }
            discarded.insert(position)
            count -= 1
            byteCount -= byteCounts[position]
        }
        guard !discarded.isEmpty else { return }

        // Reindex the retained AUMs. The root (position 0) stays because it is on the active chain.
        var kept = self
        kept.aums = [aums[0]]
        kept.hashes = [hashes[0]]
        kept.byteCounts = [byteCounts[0]]
        kept.positions = [hashes[0]: 0]
        kept.children = [:]
        for position in aums.indices.dropFirst() where !discarded.contains(position) {
            kept.append(aums[position], hash: hashes[position], byteCount: byteCounts[position])
        }
        self = kept
    }

    /// Fast-forwards from the root state to the end to determine the head and state (behavior F2).
    private mutating func recomputeHead() throws(TKAError) {
        (head, state) = try fastForward(from: bootstrap, state: rootState, iterationLimit: nil) { _ in false }
    }

    /// Applies children one at a time from `start` (whose state is `startState`), following fork resolution (Go `fastForward`, behavior F2).
    ///
    /// Calls `done` at each AUM (including `start`) and stops there if it returns true. The end is where no child exists. Like Go,
    /// throws `iterationLimit` if it has not finished after iterationLimit steps. nil means unlimited.
    func fastForward(
        from start: AUMHash,
        state startState: AuthorityState,
        iterationLimit: Int?,
        until done: (AUMHash) -> Bool
    ) throws(TKAError) -> (head: AUMHash, state: AuthorityState) {
        var cursor = start
        var state = startState
        var iterations = 0
        while true {
            if let iterationLimit, iterations == iterationLimit { throw .iterationLimit }
            iterations += 1
            if done(cursor) { return (cursor, state) }
            guard let chosen = preferredChild(of: cursor, state: state) else { return (cursor, state) }
            state = try state.applying(aums[chosen], hash: hashes[chosen])
            cursor = hashes[chosen]
        }
    }

    /// The position of the child of `parent` that extends the chain (Go `pickNextAUM`, behavior F1), or nil if there are no children.
    ///
    /// ① Higher signature weight counted using the parent state. ② If tied, RemoveKey. ③ If still tied, the smaller hash by byte comparison.
    private func preferredChild(of parent: AUMHash, state: AuthorityState) -> Int? {
        let ranked = (children[parent] ?? []).map { position in
            (
                position: position,
                weight: state.weight(of: aums[position]),
                removesKey: aums[position].messageKind == AUM.Kind.removeKey,
                hash: hashes[position].bytes
            )
        }
        guard var best = ranked.first else { return nil }
        for candidate in ranked.dropFirst() {
            let isPreferred =
                if candidate.weight != best.weight {
                    candidate.weight > best.weight
                } else if candidate.removesKey != best.removesKey {
                    candidate.removesKey
                } else {
                    candidate.hash.lexicographicallyPrecedes(best.hash)
                }
            if isPreferred { best = candidate }
        }
        return best.position
    }

    /// The state of AUM `target` in the store (Go `computeStateAt`, behavior F3).
    ///
    /// Walks backward to a checkpoint and reapplies updates along the traversed path without using fork resolution. Like Go, throws
    /// `iterationLimit` if the path including the checkpoint exceeds iterationLimit entries (the combined backward and fast-forward limits).
    func state(at target: AUMHash, iterationLimit: Int) throws(TKAError) -> AuthorityState {
        var path: [Int] = []
        var cursor = target
        while true {
            guard path.count < iterationLimit else { throw .iterationLimit }
            guard let position = positions[cursor] else { throw .missingParent }
            let aum = aums[position]
            if aum.messageKind == AUM.Kind.checkpoint, var state = aum.state {
                state.lastAUMHash = cursor
                for position in path.reversed() {
                    state = try state.applying(aums[position], hash: hashes[position])
                }
                return state
            }
            // The root is a checkpoint, so traversal does not reach a parentless AUM.
            guard let parent = aum.parentHash else { throw .missingParent }
            path.append(position)
            cursor = parent
        }
    }
}

extension AUM {
    /// A 32-byte parent hash. Every stored non-root AUM has one because application checks byte equality.
    var parentHash: AUMHash? { prevAUMHash.flatMap(AUMHash.init) }
}
