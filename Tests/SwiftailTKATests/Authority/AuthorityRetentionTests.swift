import Testing

@testable import SwiftailTKA

/// Contract §5 TL-11a item 1: Apply limits (4,096 AUMs and 16MiB) to the active chain. If all retained AUMs exceed a limit, discard the newest admissions
/// outside the active chain first. The byte limit reaches the boundary with a few dozen AUMs: a checkpoint with 512 keys filled with `Meta` is about 280KiB.
@Suite("Signing authority state machine: pruning AUMs outside the active chain")
struct AuthorityRetentionTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()

    /// A state filled with 512 keys: `trusted` plus random keys filled with `Meta`.
    static func largeState(_ trusted: [TrustedKey], seed: UInt64) -> AuthorityState {
        var random = CBORTesting.Random(state: seed)
        let meta = [MetaEntry(key: Array("m".utf8), value: Array(repeating: UInt8(ascii: "x"), count: 511))]
        var keys = trusted
        while keys.count < AuthorityState.maximumKeyCount {
            let publicKey = (0..<32).map { _ in UInt8.random(in: 0...255, using: &random) }
            keys.append(TrustedKey(kind: 1, votes: 1, publicKey: publicKey, meta: meta))
        }
        return T.checkpointState(keys)
    }

    /// Links `count` checkpoints from `parent`.
    static func checkpointChain(_ state: AuthorityState, after parent: AUMHash, count: Int, by signers: [T.Signer]) -> [AUM] {
        var chain: [AUM] = []
        var parent = parent
        for _ in 0..<count {
            let next = T.checkpoint(state, parent: parent, by: signers)
            chain.append(next)
            parent = next.hash
        }
        return chain
    }

    static func expectReopens(_ authority: Authority, sourceLocation: SourceLocation = #_sourceLocation) throws {
        let stored = try authority.aums.map { aum throws(TKAError) in try AUM(decoding: aum.serialized()) }
        let reopened = try Authority(opening: stored, bootstrap: authority.bootstrap)
        #expect(reopened.head == authority.head && reopened.state == authority.state, sourceLocation: sourceLocation)
        #expect(Set(reopened.hashes) == Set(authority.hashes), sourceLocation: sourceLocation)
    }

    /// Admits a group of 60 sibling checkpoints off the root (over 16MiB combined) and follows the subsequent RemoveKey and checkpoint.
    /// Go retains them all because it has no retention count limit. The head (the sibling with the smallest hash because the weight and kind match) and state match.
    @Test func inactiveSiblingsAreDiscardedAndRemovalStillApplies() throws {
        let state = Self.largeState([a.trusted(), b.trusted()], seed: 21)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        let siblings = (0..<60).map { _ in T.checkpoint(state, parent: authority.head, by: [a]) }
        #expect(T.byteCount(authority.aums + siblings) > Authority.maximumByteCount)
        try authority.inform(siblings)

        let winner = try #require(siblings.min { $0.hash.bytes.lexicographicallyPrecedes($1.hash.bytes) })
        #expect(authority.head == winner.hash)
        #expect(T.byteCount(authority.aums) <= Authority.maximumByteCount)
        // Later admissions were discarded first. All retained losing siblings preceded the discarded ones. The winning sibling remains regardless of position.
        let kept = Set(authority.hashes)
        let keptLosers = siblings.indices.filter { kept.contains(siblings[$0].hash) && siblings[$0] != winner }
        let discarded = siblings.indices.filter { !kept.contains(siblings[$0].hash) }
        #expect(!discarded.isEmpty && (keptLosers.max() ?? -1) < (discarded.min() ?? 0))
        try Self.expectReopens(authority)

        // Remove b and include the resulting state in a checkpoint.
        let removal = T.removeKey(b.publicKey, after: authority.head, by: [a])
        var reduced = state
        reduced.keys.removeAll { $0.publicKey == b.publicKey }
        let checkpoint = T.checkpoint(reduced, parent: removal.hash, by: [a])
        try authority.inform([removal, checkpoint])
        #expect(authority.head == checkpoint.hash && authority.state.key(withID: b.publicKey) == nil)
        #expect(T.byteCount(authority.aums) <= Authority.maximumByteCount)
        #expect(T.activeChain(of: authority).map(\.hash) == [checkpoint.hash, removal.hash, winner.hash, authority.bootstrap])
        try Self.expectReopens(authority)
    }

    /// An AUM whose parent was discarded has an unknown parent. If a discarded AUM returns, admit it again. If the limit is still full,
    /// it is discarded again as the most recent admission, along with its reintroduced child. Neither affects the head or state.
    @Test func discardedAUMsAndTheirDescendants() throws {
        let state = Self.largeState([a.trusted()], seed: 22)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        let siblings = (0..<60).map { _ in T.checkpoint(state, parent: authority.head, by: [a]) }
        try authority.inform(siblings)
        let kept = Set(authority.hashes)
        let gone = try #require(siblings.last { !kept.contains($0.hash) })
        let child = T.noOp(after: gone.hash, by: [a])
        let before = authority

        #expect(T.informError(&authority, [child]) == .missingParent)
        // The room left after pruning is smaller than one sibling (they are all the same size), so the reintroduced sibling is discarded again.
        #expect(Authority.maximumByteCount - T.byteCount(authority.aums) < gone.serialized().count)
        try authority.inform([gone])
        #expect(Set(authority.hashes) == Set(before.hashes) && authority.head == before.head && authority.state == before.state)
        try authority.inform([gone, child])
        #expect(Set(authority.hashes) == Set(before.hashes) && authority.head == before.head && authority.state == before.state)
    }

    /// When the active chain changes within a group, measure the limit against the new active chain. The previously active chain becomes a losing branch and is pruned
    /// from its end. If the new active chain itself exceeds the limit, reject the entire group (unchanged behavior: no compaction).
    @Test func activeChainSwitchWithinABatch() throws {
        let c = T.Signer()
        let state = Self.largeState([a.trusted(), b.trusted(votes: 2), c.trusted(votes: 3)], seed: 23)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        let root = authority.head
        let old = Self.checkpointChain(state, after: root, count: 50, by: [a])
        try authority.inform(old)
        #expect(authority.head == old.last?.hash)

        // The chain started at the root by b (2 votes) beats a's chain (1 vote). The two together exceed 16MiB.
        let new = Self.checkpointChain(state, after: root, count: 10, by: [b])
        #expect(T.byteCount(authority.aums + new) > Authority.maximumByteCount)
        try authority.inform(new)
        #expect(authority.head == new.last?.hash)
        #expect(T.activeChain(of: authority).map(\.hash) == (new.reversed().map(\.hash) + [root]))
        #expect(T.byteCount(authority.aums) <= Authority.maximumByteCount)
        let kept = Set(authority.hashes)
        let keptOld = old.indices.filter { kept.contains(old[$0].hash) }
        #expect(keptOld == Array(old.indices.prefix(keptOld.count)) && keptOld.count < old.count, "Prunes the old chain starting at its end")
        try Self.expectReopens(authority)

        // The chain started at the root by c (3 votes) wins and itself exceeds 16MiB.
        let tooLong = Self.checkpointChain(state, after: root, count: 59, by: [c])
        #expect(T.byteCount([authority.aums[0]] + tooLong) > Authority.maximumByteCount)
        let before = authority
        #expect(T.informError(&authority, tooLong) == .limitExceeded)
        #expect(authority.aums == before.aums && authority.head == before.head && authority.state == before.state)
        // Admission succeeds when shortened to fit the limit.
        try authority.inform(Array(tooLong.prefix(20)))
        #expect(authority.head == tooLong[19].hash)
        try Self.expectReopens(authority)
    }
}
