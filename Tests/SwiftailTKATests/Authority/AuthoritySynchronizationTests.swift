import Testing

@testable import SwiftailTKA

/// Contract §7 test 9: synchronization calculation (behaviors Y1 and Y4). `sync`/`long` in `tka-fixtures.json` compares the 1,000 and 2,000 boundaries with Go.
@Suite("Signing authority state machine: synchronization calculation")
struct AuthoritySynchronizationTests {
    typealias T = AuthorityTesting

    let a = T.Signer()

    func start() throws -> Authority {
        try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
    }

    /// Ancestor list: the root alone if there are no checkpoints, otherwise checkpoint hashes from newest to oldest followed by the root.
    @Test func offerAncestors() throws {
        var authority = try start()
        #expect(authority.syncOffer() == SyncOffer(head: authority.bootstrap, ancestors: [authority.bootstrap]))
        let state = T.checkpointState([a.trusted()])
        var checkpoints: [AUMHash] = []
        for _ in 0..<2 {
            let noOp = T.noOp(after: authority.head, by: [a])
            let checkpoint = T.checkpoint(state, parent: noOp.hash, by: [a])
            try authority.inform([noOp, checkpoint])
            checkpoints.insert(checkpoint.hash, at: 0)
            #expect(authority.syncOffer().ancestors == checkpoints + [authority.bootstrap])
        }
        try authority.inform([T.noOp(after: authority.head, by: [a])])
        #expect(authority.syncOffer() == SyncOffer(head: authority.head, ancestors: checkpoints + [authority.bootstrap]))
    }

    @Test func sameHeadNeedsNothing() throws {
        var authority = try start()
        try authority.inform(T.noOpChain(after: authority.head, count: 2, by: a))
        #expect(try authority.missingAUMs(for: authority.syncOffer()).isEmpty)
    }

    /// Head intersection: if the peer's head is on the local chain, send what follows it.
    @Test func headIntersection() throws {
        let root = try start()
        let chain = T.noOpChain(after: root.head, count: 5, by: a)
        var remote = root
        try remote.inform(Array(chain.prefix(2)))
        var local = root
        try local.inform(chain)
        #expect(try local.missingAUMs(for: remote.syncOffer()) == Array(chain.dropFirst(2)))
        // The side that is behind does not know the peer's head, so it sends its chain from the tail intersection (the root), as in Go `basic/behind`.
        #expect(try remote.missingAUMs(for: local.syncOffer()) == Array(chain.prefix(2)))
        try remote.inform(local.missingAUMs(for: remote.syncOffer()))
        #expect(remote.head == local.head)
    }

    /// Tail intersection: peers on different branches send their own active chains starting after the common ancestor and omit losing branches.
    @Test func tailIntersection() throws {
        let b = T.Signer()
        var root = try Authority(
            bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted(), b.trusted(votes: 2)]), by: [a])
        )
        let shared = T.noOp(after: root.head, by: [a])
        try root.inform([shared])
        let ours = T.noOpChain(after: shared.hash, count: 2, by: a)
        let theirs = T.noOp(after: shared.hash, by: [b])
        var local = root
        try local.inform(ours)
        var remote = root
        try remote.inform([theirs])
        #expect(try local.missingAUMs(for: remote.syncOffer()) == [shared] + ours)
        #expect(try remote.missingAUMs(for: local.syncOffer()) == [shared, theirs])

        // After mutual receipt, both converge on the same head (b's 2 votes win). The local side retains the peer's head on a losing branch.
        let toRemote = try local.missingAUMs(for: remote.syncOffer())
        let toLocal = try remote.missingAUMs(for: local.syncOffer())
        try local.inform(toLocal)
        try remote.inform(toRemote)
        #expect(local.head == theirs.hash && remote.head == theirs.hash)
    }

    @Test func noIntersection() throws {
        let local = try start()
        let unknown = try #require(AUMHash(Array(repeating: 9, count: 32)))
        #expect(throws: TKAError.noIntersection) {
            try local.missingAUMs(for: SyncOffer(head: unknown, ancestors: [unknown]))
        }
        #expect(throws: TKAError.noIntersection) { try local.missingAUMs(for: SyncOffer(head: unknown, ancestors: [])) }
    }

    /// Checks only the first 1,001 distinct peer ancestors (TL-11a item 3). Repeated ancestors do not count, and an intersection at 1,002 is
    /// missed. Ancestors unknown locally also count.
    @Test func remoteAncestorsAreDeduplicatedAndCapped() throws {
        var authority = try start()
        let chain = T.noOpChain(after: authority.head, count: 2, by: a)
        try authority.inform(chain)
        let unknown = try #require(AUMHash(Array(repeating: 9, count: 32)))
        let fillers = try (0..<Authority.maximumSyncAncestorCount).map { index in
            try #require(AUMHash((0..<32).map { UInt8(truncatingIfNeeded: index >> ($0 % 4 * 8)) ^ UInt8($0) }))
        }
        #expect(Set(fillers).count == fillers.count && !fillers.contains(authority.bootstrap))
        #expect(Authority.maximumSyncAncestorCount == 1_001)

        let repeated = SyncOffer(head: unknown, ancestors: Array(repeating: unknown, count: 5_000) + [authority.bootstrap])
        #expect(try authority.missingAUMs(for: repeated) == chain)
        let atLimit = SyncOffer(head: unknown, ancestors: Array(fillers.dropLast()) + [authority.bootstrap])
        #expect(try authority.missingAUMs(for: atLimit) == chain)
        let pastLimit = SyncOffer(head: unknown, ancestors: fillers + [authority.bootstrap])
        #expect(throws: TKAError.noIntersection) { try authority.missingAUMs(for: pastLimit) }
        // Counts only distinct ancestors even with duplicates interleaved.
        let mixed = SyncOffer(head: unknown, ancestors: fillers.dropLast().flatMap { [$0, $0] } + [authority.bootstrap])
        #expect(try authority.missingAUMs(for: mixed) == chain)
    }

    /// Iteration limit boundary: a path including the checkpoint can reach the limit count, as counted by Go `computeStateAt` and `fastForward`.
    @Test func iterationLimitBoundaries() throws {
        var authority = try start()
        let chain = T.noOpChain(after: authority.head, count: 5, by: a)
        try authority.inform(chain)
        let tip = try #require(chain.last?.hash)
        #expect(throws: Never.self) { try authority.state(at: tip, iterationLimit: 6) }
        #expect(throws: TKAError.iterationLimit) { try authority.state(at: tip, iterationLimit: 5) }

        let rootState = try authority.state(at: authority.bootstrap, iterationLimit: 1)
        #expect(throws: Never.self) {
            try authority.fastForward(from: authority.bootstrap, state: rootState, iterationLimit: 6) { _ in false }
        }
        #expect(throws: TKAError.iterationLimit) {
            try authority.fastForward(from: authority.bootstrap, state: rootState, iterationLimit: 5) { _ in false }
        }
        #expect(Authority.maximumScanIterations == 2_000 && Authority.maximumSyncIterations == 2_000)
        #expect(Authority.maximumSyncHeadIntersectionIterations == 1_000)
    }
}
