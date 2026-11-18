import Testing

@testable import SwiftailTKA

/// Contract §7 tests 6 and 7: fork resolution (behavior F1) and admission (behavior F4).
@Suite("Signing authority state machine: forks and admission")
struct AuthorityChainTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()
    let c = T.Signer()

    func start(votes: (UInt64, UInt64, UInt64) = (1, 1, 1)) throws -> Authority {
        let keys = [a.trusted(votes: votes.0), b.trusted(votes: votes.1), c.trusted(votes: votes.2)]
        return try Authority(bootstrappingWith: T.checkpoint(T.checkpointState(keys), by: [a]))
    }

    /// Admitting `first` and `second` in either order gives `winner` as the head.
    func expectWinner(_ winner: AUM, among first: AUM, _ second: AUM, from authority: Authority) throws {
        for order in [[first, second], [second, first]] {
            var copy = authority
            for update in order { try copy.inform([update]) }
            #expect(copy.head == winner.hash)
        }
        var batch = authority
        try batch.inform([first, second])
        #expect(batch.head == winner.hash)
    }

    // MARK: Fork resolution (test 6)

    @Test func heavierSignatureWeightWins() throws {
        let authority = try start(votes: (1, 2, 1))
        let light = T.noOp(after: authority.head, by: [a])
        let heavy = T.noOp(after: authority.head, by: [b])
        try expectWinner(heavy, among: light, heavy, from: authority)
        // Two keys (1 vote + 1 vote) beat one key (1 vote).
        let both = T.noOp(after: authority.head, by: [a, c])
        try expectWinner(both, among: light, both, from: authority)
    }

    /// Two signatures from one key count once: a (2 votes) × 2 = 2 < c (3 votes). Counting both would win with 4.
    @Test func sameKeyCountsOnce() throws {
        let authority = try start(votes: (2, 1, 3))
        let twice = T.signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: authority.head.bytes), by: [a, a])
        #expect(twice.signatures.count == 2)
        let once = T.noOp(after: authority.head, by: [c])
        try expectWinner(once, among: twice, once, from: authority)
    }

    /// RemoveKey wins at equal weight. Choose hashes such that the other side would win on hash alone.
    @Test func removeKeyWinsATie() throws {
        let authority = try start()
        let noOp = T.noOp(after: authority.head, by: [a])
        var removal = T.removeKey(c.publicKey, after: authority.head, by: [b])
        while !noOp.hash.bytes.lexicographicallyPrecedes(removal.hash.bytes) {
            removal = T.removeKey(c.publicKey, after: authority.head, by: [b])
        }
        try expectWinner(removal, among: noOp, removal, from: authority)
    }

    @Test func smallerHashBreaksATie() throws {
        let authority = try start()
        let first = T.noOp(after: authority.head, by: [a])
        let second = T.noOp(after: authority.head, by: [b])
        let winner = first.hash.bytes.lexicographicallyPrecedes(second.hash.bytes) ? first : second
        try expectWinner(winner, among: first, second, from: authority)
    }

    /// A child on the losing branch leaves the head unchanged. A child on the winning branch becomes the head.
    @Test func losingBranchGrowsWithoutMovingTheHead() throws {
        var authority = try start(votes: (1, 2, 1))
        let winner = T.noOp(after: authority.head, by: [b])
        let loser = T.noOp(after: authority.head, by: [a])
        try authority.inform([winner, loser])
        let loserChain = T.noOpChain(after: loser.hash, count: 3, by: a)
        try authority.inform(loserChain)
        #expect(authority.head == winner.hash)
        #expect(authority.aums.count == 6)
        let next = T.noOp(after: winner.hash, by: [a])
        try authority.inform([next])
        #expect(authority.head == next.hash)
        // AUMs on the losing branch are verified against that branch's state. A key removed on that branch can no longer sign for it.
        let removal = T.removeKey(c.publicKey, after: loserChain[2].hash, by: [a])
        try authority.inform([removal])
        #expect(T.informError(&authority, [T.noOp(after: removal.hash, by: [c])]) == .untrustedSigner)
        #expect(authority.head == next.hash)
    }

    // MARK: Admission (test 7)

    @Test func emptyBatch() throws {
        var authority = try start()
        #expect(T.informError(&authority, []) == .emptyUpdate)
    }

    @Test func parentlessAndUnknownParent() throws {
        var authority = try start()
        let parentless = T.signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: nil), by: [a])
        #expect(T.informError(&authority, [parentless]) == .missingParent)
        let empty = T.signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: []), by: [a])
        #expect(T.informError(&authority, [empty]) == .missingParent)
        let unknown = try T.noOp(after: #require(AUMHash(Array(repeating: 7, count: 32))), by: [a])
        #expect(T.informError(&authority, [unknown]) == .missingParent)
        #expect(authority.aums.count == 1)
    }

    @Test func alreadyHeldAUMsAreSkipped() throws {
        var authority = try start()
        let update = T.noOp(after: authority.head, by: [a])
        try authority.inform([update])
        let before = authority
        try authority.inform([update])
        try authority.inform([update, update])
        #expect(authority.aums == before.aums && authority.head == before.head && authority.state == before.state)
        // When a new AUM follows one already retained, only the new AUM is added.
        let next = T.noOp(after: update.hash, by: [b])
        try authority.inform([update, next])
        #expect(authority.aums.count == 3 && authority.head == next.hash)
    }

    /// If any member of the group is invalid, the entire group is rejected, including preceding members.
    @Test func oneBadUpdateRejectsTheBatch() throws {
        var authority = try start()
        let chain = T.noOpChain(after: authority.head, count: 3, by: a)
        let bad = T.noOp(after: chain[2].hash, by: [])
        let before = authority
        #expect(T.informError(&authority, chain + [bad]) == .unsigned)
        #expect(T.informError(&authority, [bad] + chain) == .missingParent)
        var tampered = chain
        tampered[1].signatures[0].signature[0] ^= 0x80
        #expect(T.informError(&authority, tampered) == .invalidSignature)
        #expect(authority.aums == before.aums && authority.head == before.head && authority.state == before.state)
        try authority.inform(chain)
        #expect(authority.head == chain[2].hash)
    }

    /// Processes in received order without sorting.
    @Test func outOfOrderBatch() throws {
        var authority = try start()
        let chain = T.noOpChain(after: authority.head, count: 2, by: a)
        #expect(T.informError(&authority, chain.reversed()) == .missingParent)
        try authority.inform(chain)
        #expect(authority.head == chain[1].hash)
    }

    /// A group that creates a fork uses the fork resolution rule to select the head even when the losing branch is longer.
    @Test func batchThatForks() throws {
        var authority = try start(votes: (1, 3, 1))
        let heavy = T.noOp(after: authority.head, by: [b])
        let light = T.noOp(after: authority.head, by: [a])
        let lightChain = T.noOpChain(after: light.hash, count: 4, by: a)
        try authority.inform([light] + lightChain + [heavy])
        #expect(authority.head == heavy.hash)
        #expect(authority.aums.count == 7)
    }
}
