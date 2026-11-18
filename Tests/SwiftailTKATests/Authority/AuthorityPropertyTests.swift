import Testing

@testable import SwiftailTKA

/// Admission properties (order-independent head, readmission, and reopening), limit boundaries (behaviors F7 and M), and malformed input.
@Suite("Signing authority state machine: properties and limits")
struct AuthorityPropertyTests {
    typealias T = AuthorityTesting

    /// An AUM tree with several branches and key additions and removals. `updates` is in creation order (parents first).
    struct Tree {
        let root: AUM
        let updates: [AUM]
        /// The result of admitting `updates` one at a time in creation order.
        let reference: Authority
    }

    static func randomTree(count: Int, random: inout CBORTesting.Random) throws -> Tree {
        var signers = (0..<3).map { _ in T.Signer() }
        let keys = signers.enumerated().map { $1.trusted(votes: UInt64($0 + 1)) }
        let root = T.checkpoint(T.checkpointState(keys), by: [signers[0]])
        var builder = try Authority(bootstrappingWith: root)
        var updates: [AUM] = []
        while updates.count < count {
            let parent = try #require(builder.hashes.randomElement(using: &random))
            let state = try builder.state(at: parent, iterationLimit: Authority.maximumScanIterations)
            let trusted = signers.filter { state.key(withID: $0.publicKey) != nil }
            var chosen = trusted.filter { _ in Bool.random(using: &random) }
            if chosen.isEmpty { chosen = [try #require(trusted.first)] }

            let update: AUM
            switch Int.random(in: 0..<4, using: &random) {
            case 0 where state.keys.count > 1:
                let removed = try #require(state.keys.randomElement(using: &random)?.publicKey)
                update = T.removeKey(removed, after: parent, by: chosen)
            case 1:
                let added = T.Signer()
                signers.append(added)
                update = T.addKey(added.trusted(votes: UInt64.random(in: 1...3, using: &random)), after: parent, by: chosen)
            default:
                update = T.noOp(after: parent, by: chosen)
            }
            try builder.inform([update])
            updates.append(update)
        }
        return Tree(root: root, updates: updates, reference: builder)
    }

    /// A random order with parents first.
    static func parentFirstOrder(_ updates: [AUM], root: AUMHash, random: inout CBORTesting.Random) -> [AUM] {
        var placed: Set<AUMHash> = [root]
        var remaining = updates
        var order: [AUM] = []
        while let pick = remaining.indices.filter({ remaining[$0].parentHash.map(placed.contains) ?? false })
            .randomElement(using: &random)
        {
            let update = remaining.remove(at: pick)
            placed.insert(update.hash)
            order.append(update)
        }
        return order
    }

    static func expectSame(_ authority: Authority, _ reference: Authority, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(authority.head == reference.head, sourceLocation: sourceLocation)
        #expect(authority.state == reference.state, sourceLocation: sourceLocation)
        #expect(Set(authority.hashes) == Set(reference.hashes), sourceLocation: sourceLocation)
    }

    /// Admitting the same set of AUMs in any parent-first order and with any grouping yields the same head and state.
    @Test(arguments: [UInt64(1), 2, 3])
    func headDoesNotDependOnOrder(seed: UInt64) throws {
        var random = CBORTesting.Random(state: seed)
        let tree = try Self.randomTree(count: 40, random: &random)
        for _ in 0..<4 {
            var authority = try Authority(bootstrappingWith: tree.root)
            var order = Self.parentFirstOrder(tree.updates, root: authority.bootstrap, random: &random)[...]
            #expect(order.count == tree.updates.count)
            while !order.isEmpty {
                let size = Int.random(in: 1...6, using: &random)
                try authority.inform(Array(order.prefix(size)))
                order = order.dropFirst(size)
            }
            Self.expectSame(authority, tree.reference)
        }
    }

    /// Readmitting any subset of retained AUMs preserves the state, and reopening yields the same head and state.
    @Test func reinformingAndReopening() throws {
        var random = CBORTesting.Random(state: 7)
        let tree = try Self.randomTree(count: 30, random: &random)
        var authority = tree.reference
        for _ in 0..<5 {
            let subset = tree.updates.filter { _ in Bool.random(using: &random) } + [tree.updates[0]]
            try authority.inform(subset.shuffled(using: &random))
            Self.expectSame(authority, tree.reference)
            #expect(authority.aums == tree.reference.aums)
        }
        let reopened = try Authority(opening: tree.reference.aums.shuffled(using: &random), bootstrap: tree.reference.bootstrap)
        Self.expectSame(reopened, tree.reference)
    }

    /// The limit on AUMs per admission (4,096) is checked before verification.
    @Test func batchCountLimit() throws {
        let a = T.Signer()
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        let update = T.noOp(after: authority.head, by: [a])
        #expect(T.informError(&authority, Array(repeating: update, count: Authority.maximumBatchCount + 1)) == .limitExceeded)
        try authority.inform(Array(repeating: update, count: Authority.maximumBatchCount))
        #expect(authority.aums.count == 2)
    }

    /// Boundaries of the backward search for parent state (2,000 AUMs including the checkpoint) and of retained AUM count (4,096).
    @Test func scanAndCountLimits() throws {
        let a = T.Signer()
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        // N1…N2001 follow the root. Admission along the head chain does not look up parent state.
        let chain = T.noOpChain(after: authority.head, count: 2_001, by: a)
        try authority.inform(chain)
        #expect(authority.head == chain[2_000].hash)

        // A child of N2000 (which is not the head): N2000…N1 and root, 2,001 AUMs → over the limit. A child of N1999: 2,000 → accepted.
        #expect(T.informError(&authority, [T.noOp(after: chain[1_999].hash, by: [a])]) == .iterationLimit)
        try authority.inform([T.noOp(after: chain[1_998].hash, by: [a])])
        #expect(authority.aums.count == 2_003)

        // Fill the active chain to 4,096. The total retained count exceeds the limit, so discard AUMs outside the active chain (branches, TL-11a item 1).
        let active = T.activeChain(of: authority).count
        let rest = T.noOpChain(after: authority.head, count: Authority.maximumAUMCount - active, by: a)
        #expect(authority.aums.count + rest.count > Authority.maximumAUMCount)
        try authority.inform(rest)
        #expect(authority.aums.count == Authority.maximumAUMCount)
        #expect(T.activeChain(of: authority).count == Authority.maximumAUMCount)
        // Reject an entire group if the active chain exceeds the limit.
        let before = authority
        #expect(T.informError(&authority, [T.noOp(after: authority.head, by: [a])]) == .limitExceeded)
        #expect(authority.aums == before.aums && authority.head == before.head)
        // A group containing only retained AUMs does not hit the limit.
        try authority.inform([rest[0]])
    }

    /// Group admission matches admitting the same AUMs separately: outcome (first error), head, state, and retained AUMs. A failed group changes
    /// nothing. Individual admission always looks up parent state in storage again, which checks that releasing state no longer needed as a parent
    /// within the group (TL-11a item 4) preserves the outcome. The group mixes repeated AUMs and rejected AUMs.
    @Test(arguments: [UInt64(4), 5, 6])
    func batchMatchesOneByOne(seed: UInt64) throws {
        var random = CBORTesting.Random(state: seed)
        let tree = try Self.randomTree(count: 60, random: &random)
        let stranger = T.Signer()
        let start = try Authority(bootstrappingWith: tree.root)
        for round in 0..<8 {
            var batch = Self.parentFirstOrder(tree.updates, root: start.bootstrap, random: &random)
            for _ in 0..<Int.random(in: 0...8, using: &random) {
                let repeated = try #require(batch.randomElement(using: &random))
                batch.insert(repeated, at: Int.random(in: 0...batch.count, using: &random))
            }
            if round % 2 == 1 {
                // An AUM whose parent is in the group has a signature from an unknown key. The group fails there.
                let parent = try #require(batch.randomElement(using: &random)).hash
                batch.insert(T.noOp(after: parent, by: [stranger]), at: Int.random(in: 0...batch.count, using: &random))
            }

            var batched = start
            let batchError = T.informError(&batched, batch)
            var single = start
            var singleError: TKAError?
            for update in batch {
                singleError = T.informError(&single, [update])
                if singleError != nil { break }
            }
            #expect(batchError == singleError, "Group \(round)")
            if batchError == nil {
                Self.expectSame(batched, single)
                Self.expectSame(batched, tree.reference)
            } else {
                Self.expectSame(batched, start)
            }
        }
    }

    /// Limit on the total canonical bytes of retained AUMs (16MiB). Link checkpoints (about 280KiB each) with 512 keys filled with `Meta`.
    @Test func byteLimit() throws {
        let a = T.Signer()
        var random = CBORTesting.Random(state: 11)
        let meta = [MetaEntry(key: Array("m".utf8), value: Array(repeating: UInt8(ascii: "x"), count: 511))]
        var keys = [a.trusted()]
        while keys.count < AuthorityState.maximumKeyCount {
            let publicKey = (0..<32).map { _ in UInt8.random(in: 0...255, using: &random) }
            keys.append(TrustedKey(kind: 1, votes: 1, publicKey: publicKey, meta: meta))
        }
        let state = T.checkpointState(keys)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        var total = authority.aums[0].serialized().count
        while true {
            let next = T.checkpoint(state, parent: authority.head, by: [a])
            let count = next.serialized().count
            let before = authority
            if let error = T.informError(&authority, [next]) {
                #expect(error == .limitExceeded)
                #expect(total + count > Authority.maximumByteCount)
                #expect(authority.aums == before.aums && authority.head == before.head)
                #expect(throws: TKAError.limitExceeded) {
                    try Authority(opening: authority.aums + [next], bootstrap: authority.bootstrap)
                }
                break
            }
            total += count
            #expect(total <= Authority.maximumByteCount)
        }
        #expect(authority.aums.count > 50)
    }

    /// Corrupting the bytes of an AUM under admission one at a time does not crash, and only AUMs with the same canonical form are accepted.
    @Test func corruptedBytesAreRejected() throws {
        let a = T.Signer()
        let authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        let original = T.addKey(T.Signer().trusted(votes: 3), after: authority.head, by: [a])
        let bytes = original.serialized()
        for index in bytes.indices {
            for flip in [UInt8(0x01), 0x80, 0xff] {
                var corrupted = bytes
                corrupted[index] ^= flip
                guard let update = try? AUM(decoding: corrupted) else { continue }
                var copy = authority
                if T.informError(&copy, [update]) == nil {
                    #expect(update.hash == original.hash, "Byte \(index) with \(flip)")
                }
            }
        }
    }
}
