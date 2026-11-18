import Testing

@testable import SwiftailTKA

/// Contract §7 test 8: bootstrap (behavior F5) and reopening (behavior F6, decision L14, §5 TL-11a item 2).
@Suite("Signing authority state machine: bootstrap and reopening")
struct AuthorityBootstrapTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()

    var rootState: AuthorityState { T.checkpointState([a.trusted(), b.trusted(votes: 2)]) }

    /// A forked chain: root → x1 → x2 (a), x1 → y2 (b, wins) → y3, plus one checkpoint.
    func grown() throws -> Authority {
        var authority = try Authority(bootstrappingWith: T.checkpoint(rootState, by: [a]))
        let x1 = T.noOp(after: authority.head, by: [a])
        let x2 = T.noOp(after: x1.hash, by: [a])
        let y2 = T.noOp(after: x1.hash, by: [b])
        let checkpoint = T.checkpoint(rootState, parent: y2.hash, by: [b])
        let y3 = T.addKey(T.Signer().trusted(), after: checkpoint.hash, by: [a])
        try authority.inform([x1, x2, y2, checkpoint, y3])
        #expect(authority.head == y3.hash)
        return authority
    }

    @Test func bootstrapNeedsACheckpoint() throws {
        let noOp = T.signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: nil), by: [a])
        #expect(throws: TKAError.notACheckpoint) { try Authority(bootstrappingWith: noOp) }
        let stateless = T.signed(AUM(messageKind: AUM.Kind.checkpoint, prevAUMHash: nil), by: [a])
        #expect(throws: TKAError.notACheckpoint) { try Authority(bootstrappingWith: stateless) }
    }

    /// A checkpoint must be signed by a key in its own state.
    @Test func bootstrapVerifiesAgainstItsOwnState() throws {
        #expect(throws: TKAError.untrustedSigner) {
            try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [b]))
        }
        #expect(throws: TKAError.unsigned) {
            try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: []))
        }
        var tampered = T.checkpoint(rootState, by: [a])
        tampered.signatures[0].signature[5] ^= 1
        #expect(throws: TKAError.invalidSignature) { try Authority(bootstrappingWith: tampered) }
    }

    /// Also bootstraps from a later, non-genesis checkpoint with a parent hash (note §8.2).
    @Test func bootstrapFromALaterCheckpoint() throws {
        let parent = try #require(AUMHash(Array(repeating: 3, count: 32)))
        let checkpoint = T.checkpoint(rootState, parent: parent, by: [b])
        var authority = try Authority(bootstrappingWith: checkpoint)
        #expect(authority.head == checkpoint.hash && authority.bootstrap == checkpoint.hash)
        #expect(authority.state.keys == rootState.keys && authority.state.lastAUMHash == checkpoint.hash)
        try authority.inform([T.noOp(after: authority.head, by: [a])])
        let reopened = try Authority(opening: authority.aums, bootstrap: authority.bootstrap)
        #expect(reopened.head == authority.head)
    }

    /// Reopening saved data yields the same head and state, even when storage order changes.
    @Test func reopeningGivesTheSameHeadAndState() throws {
        let authority = try grown()
        for stored in [authority.aums, authority.aums.reversed(), authority.aums.shuffled()] {
            let reopened = try Authority(opening: stored, bootstrap: authority.bootstrap)
            #expect(reopened.head == authority.head && reopened.state == authority.state)
            #expect(Set(reopened.aums.map(\.hash)) == Set(authority.aums.map(\.hash)))
            #expect(reopened.syncOffer() == authority.syncOffer())
        }
    }

    @Test func storeWithTwoRoots() throws {
        let authority = try grown()
        let other = T.checkpoint(T.checkpointState([b.trusted()]), by: [b])
        #expect(throws: TKAError.corruptStore) { try Authority(opening: authority.aums + [other], bootstrap: authority.bootstrap) }
    }

    @Test func storeWithAMissingParent() throws {
        let authority = try grown()
        var stored = authority.aums
        stored.remove(at: 1)
        #expect(throws: TKAError.corruptStore) { try Authority(opening: stored, bootstrap: authority.bootstrap) }
    }

    @Test func storeWithAChangedSignature() throws {
        let authority = try grown()
        var stored = authority.aums
        stored[stored.count - 1].signatures[0].signature[1] ^= 1
        #expect(throws: TKAError.invalidSignature) { try Authority(opening: stored, bootstrap: authority.bootstrap) }
    }

    /// An UpdateKey with only empty `Meta` (`07a0`) passes static validation on acceptance and fails after saving and reading canonical bytes. Reopening
    /// skips static validation, so it opens with the same head and state (TL-11a item 2, Go `Open` also opens it).
    @Test func emptyMetaUpdateKeyReopens() throws {
        var authority = try grown()
        let update = T.signed(
            AUM(messageKind: AUM.Kind.updateKey, prevAUMHash: authority.head.bytes, keyID: b.publicKey, meta: []), by: [a]
        )
        try authority.inform([update, T.noOp(after: update.hash, by: [b])])
        let stored = try authority.aums.map { aum throws(TKAError) in try AUM(decoding: aum.serialized()) }
        #expect(throws: TKAError.invalidAUM) { try stored.first { $0.hash == update.hash }?.validate() }
        let reopened = try Authority(opening: stored, bootstrap: authority.bootstrap)
        #expect(reopened.head == authority.head && reopened.state == authority.state)
        // Storage with an altered signature is still rejected. The check from `storeWithAChangedSignature` also applies to this AUM.
        var tampered = stored
        let index = try #require(tampered.firstIndex { $0.hash == update.hash })
        tampered[index].signatures[0].signature[1] ^= 1
        #expect(throws: TKAError.invalidSignature) { try Authority(opening: tampered, bootstrap: authority.bootstrap) }
    }

    /// If storage contains an AUM signed by a trusted key that fails static validation (AddKey with key `Votes` over 4,096), reopening follows Go `Open`
    /// and selects the branch using that state. Weights wrap like Go `uint` (the sum of two 2^64−1 votes is 2^64−2, which beats 1 vote). It does not trap.
    @Test func storeWithAStaticallyInvalidButSignedAUM() throws {
        let heavy1 = T.Signer()
        let heavy2 = T.Signer()
        let root = T.checkpoint(T.checkpointState([a.trusted()]), by: [a])
        let add1 = T.addKey(heavy1.trusted(votes: .max), after: root.hash, by: [a])
        let add2 = T.addKey(heavy2.trusted(votes: .max), after: add1.hash, by: [a])
        #expect(throws: TKAError.invalidAUM) { try add1.validate() }
        let heavyChild = T.noOp(after: add2.hash, by: [heavy1, heavy2])
        let lightChild = T.noOp(after: add2.hash, by: [a])
        let reopened = try Authority(opening: [root, add1, add2, lightChild, heavyChild], bootstrap: root.hash)
        #expect(reopened.head == heavyChild.hash)
        #expect(reopened.state.weight(of: heavyChild) == UInt64.max &+ UInt64.max)
        // It cannot enter through the acceptance path.
        var informed = try Authority(bootstrappingWith: root)
        #expect(T.informError(&informed, [add1]) == .invalidAUM)
    }

    @Test func storeWithoutItsRootOrWithDuplicates() throws {
        let authority = try grown()
        // If the recorded root is a checkpoint in the middle of a chain, earlier AUMs are unreachable. A non-checkpoint is rejected at bootstrap.
        let checkpoint = authority.aums[4]
        #expect(checkpoint.messageKind == AUM.Kind.checkpoint)
        #expect(throws: TKAError.corruptStore) { try Authority(opening: authority.aums, bootstrap: checkpoint.hash) }
        #expect(throws: TKAError.notACheckpoint) { try Authority(opening: authority.aums, bootstrap: authority.head) }
        #expect(throws: TKAError.corruptStore) { try Authority(opening: Array(authority.aums.dropFirst()), bootstrap: authority.bootstrap) }
        #expect(throws: TKAError.corruptStore) { try Authority(opening: authority.aums + [authority.aums[2]], bootstrap: authority.bootstrap) }
        #expect(throws: TKAError.corruptStore) { try Authority(opening: [], bootstrap: authority.bootstrap) }
    }

    /// The store's AUM count limit (4,096) is checked before verification.
    @Test func storeOverTheCountLimit() throws {
        let authority = try grown()
        let stored = Array(repeating: authority.aums[1], count: Authority.maximumAUMCount + 1)
        #expect(throws: TKAError.limitExceeded) { try Authority(opening: stored, bootstrap: authority.bootstrap) }
    }
}
