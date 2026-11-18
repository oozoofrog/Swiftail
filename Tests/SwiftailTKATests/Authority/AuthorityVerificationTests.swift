import Testing

@testable import SwiftailTKA

/// Contract §7 test 5: verifying one AUM and applying it to state (behaviors A2–A7).
@Suite("Signing authority state machine: verification and application")
struct AuthorityVerificationTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()
    let stranger = T.Signer()
    /// A checkpoint that trusts keys a and b (1 vote each). Build it once because signatures are nondeterministic.
    let root: AUM

    init() {
        root = T.checkpoint(T.checkpointState([a.trusted(), b.trusted()]), by: [a])
    }

    func start() throws -> Authority {
        try Authority(bootstrappingWith: root)
    }

    /// Rejection leaves everything unchanged.
    func expectRejected(_ update: AUM, _ expected: TKAError, sourceLocation: SourceLocation = #_sourceLocation) throws {
        var authority = try start()
        let before = authority
        #expect(T.informError(&authority, [update]) == expected, sourceLocation: sourceLocation)
        #expect(authority.head == before.head && authority.aums == before.aums, sourceLocation: sourceLocation)
        #expect(authority.state == before.state, sourceLocation: sourceLocation)
    }

    @Test func unsigned() throws {
        try expectRejected(T.noOp(after: start().head, by: []), .unsigned)
    }

    @Test func untrustedSignatureMixedIn() throws {
        try expectRejected(T.noOp(after: start().head, by: [a, stranger]), .untrustedSigner)
    }

    @Test func wrongSignature() throws {
        var update = try T.noOp(after: start().head, by: [a])
        update.signatures[0].signature[10] ^= 1
        try expectRejected(update, .invalidSignature)
    }

    @Test("An AUM that repeats the same (KeyID, signature) 4,096 times keeps the same outcome and verifies only once", .timeLimit(.minutes(10)))
    func repeatedSignatureIsVerifiedOnce() throws {
        let single = try T.noOp(after: start().head, by: [a])
        var repeated = single
        repeated.signatures = Array(repeating: single.signatures[0], count: 4_096)

        // Outcome: accepted. The head is the hash of the bytes including repeated signatures, and the state matches admitting a single-signature AUM.
        var plain = try start()
        try plain.inform([single])
        var authority = try start()
        try authority.inform([repeated])
        #expect(authority.head == repeated.hash && repeated.hash != single.hash)
        #expect(authority.aums.last == repeated)
        var expected = plain.state
        expected.lastAUMHash = repeated.hash
        #expect(authority.state == expected)
        #expect(authority.state.weight(of: repeated) == 1)

        // Cost: 4,096 repetitions require one verification, and 64 distinct signatures require 64 verifications.
        var distinct = single
        distinct.signatures = (0..<64).map { _ in a.signature(over: single) }
        #expect(Set(distinct.signatures.map(\.signature)).count == 64)
        let state = try start().state
        #expect(try state.verifyParentAndSignatures(of: repeated, isBootstrap: false) == 1)
        #expect(try state.verifyParentAndSignatures(of: distinct, isBootstrap: false) == 64)
    }

    @Test("Skipping repeats still rejects invalid signatures and unknown keys")
    func repeatedSignatureDoesNotHideFailures() throws {
        let valid = try T.noOp(after: start().head, by: [a, a])
        var tampered = valid
        tampered.signatures[1].signature[10] ^= 1
        try expectRejected(tampered, .invalidSignature)

        var foreign = valid
        foreign.signatures[1] = stranger.signature(over: valid)
        try expectRejected(foreign, .untrustedSigner)

        // The same signature with a different KeyID forms a distinct pair.
        var relabelled = valid
        relabelled.signatures[1] = AUMSignature(keyID: b.publicKey, signature: valid.signatures[0].signature)
        try expectRejected(relabelled, .invalidSignature)
    }

    @Test func parentHashOf33Bytes() throws {
        let update = try T.signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: start().head.bytes + [0]), by: [a])
        try expectRejected(update, .rejectedUpdate)
    }

    @Test func addingAnExistingKey() throws {
        try expectRejected(T.addKey(b.trusted(votes: 3), after: start().head, by: [a]), .rejectedUpdate)
    }

    @Test func removingOrUpdatingAMissingKey() throws {
        let head = try start().head
        try expectRejected(T.removeKey(stranger.publicKey, after: head, by: [a]), .rejectedUpdate)
        let update = T.signed(
            AUM(messageKind: AUM.Kind.updateKey, prevAUMHash: head.bytes, keyID: stranger.publicKey, votes: 2), by: [a]
        )
        try expectRejected(update, .rejectedUpdate)
    }

    /// The updated key must pass key validation again (`Votes` 0).
    @Test func updatingVotesToZero() throws {
        let update = try T.signed(
            AUM(messageKind: AUM.Kind.updateKey, prevAUMHash: start().head.bytes, keyID: b.publicKey, votes: 0), by: [a]
        )
        try expectRejected(update, .rejectedUpdate)
    }

    @Test func removingTheLastKey() throws {
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        #expect(T.informError(&authority, [T.removeKey(a.publicKey, after: authority.head, by: [a])]) == .rejectedUpdate)
        // With two keys, the signer can remove its own key.
        var two = try start()
        try two.inform([T.removeKey(a.publicKey, after: two.head, by: [a])])
        #expect(two.state.keys == [b.trusted()])
    }

    @Test func checkpointWithAnotherStateID() throws {
        let state = T.checkpointState([a.trusted(), b.trusted()], stateID1: 9)
        try expectRejected(T.checkpoint(state, parent: start().head, by: [a]), .rejectedUpdate)
    }

    @Test func staticallyInvalidUpdate() throws {
        let update = try T.signed(
            AUM(messageKind: AUM.Kind.addKey, prevAUMHash: start().head.bytes, key: stranger.trusted(), keyID: [1]),
            by: [a]
        )
        try expectRejected(update, .invalidAUM)
    }

    /// Kind 0 (`AUMInvalid`) and unknown kinds are accepted with valid signatures, advance the head, and preserve state (decision L10).
    @Test(arguments: [UInt8(0), 9, 255])
    func unknownKindsMoveTheHead(kind: UInt8) throws {
        var authority = try start()
        let keys = authority.state.keys
        let update = T.signed(AUM(messageKind: kind, prevAUMHash: authority.head.bytes), by: [b])
        try authority.inform([update])
        #expect(authority.head == update.hash)
        #expect(authority.state.keys == keys && authority.state.lastAUMHash == update.hash)
    }

    /// RemoveKey at a parentless position fails admission for a missing parent and bootstrap for a non-checkpoint.
    @Test func parentlessRemoveKey() throws {
        let update = T.signed(AUM(messageKind: AUM.Kind.removeKey, prevAUMHash: nil, keyID: b.publicKey), by: [a])
        try expectRejected(update, .missingParent)
        #expect(throws: TKAError.notACheckpoint) { try Authority(bootstrappingWith: update) }
    }

    /// There is no voting threshold: one signature from a 1-vote key changes a state with a 4,096-vote key (behavior A4).
    @Test func oneTrustedSignatureIsEnough() throws {
        var authority = try Authority(
            bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted(), b.trusted(votes: 4_096)]), by: [b])
        )
        try authority.inform([T.removeKey(b.publicKey, after: authority.head, by: [a])])
        #expect(authority.state.keys == [a.trusted()])
    }

    /// Applying AddKey appends at the end, UpdateKey changes `Votes` and `Meta`, and RemoveKey removes the key while preserving order.
    @Test func applyingKeyChanges() throws {
        var authority = try start()
        let c = T.Signer()
        try authority.inform([T.addKey(c.trusted(votes: 2), after: authority.head, by: [a])])
        #expect(authority.state.keys == [a.trusted(), b.trusted(), c.trusted(votes: 2)])

        let meta = [MetaEntry(key: Array("k".utf8), value: Array("v".utf8))]
        try authority.inform([
            T.signed(
                AUM(messageKind: AUM.Kind.updateKey, prevAUMHash: authority.head.bytes, keyID: a.publicKey, votes: 7, meta: meta),
                by: [c]
            )
        ])
        var updated = a.trusted(votes: 7)
        updated.meta = meta
        #expect(authority.state.keys == [updated, b.trusted(), c.trusted(votes: 2)])

        try authority.inform([T.removeKey(b.publicKey, after: authority.head, by: [c])])
        #expect(authority.state.keys == [updated, c.trusted(votes: 2)])
        // Signatures from a removed key are no longer accepted.
        #expect(T.informError(&authority, [T.noOp(after: authority.head, by: [b])]) == .untrustedSigner)
    }
}
