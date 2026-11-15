import Testing

@testable import SwiftailTKA

/// 계약 7절 시험 5: AUM 하나의 검증과 상태 적용(동작 A2~A7).
@Suite("서명 권한 상태 기계: 검증과 적용")
struct AuthorityVerificationTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()
    let stranger = T.Signer()
    /// 키 a·b(각 1표)를 믿는 체크포인트. 서명이 결정적이지 않으므로 한 번 만들어 둔다.
    let root: AUM

    init() {
        root = T.checkpoint(T.checkpointState([a.trusted(), b.trusted()]), by: [a])
    }

    func start() throws -> Authority {
        try Authority(bootstrappingWith: root)
    }

    /// 거절되면 아무것도 바뀌지 않는다.
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

    /// 고친 키가 키 검사를 다시 통과해야 한다(`Votes` 0).
    @Test func updatingVotesToZero() throws {
        let update = try T.signed(
            AUM(messageKind: AUM.Kind.updateKey, prevAUMHash: start().head.bytes, keyID: b.publicKey, votes: 0), by: [a]
        )
        try expectRejected(update, .rejectedUpdate)
    }

    @Test func removingTheLastKey() throws {
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        #expect(T.informError(&authority, [T.removeKey(a.publicKey, after: authority.head, by: [a])]) == .rejectedUpdate)
        // 키가 둘이면 서명한 키 자신도 지울 수 있다.
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

    /// 종류 0(`AUMInvalid`)과 모르는 종류는 서명이 맞으면 받아들여지고 머리가 옮겨 가며 상태는 그대로다(결정 L10).
    @Test(arguments: [UInt8(0), 9, 255])
    func unknownKindsMoveTheHead(kind: UInt8) throws {
        var authority = try start()
        let keys = authority.state.keys
        let update = T.signed(AUM(messageKind: kind, prevAUMHash: authority.head.bytes), by: [b])
        try authority.inform([update])
        #expect(authority.head == update.hash)
        #expect(authority.state.keys == keys && authority.state.lastAUMHash == update.hash)
    }

    /// 부모 없는 자리의 RemoveKey: 들이기는 부모 없음으로, 부트스트랩은 체크포인트가 아님으로 거절한다.
    @Test func parentlessRemoveKey() throws {
        let update = T.signed(AUM(messageKind: AUM.Kind.removeKey, prevAUMHash: nil, keyID: b.publicKey), by: [a])
        try expectRejected(update, .missingParent)
        #expect(throws: TKAError.notACheckpoint) { try Authority(bootstrappingWith: update) }
    }

    /// 투표 문턱은 없다: 1표 키 하나의 서명으로 4,096표 키가 있는 상태를 바꾼다(동작 A4).
    @Test func oneTrustedSignatureIsEnough() throws {
        var authority = try Authority(
            bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted(), b.trusted(votes: 4_096)]), by: [b])
        )
        try authority.inform([T.removeKey(b.publicKey, after: authority.head, by: [a])])
        #expect(authority.state.keys == [a.trusted()])
    }

    /// 적용의 결과: AddKey는 끝에 덧붙이고, UpdateKey는 `Votes`·`Meta`를 바꾸고, RemoveKey는 순서를 지키며 지운다.
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
        // 지운 키의 서명은 더 받지 않는다.
        #expect(T.informError(&authority, [T.noOp(after: authority.head, by: [b])]) == .untrustedSigner)
    }
}
