import Testing

@testable import SwiftailTKA

/// 계약 7절 시험 6·7: 갈래 해소(동작 F1)와 들이기(동작 F4).
@Suite("서명 권한 상태 기계: 갈래와 들이기")
struct AuthorityChainTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()
    let c = T.Signer()

    func start(votes: (UInt64, UInt64, UInt64) = (1, 1, 1)) throws -> Authority {
        let keys = [a.trusted(votes: votes.0), b.trusted(votes: votes.1), c.trusted(votes: votes.2)]
        return try Authority(bootstrappingWith: T.checkpoint(T.checkpointState(keys), by: [a]))
    }

    /// `first`·`second`를 어느 차례로 들여도 머리가 `winner`다.
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

    // MARK: 갈래 해소(시험 6)

    @Test func heavierSignatureWeightWins() throws {
        let authority = try start(votes: (1, 2, 1))
        let light = T.noOp(after: authority.head, by: [a])
        let heavy = T.noOp(after: authority.head, by: [b])
        try expectWinner(heavy, among: light, heavy, from: authority)
        // 키 둘(1표 + 1표)이 키 하나(1표)를 이긴다.
        let both = T.noOp(after: authority.head, by: [a, c])
        try expectWinner(both, among: light, both, from: authority)
    }

    /// 같은 키의 서명 둘은 한 번만 센다: a(2표) × 2 = 2 < c(3표). 두 번 세면 4로 이긴다.
    @Test func sameKeyCountsOnce() throws {
        let authority = try start(votes: (2, 1, 3))
        let twice = T.signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: authority.head.bytes), by: [a, a])
        #expect(twice.signatures.count == 2)
        let once = T.noOp(after: authority.head, by: [c])
        try expectWinner(once, among: twice, once, from: authority)
    }

    /// 가중치가 같으면 RemoveKey가 이긴다. 해시만 보면 다른 쪽이 이기도록 고른다.
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

    /// 갈래의 진 쪽에 자식이 붙어도 머리는 그대로다. 이긴 쪽에 자식이 붙으면 그리 옮겨 간다.
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
        // 진 쪽의 상태를 따라 그 갈래 위의 AUM도 검증한다: 진 쪽에서 지운 키의 서명은 그 갈래에서 거절된다.
        let removal = T.removeKey(c.publicKey, after: loserChain[2].hash, by: [a])
        try authority.inform([removal])
        #expect(T.informError(&authority, [T.noOp(after: removal.hash, by: [c])]) == .untrustedSigner)
        #expect(authority.head == next.hash)
    }

    // MARK: 들이기(시험 7)

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
        // 이미 쥔 것 뒤에 새것이 이어지면 새것만 더한다.
        let next = T.noOp(after: update.hash, by: [b])
        try authority.inform([update, next])
        #expect(authority.aums.count == 3 && authority.head == next.hash)
    }

    /// 묶음 가운데 하나라도 틀리면 그 앞의 것까지 아무것도 들이지 않는다.
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

    /// 받은 순서대로 처리하고 정렬하지 않는다.
    @Test func outOfOrderBatch() throws {
        var authority = try start()
        let chain = T.noOpChain(after: authority.head, count: 2, by: a)
        #expect(T.informError(&authority, chain.reversed()) == .missingParent)
        try authority.inform(chain)
        #expect(authority.head == chain[1].hash)
    }

    /// 갈래를 만드는 묶음: 진 쪽이 더 길어도 머리는 갈래 해소 규칙이 정한다.
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
