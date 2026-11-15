import Testing

@testable import SwiftailTKA

/// 계약 5절 TL-11a 항목 1: 한도(4,096개·16MiB)는 활성 사슬에만 걸고, 쥔 것 전체가 넘으면 활성 사슬 밖의 AUM을 나중에 들인
/// 것부터 버린다. 바이트 한도를 쓰면 AUM 몇십 개로 경계에 닿는다: 키 512개에 `Meta`를 채운 체크포인트는 하나가 약 280KiB다.
@Suite("서명 권한 상태 기계: 활성 사슬 밖의 AUM 버리기")
struct AuthorityRetentionTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()

    /// `trusted`와 `Meta`를 채운 임의의 키로 512개를 채운 상태.
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

    /// `parent`부터 `count`개의 체크포인트를 잇는다.
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

    /// 뿌리의 형제 체크포인트 60개(합이 16MiB를 넘는다)를 한 묶음으로 받아도 들이고, 그 뒤의 RemoveKey와 체크포인트를 따라간다.
    /// Go는 쥐는 수에 한도가 없어 모두 쥐고, 머리(가중치·종류가 같아 해시가 가장 작은 형제)와 상태는 같다.
    @Test func inactiveSiblingsAreDiscardedAndRemovalStillApplies() throws {
        let state = Self.largeState([a.trusted(), b.trusted()], seed: 21)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        let siblings = (0..<60).map { _ in T.checkpoint(state, parent: authority.head, by: [a]) }
        #expect(T.byteCount(authority.aums + siblings) > Authority.maximumByteCount)
        try authority.inform(siblings)

        let winner = try #require(siblings.min { $0.hash.bytes.lexicographicallyPrecedes($1.hash.bytes) })
        #expect(authority.head == winner.hash)
        #expect(T.byteCount(authority.aums) <= Authority.maximumByteCount)
        // 나중에 든 것부터 버렸다: 남은 진 형제는 모두 버린 것보다 앞자리다. 이긴 형제는 자리와 관계없이 남는다.
        let kept = Set(authority.hashes)
        let keptLosers = siblings.indices.filter { kept.contains(siblings[$0].hash) && siblings[$0] != winner }
        let discarded = siblings.indices.filter { !kept.contains(siblings[$0].hash) }
        #expect(!discarded.isEmpty && (keptLosers.max() ?? -1) < (discarded.min() ?? 0))
        try Self.expectReopens(authority)

        // b를 지우고 그 상태를 체크포인트로 싣는다.
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

    /// 버린 AUM을 부모로 하는 AUM은 "부모를 모르는 AUM"이다. 버린 AUM이 다시 오면 다시 들인다: 한도가 여전히 차 있으면 가장
    /// 나중에 든 그것이 다시 버려지고, 함께 온 자식도 같이 버려진다. 어느 쪽도 머리와 상태를 바꾸지 않는다.
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
        // 버린 뒤 남은 여유는 형제 하나(모두 같은 크기)보다 작으므로, 다시 든 것은 다시 버려진다.
        #expect(Authority.maximumByteCount - T.byteCount(authority.aums) < gone.serialized().count)
        try authority.inform([gone])
        #expect(Set(authority.hashes) == Set(before.hashes) && authority.head == before.head && authority.state == before.state)
        try authority.inform([gone, child])
        #expect(Set(authority.hashes) == Set(before.hashes) && authority.head == before.head && authority.state == before.state)
    }

    /// 한 묶음 안에서 활성 사슬이 바뀌면 한도는 새 활성 사슬로 센다. 방금까지 활성이던 사슬은 진 갈래가 되어 끝 쪽부터
    /// 버려진다. 새 활성 사슬 자체가 한도를 넘으면 묶음을 통째로 거절한다(고치지 않는 것: 압축 없음).
    @Test func activeChainSwitchWithinABatch() throws {
        let c = T.Signer()
        let state = Self.largeState([a.trusted(), b.trusted(votes: 2), c.trusted(votes: 3)], seed: 23)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        let root = authority.head
        let old = Self.checkpointChain(state, after: root, count: 50, by: [a])
        try authority.inform(old)
        #expect(authority.head == old.last?.hash)

        // b(2표)가 뿌리에서 시작한 사슬이 a(1표)의 사슬을 이긴다. 둘을 합치면 16MiB를 넘는다.
        let new = Self.checkpointChain(state, after: root, count: 10, by: [b])
        #expect(T.byteCount(authority.aums + new) > Authority.maximumByteCount)
        try authority.inform(new)
        #expect(authority.head == new.last?.hash)
        #expect(T.activeChain(of: authority).map(\.hash) == (new.reversed().map(\.hash) + [root]))
        #expect(T.byteCount(authority.aums) <= Authority.maximumByteCount)
        let kept = Set(authority.hashes)
        let keptOld = old.indices.filter { kept.contains(old[$0].hash) }
        #expect(keptOld == Array(old.indices.prefix(keptOld.count)) && keptOld.count < old.count, "옛 사슬의 끝 쪽부터 버린다")
        try Self.expectReopens(authority)

        // c(3표)가 뿌리에서 시작한 사슬이 이기지만 그 자체가 16MiB를 넘는다.
        let tooLong = Self.checkpointChain(state, after: root, count: 59, by: [c])
        #expect(T.byteCount([authority.aums[0]] + tooLong) > Authority.maximumByteCount)
        let before = authority
        #expect(T.informError(&authority, tooLong) == .limitExceeded)
        #expect(authority.aums == before.aums && authority.head == before.head && authority.state == before.state)
        // 한도 안으로 줄이면 들인다.
        try authority.inform(Array(tooLong.prefix(20)))
        #expect(authority.head == tooLong[19].hash)
        try Self.expectReopens(authority)
    }
}
