import Testing

@testable import SwiftailTKA

/// 계약 7절 시험 8: 부트스트랩(동작 F5)과 다시 열기(동작 F6·결정 L14, 5절 TL-11a 항목 2).
@Suite("서명 권한 상태 기계: 부트스트랩과 다시 열기")
struct AuthorityBootstrapTests {
    typealias T = AuthorityTesting

    let a = T.Signer()
    let b = T.Signer()

    var rootState: AuthorityState { T.checkpointState([a.trusted(), b.trusted(votes: 2)]) }

    /// 갈래가 있는 사슬: 뿌리 → x1 → x2(a), x1 → y2(b, 이김) → y3, 그리고 체크포인트 하나.
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

    /// 체크포인트는 자기 상태의 키로 서명되어야 한다.
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

    /// genesis가 아닌 나중 체크포인트(부모 해시가 있다)도 부트스트랩한다(노트 8.2).
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

    /// 저장한 것을 다시 열면 같은 머리와 상태다. 저장의 차례가 바뀌어도 같다.
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

    /// 빈 `Meta`(`07a0`)만 있는 UpdateKey는 받아들일 때 정적 검사를 통과하고, 정준 바이트로 저장했다 읽으면 떨어진다. 다시 열기는
    /// 정적 검사를 하지 않으므로 같은 머리와 상태로 열린다(TL-11a 항목 2, Go `Open`도 연다).
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
        // 서명이 바뀐 저장은 여전히 거절한다(`storeWithAChangedSignature`와 같은 검사가 이 AUM에도 걸린다).
        var tampered = stored
        let index = try #require(tampered.firstIndex { $0.hash == update.hash })
        tampered[index].signatures[0].signature[1] ^= 1
        #expect(throws: TKAError.invalidSignature) { try Authority(opening: tampered, bootstrap: authority.bootstrap) }
    }

    /// 신뢰 키가 서명했지만 정적 검사에서 떨어지는 AUM(`Votes`가 4,096을 넘는 키의 AddKey)이 저장소에 있으면, Go `Open`과 같이
    /// 열고 그 상태로 갈래를 고른다. 가중치는 Go `uint`와 같이 감긴다(2^64−1 두 표의 합 2^64−2가 1표를 이긴다). 트랩하지 않는다.
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
        // 받아들이는 길로는 들어오지 않는다.
        var informed = try Authority(bootstrappingWith: root)
        #expect(T.informError(&informed, [add1]) == .invalidAUM)
    }

    @Test func storeWithoutItsRootOrWithDuplicates() throws {
        let authority = try grown()
        // 기록된 뿌리가 사슬 가운데의 체크포인트면 그 앞의 AUM에 닿지 못한다. 체크포인트가 아니면 부트스트랩부터 거절된다.
        let checkpoint = authority.aums[4]
        #expect(checkpoint.messageKind == AUM.Kind.checkpoint)
        #expect(throws: TKAError.corruptStore) { try Authority(opening: authority.aums, bootstrap: checkpoint.hash) }
        #expect(throws: TKAError.notACheckpoint) { try Authority(opening: authority.aums, bootstrap: authority.head) }
        #expect(throws: TKAError.corruptStore) { try Authority(opening: Array(authority.aums.dropFirst()), bootstrap: authority.bootstrap) }
        #expect(throws: TKAError.corruptStore) { try Authority(opening: authority.aums + [authority.aums[2]], bootstrap: authority.bootstrap) }
        #expect(throws: TKAError.corruptStore) { try Authority(opening: [], bootstrap: authority.bootstrap) }
    }

    /// 저장소의 AUM 수 한도(4,096개)는 검증 전에 본다.
    @Test func storeOverTheCountLimit() throws {
        let authority = try grown()
        let stored = Array(repeating: authority.aums[1], count: Authority.maximumAUMCount + 1)
        #expect(throws: TKAError.limitExceeded) { try Authority(opening: stored, bootstrap: authority.bootstrap) }
    }
}
