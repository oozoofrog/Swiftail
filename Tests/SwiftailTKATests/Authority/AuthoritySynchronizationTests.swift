import Testing

@testable import SwiftailTKA

/// 계약 7절 시험 9: 동기화 계산(동작 Y1·Y4). 1,000·2,000의 경계는 `tka-fixtures.json`의 `sync`/`long`이 Go와 견준다.
@Suite("서명 권한 상태 기계: 동기화 계산")
struct AuthoritySynchronizationTests {
    typealias T = AuthorityTesting

    let a = T.Signer()

    func start() throws -> Authority {
        try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
    }

    /// 조상 목록: 체크포인트가 없으면 뿌리 하나, 있으면 새것부터 그 해시들과 끝의 뿌리.
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

    /// 머리 교차: 상대의 머리가 로컬 사슬에 있으면 그 뒤의 것을 보낸다.
    @Test func headIntersection() throws {
        let root = try start()
        let chain = T.noOpChain(after: root.head, count: 5, by: a)
        var remote = root
        try remote.inform(Array(chain.prefix(2)))
        var local = root
        try local.inform(chain)
        #expect(try local.missingAUMs(for: remote.syncOffer()) == Array(chain.dropFirst(2)))
        // 뒤처진 쪽은 상대의 머리를 모르므로 꼬리 교차(뿌리)부터 자기 사슬을 보낸다(Go `basic/behind`와 같다).
        #expect(try remote.missingAUMs(for: local.syncOffer()) == Array(chain.prefix(2)))
        try remote.inform(local.missingAUMs(for: remote.syncOffer()))
        #expect(remote.head == local.head)
    }

    /// 꼬리 교차: 갈라진 두 쪽은 공통 조상 다음부터 자기 활성 사슬을 보낸다(진 갈래는 보내지 않는다).
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

        // 서로 받으면 같은 머리(b의 2표가 이긴다)로 모인다. 로컬은 상대의 머리를 진 갈래로 쥔다.
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

    /// 반복 한도의 경계: 체크포인트를 포함한 경로가 한도 개수까지는 된다(Go `computeStateAt`·`fastForward`와 같은 셈).
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
