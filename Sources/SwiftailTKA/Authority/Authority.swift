// 서명 권한 상태 기계(Go `tka.Authority`). 노트 4.1~4.3, 계약 동작 F·M, 결정 L7·L10·L14, 5절 "독립 검토에서 고치는 것:
// 순수 로직 (TL-11a)"의 1·2·4.
//
// 부트스트랩, 들이기(`Inform`)의 차례와 실패 규칙, 갈래 해소(`pickNextAUM`), 앞으로 감기(`fastForward`), 어느 AUM의
// 상태(`computeStateAt`)와 그 반복 한도는 Go 구현을 따라 옮겼다. 저장소를 뿌리 하나로 좁혀 `Open`의 조상 고르기는 옮기지
// 않았다(동작 F6).
// 출처: tailscale.com v1.104.7 `tka/tka.go`(`Bootstrap`, `InformIdempotent`, `pickNextAUM`, `fastForwardWithAdvancer`,
// `computeStateAt`), `tka/limits.go`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// tailnet의 서명 권한 상태. 받아들인 AUM과 거기서 계산한 머리·신뢰 상태를 쥔 값 타입이다.
///
/// 소켓·파일·시계를 갖지 않는다. 저장은 `aums`와 `bootstrap`을 가장자리(`TailnetLockStore`)가 적는다. 압축하지 않으므로
/// 뿌리는 늘 부트스트랩한 체크포인트 하나이고, 나머지 AUM은 모두 부모가 이 안에 있다(결정 L7). 활성 사슬 밖의 AUM은 한도에
/// 닿으면 버린다(TL-11a 항목 1). 그래서 `aums`는 받아들인 AUM 전부가 아니라 그 가운데 쥔 것이다.
package struct Authority: Sendable {
    /// 뿌리에서 갈래 해소 규칙(동작 F1)으로 끝까지 따라간 AUM의 해시(동작 F2).
    package private(set) var head: AUMHash
    /// 머리까지 적용한 신뢰 상태. `lastAUMHash`는 `head`다.
    package private(set) var state: AuthorityState
    /// 부트스트랩한 AUM의 해시. 저장소의 하나뿐인 뿌리다.
    package let bootstrap: AUMHash
    /// 쥔 AUM(활성 사슬 전부와, 한도 안에서 남긴 갈래). 부모가 늘 자식보다 앞에 있다. 저장할 것이다.
    package private(set) var aums: [AUM]

    /// `aums`와 같은 자리의 해시.
    private(set) var hashes: [AUMHash]
    /// 해시 → `aums`의 자리.
    private(set) var positions: [AUMHash: Int]
    /// 부모 해시 → 자식들의 자리.
    private var children: [AUMHash: [Int]] = [:]
    /// `aums`와 같은 자리의 정준 바이트 수.
    private var byteCounts: [Int]
    /// 뿌리 체크포인트 자신의 상태(`lastAUMHash`는 뿌리). 머리를 다시 계산하는 출발점이다.
    private let rootState: AuthorityState

    /// AUM 수와 정준 바이트 합의 상한(동작 M, 결정 L7·L16, TL-11a 항목 1).
    ///
    /// **활성 사슬**(뿌리에서 머리까지)이 넘는 묶음은 통째로 거절한다. 쥔 AUM 전체가 넘으면 활성 사슬 밖의 것을 버려 이 안으로
    /// 돌아온다(`discardInactiveAUMs()`). 한도를 전체 수에 걸면, 서명 키 없이 만들 수 있는 서명 목록 변종으로 제어 서버가
    /// 한도를 채워 그 뒤의 RemoveKey까지 막는다.
    static let maximumAUMCount = 4_096
    static let maximumByteCount = 16 * 1_024 * 1_024
    /// 한 번에 들이는 AUM의 상한(동작 M).
    static let maximumBatchCount = 4_096
    /// 부모 상태를 찾아 거꾸로 가는 반복의 상한(Go `maxScanIterations`, 동작 F7).
    static let maximumScanIterations = 2_000

    /// 서버가 준 체크포인트 하나로 시작한다(Go `Bootstrap`, 동작 F5).
    ///
    /// 그 체크포인트 **자신의 상태**를 부모 상태 삼아 정적 검사와 서명을 본다. 부모 해시는 보지 않는다: genesis가 아닌 나중
    /// 체크포인트도 받는다. 첫 신뢰는 제어 서버가 준 것에 대한 TOFU다.
    package init(bootstrappingWith checkpoint: AUM) throws(TKAError) {
        guard checkpoint.messageKind == AUM.Kind.checkpoint, let checkpointState = checkpoint.state else {
            throw .notACheckpoint
        }
        try checkpointState.verify(checkpoint, isBootstrap: true)
        let bytes = checkpoint.serialized()
        guard bytes.count <= Self.maximumByteCount else { throw .limitExceeded }
        let hash = AUMHash(hashing: bytes)
        var rootState = checkpointState
        rootState.lastAUMHash = hash

        self.rootState = rootState
        head = hash
        state = rootState
        bootstrap = hash
        aums = [checkpoint]
        hashes = [hash]
        positions = [hash: 0]
        byteCounts = [bytes.count]
    }

    /// 저장해 둔 AUM들에서 다시 계산한다(Go `Open`, 동작 F6·T3).
    ///
    /// 불변 조건을 검사한다: 한도 안이고, 같은 AUM이 두 번 없고, 뿌리가 `bootstrap` 하나이고, 나머지는 모두 부모가 저장소에
    /// 있다. 어긋나면 `corruptStore`다. 뿌리 아래의 AUM은 **부모와 서명만** 다시 보고 상태를 적용한다(결정 L14를 좁힌 TL-11a
    /// 항목 2): 바뀐 파일은 서명으로 알아채고, 그 실패는 그 까닭으로 던진다. 정적 검사는 받아들일 때만 한다. 정준 쓰기는 빈
    /// `Meta`를 빼므로, 받아들일 때 통과한 AUM도 다시 읽으면 떨어질 수 있다(Go `Open`은 아무것도 다시 검증하지 않는다).
    /// 뿌리는 부트스트랩과 같이 본다. 뿌리부터 머리까지의 재계산에는 반복 한도를 두지 않는다(동작 F7. 저장 한도가 상한이다).
    package init(opening stored: [AUM], bootstrap: AUMHash) throws(TKAError) {
        guard stored.count <= Self.maximumAUMCount else { throw .limitExceeded }
        var hashes: [AUMHash] = []
        var byteCounts: [Int] = []
        var positions: [AUMHash: Int] = [:]
        var storedChildren: [AUMHash: [Int]] = [:]
        for (position, aum) in stored.enumerated() {
            let bytes = aum.serialized()
            let hash = AUMHash(hashing: bytes)
            guard positions.updateValue(position, forKey: hash) == nil else { throw .corruptStore }
            hashes.append(hash)
            byteCounts.append(bytes.count)
            if hash != bootstrap, let parent = aum.parentHash {
                storedChildren[parent, default: []].append(position)
            }
        }
        guard byteCounts.reduce(0, +) <= Self.maximumByteCount else { throw .limitExceeded }
        guard let rootPosition = positions[bootstrap] else { throw .corruptStore }

        // 뿌리에서 자식으로 내려가며 부모 상태로 검증하고 받아들인다. 받아들이는 차례는 부모가 먼저인 깊이 우선이다.
        var authority = try Authority(bootstrappingWith: stored[rootPosition])
        var pending = (storedChildren[bootstrap] ?? []).map { (position: $0, parentState: authority.rootState) }
        while let child = pending.popLast() {
            let aum = stored[child.position]
            let hash = hashes[child.position]
            try child.parentState.verifyParentAndSignatures(of: aum, isBootstrap: false)
            let state = try child.parentState.applying(aum, hash: hash)
            authority.append(aum, hash: hash, byteCount: byteCounts[child.position])
            pending += (storedChildren[hash] ?? []).map { (position: $0, parentState: state) }
        }
        // 뿌리에서 닿지 않은 것이 있으면 그 부모가 저장소에 없다(또는 부모 없는 AUM이다).
        guard authority.aums.count == stored.count else { throw .corruptStore }
        try authority.recomputeHead()
        self = authority
    }

    /// AUM 묶음을 받은 순서대로 들인다(Go `Inform`, 동작 F4).
    ///
    /// 정렬하지 않는다: 부모가 먼저 오게 주는 것은 보내는 쪽의 몫이다. 이미 쥔 AUM은 건너뛴다. 각 AUM의 부모 상태는 같은
    /// 묶음에서 앞서 처리한 것, 지금의 머리, 또는 저장소에서 거꾸로 찾은 것이다(동작 F3, 반복 2,000).
    /// **하나라도 실패하면 아무것도 바뀌지 않는다.** 모두 통과하면 머리를 다시 계산하고, 활성 사슬이 한도를 넘으면
    /// `limitExceeded`로 거절한다. 쥔 것 전체가 한도를 넘으면 활성 사슬 밖의 AUM을 버린다(TL-11a 항목 1).
    package mutating func inform(_ updates: [AUM]) throws(TKAError) {
        guard !updates.isEmpty else { throw .emptyUpdate }
        guard updates.count <= Self.maximumBatchCount else { throw .limitExceeded }
        // 묶음 안에서 각 해시를 부모로 삼는 AUM의 남은 수. 0이 되면 그 상태를 놓는다: AUM마다 상태 전체를 끝까지 쥐면
        // 메모리가 묶음 크기의 제곱으로 는다(TL-11a 항목 4).
        var pendingChildren: [AUMHash: Int] = [:]
        for update in updates {
            if let parent = update.parentHash { pendingChildren[parent, default: 0] += 1 }
        }

        var next = self
        var stateAt: [AUMHash: AuthorityState] = [head: state]
        for update in updates {
            let bytes = update.serialized()
            let hash = AUMHash(hashing: bytes)
            let parent = update.parentHash
            defer {
                if let parent, let remaining = pendingChildren[parent] {
                    pendingChildren[parent] = remaining > 1 ? remaining - 1 : nil
                    if remaining == 1 { stateAt[parent] = nil }
                }
            }
            if next.positions[hash] != nil { continue }

            guard let parentBytes = update.prevAUMHash, !parentBytes.isEmpty else { throw .missingParent }
            // 32바이트가 아닌 부모 해시는 어느 상태의 `lastAUMHash`와도 같지 않다(Go에서는 적용에서 떨어진다).
            guard let parent else { throw .rejectedUpdate }
            let parentState: AuthorityState
            if let known = stateAt[parent] {
                parentState = known
            } else {
                guard next.positions[parent] != nil else { throw .missingParent }
                parentState = try next.state(at: parent, iterationLimit: Self.maximumScanIterations)
                stateAt[parent] = parentState
            }

            try parentState.verify(update, isBootstrap: false)
            let updatedState = try parentState.applying(update, hash: hash)
            if pendingChildren[hash] != nil { stateAt[hash] = updatedState }
            next.append(update, hash: hash, byteCount: bytes.count)
        }
        guard next.aums.count > aums.count else { return }
        try next.recomputeHead()
        try next.discardInactiveAUMs()
        self = next
    }

    // MARK: 사슬

    /// 검증을 마친 AUM을 저장소에 더한다. 한도(동작 M)는 부르는 쪽이 먼저 본다.
    private mutating func append(_ aum: AUM, hash: AUMHash, byteCount count: Int) {
        let position = aums.count
        aums.append(aum)
        hashes.append(hash)
        positions[hash] = position
        byteCounts.append(count)
        if let parent = aum.parentHash {
            children[parent, default: []].append(position)
        }
    }

    /// 활성 사슬이 한도(동작 M) 안인지 보고, 쥔 것 전체가 한도를 넘으면 활성 사슬 밖의 AUM을 **나중에 들인 것부터** 버린다
    /// (TL-11a 항목 1). 활성 사슬이 넘으면 `limitExceeded`를 던진다. 머리를 다시 계산한 뒤에 부른다.
    ///
    /// 버려도 지금과 뒤의 머리·상태는 Go와 같다. 갈래 해소(동작 F1, Go `pickNextAUM`)는 부모 상태로 형제끼리만 견주는
    /// 전순서이고 후손을 보지 않는다. 활성 사슬 위의 AUM은 부모 상태가 바뀌지 않으므로, 거기서 한 번 진 형제는 새 형제가 와도
    /// (전순서라 이기는 쪽은 지금 것이거나 새것이다) 자기에게 후손이 붙어도 다시 이기지 못한다. 활성 사슬 위의 갈림길이 새
    /// 형제에게 지면 그 아래는 모두 활성 사슬 밖이 되고 같은 까닭으로 돌아오지 않는다. 그래서 활성 사슬 밖의 AUM은 판정에
    /// 쓰이지 않는다(동기화의 교차도 활성 사슬에서만 나온다). 다르게 되는 것은 버린 AUM을 부모로 하는 AUM이 뒤에 오는 경우뿐이고,
    /// 그것은 "부모를 모르는 AUM"이다(동작 F4).
    ///
    /// 나중에 들인 것부터 버리면 버리는 AUM의 자식(늘 부모보다 뒤 자리)은 이미 버려졌으므로, 남는 AUM의 부모는 늘 남는다.
    private mutating func discardInactiveAUMs() throws(TKAError) {
        var active: Set<Int> = []
        var activeByteCount = 0
        var cursor = positions[head]
        while let position = cursor {
            active.insert(position)
            activeByteCount += byteCounts[position]
            cursor = hashes[position] == bootstrap ? nil : aums[position].parentHash.flatMap { positions[$0] }
        }
        guard active.count <= Self.maximumAUMCount, activeByteCount <= Self.maximumByteCount else { throw .limitExceeded }

        var count = aums.count
        var byteCount = byteCounts.reduce(0, +)
        var discarded: Set<Int> = []
        for position in aums.indices.reversed() {
            guard count > Self.maximumAUMCount || byteCount > Self.maximumByteCount else { break }
            guard !active.contains(position) else { continue }
            discarded.insert(position)
            count -= 1
            byteCount -= byteCounts[position]
        }
        guard !discarded.isEmpty else { return }

        // 남는 것으로 자리를 다시 매긴다. 뿌리(자리 0)는 활성 사슬이라 남는다.
        var kept = self
        kept.aums = [aums[0]]
        kept.hashes = [hashes[0]]
        kept.byteCounts = [byteCounts[0]]
        kept.positions = [hashes[0]: 0]
        kept.children = [:]
        for position in aums.indices.dropFirst() where !discarded.contains(position) {
            kept.append(aums[position], hash: hashes[position], byteCount: byteCounts[position])
        }
        self = kept
    }

    /// 뿌리 상태에서 끝까지 앞으로 감아 머리와 상태를 정한다(동작 F2).
    private mutating func recomputeHead() throws(TKAError) {
        (head, state) = try fastForward(from: bootstrap, state: rootState, iterationLimit: nil) { _ in false }
    }

    /// `start`(그 상태가 `startState`)에서 갈래 해소 규칙으로 자식을 하나씩 적용해 간다(Go `fastForward`, 동작 F2).
    ///
    /// 각 AUM(`start` 포함)을 지날 때 `done`을 부르고, 참이면 그 자리에서 멈춘다. 자식이 없으면 거기가 끝이다. Go와 같이
    /// `iterationLimit`번 지나도 끝나지 않으면 `iterationLimit`을 던진다. nil이면 한도가 없다.
    func fastForward(
        from start: AUMHash,
        state startState: AuthorityState,
        iterationLimit: Int?,
        until done: (AUMHash) -> Bool
    ) throws(TKAError) -> (head: AUMHash, state: AuthorityState) {
        var cursor = start
        var state = startState
        var iterations = 0
        while true {
            if let iterationLimit, iterations == iterationLimit { throw .iterationLimit }
            iterations += 1
            if done(cursor) { return (cursor, state) }
            guard let chosen = preferredChild(of: cursor, state: state) else { return (cursor, state) }
            state = try state.applying(aums[chosen], hash: hashes[chosen])
            cursor = hashes[chosen]
        }
    }

    /// `parent`의 자식 가운데 사슬을 잇는 것의 자리(Go `pickNextAUM`, 동작 F1). 자식이 없으면 nil.
    ///
    /// ① 부모 상태로 센 서명 가중치가 큰 것 ② 같으면 RemoveKey인 것 ③ 같으면 해시가 바이트 비교로 작은 것.
    private func preferredChild(of parent: AUMHash, state: AuthorityState) -> Int? {
        let ranked = (children[parent] ?? []).map { position in
            (
                position: position,
                weight: state.weight(of: aums[position]),
                removesKey: aums[position].messageKind == AUM.Kind.removeKey,
                hash: hashes[position].bytes
            )
        }
        guard var best = ranked.first else { return nil }
        for candidate in ranked.dropFirst() {
            let isPreferred =
                if candidate.weight != best.weight {
                    candidate.weight > best.weight
                } else if candidate.removesKey != best.removesKey {
                    candidate.removesKey
                } else {
                    candidate.hash.lexicographicallyPrecedes(best.hash)
                }
            if isPreferred { best = candidate }
        }
        return best.position
    }

    /// 저장소에 있는 AUM `target`의 상태(Go `computeStateAt`, 동작 F3).
    ///
    /// 체크포인트를 만날 때까지 거꾸로 가고, 지나온 경로를 따라 다시 적용한다(갈래 규칙이 아니다). Go와 같이 체크포인트를
    /// 포함한 경로가 `iterationLimit`개를 넘으면 `iterationLimit`을 던진다(거꾸로 가기와 앞으로 감기의 한도가 겹친 결과).
    func state(at target: AUMHash, iterationLimit: Int) throws(TKAError) -> AuthorityState {
        var path: [Int] = []
        var cursor = target
        while true {
            guard path.count < iterationLimit else { throw .iterationLimit }
            guard let position = positions[cursor] else { throw .missingParent }
            let aum = aums[position]
            if aum.messageKind == AUM.Kind.checkpoint, var state = aum.state {
                state.lastAUMHash = cursor
                for position in path.reversed() {
                    state = try state.applying(aums[position], hash: hashes[position])
                }
                return state
            }
            // 뿌리가 체크포인트라 부모 없는 AUM에는 닿지 않는다.
            guard let parent = aum.parentHash else { throw .missingParent }
            path.append(position)
            cursor = parent
        }
    }
}

extension AUM {
    /// 32바이트 부모 해시. 저장소에 든 AUM은 뿌리가 아니면 늘 이것을 가진다(적용이 바이트 일치를 보므로).
    var parentHash: AUMHash? { prevAUMHash.flatMap(AUMHash.init) }
}
