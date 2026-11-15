// 서명 권한 상태 기계(Go `tka.Authority`). 노트 4.1~4.3, 계약 동작 F·M, 결정 L7·L10·L14.
//
// 부트스트랩, 들이기(`Inform`)의 차례와 실패 규칙, 갈래 해소(`pickNextAUM`), 앞으로 감기(`fastForward`), 어느 AUM의
// 상태(`computeStateAt`)와 그 반복 한도는 Go 구현을 따라 옮겼다. 저장소를 뿌리 하나로 좁혀 `Open`의 조상 고르기는 옮기지
// 않았다(동작 F6).
// 출처: tailscale.com v1.104.7 `tka/tka.go`(`Bootstrap`, `InformIdempotent`, `pickNextAUM`, `fastForwardWithAdvancer`,
// `computeStateAt`), `tka/limits.go`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// tailnet의 서명 권한 상태. 받아들인 AUM 전부와 거기서 계산한 머리·신뢰 상태를 쥔 값 타입이다.
///
/// 소켓·파일·시계를 갖지 않는다. 저장은 `aums`와 `bootstrap`을 가장자리(`TailnetLockStore`)가 적는다. 압축하지 않으므로
/// 뿌리는 늘 부트스트랩한 체크포인트 하나이고, 나머지 AUM은 모두 부모가 이 안에 있다(결정 L7).
package struct Authority: Sendable {
    /// 뿌리에서 갈래 해소 규칙(동작 F1)으로 끝까지 따라간 AUM의 해시(동작 F2).
    package private(set) var head: AUMHash
    /// 머리까지 적용한 신뢰 상태. `lastAUMHash`는 `head`다.
    package private(set) var state: AuthorityState
    /// 부트스트랩한 AUM의 해시. 저장소의 하나뿐인 뿌리다.
    package let bootstrap: AUMHash
    /// 받아들인 AUM 전부(활성 사슬과 갈래). 부모가 늘 자식보다 앞에 있다. 저장할 것이다.
    package private(set) var aums: [AUM]

    /// `aums`와 같은 자리의 해시.
    private(set) var hashes: [AUMHash]
    /// 해시 → `aums`의 자리.
    private(set) var positions: [AUMHash: Int]
    /// 부모 해시 → 자식들의 자리.
    private var children: [AUMHash: [Int]] = [:]
    /// `aums`의 정준 바이트 합.
    private var byteCount: Int
    /// 뿌리 체크포인트 자신의 상태(`lastAUMHash`는 뿌리). 머리를 다시 계산하는 출발점이다.
    private let rootState: AuthorityState

    /// 쥐는 AUM의 수와 정준 바이트 합의 상한(동작 M, 결정 L7·L16). 넘는 묶음은 통째로 거절한다.
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
        byteCount = bytes.count
    }

    /// 저장해 둔 AUM들에서 다시 계산한다(Go `Open`, 동작 F6·T3).
    ///
    /// 불변 조건을 검사한다: 한도 안이고, 같은 AUM이 두 번 없고, 뿌리가 `bootstrap` 하나이고, 나머지는 모두 부모가 저장소에
    /// 있다. 어긋나면 `corruptStore`다. 받아들일 때와 같이 정적 검사와 서명을 다시 본다(결정 L14): 그 실패는 그 까닭으로
    /// 던진다. 뿌리부터 머리까지의 재계산에는 반복 한도를 두지 않는다(동작 F7. 저장 한도가 상한이다).
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
            try child.parentState.verify(aum, isBootstrap: false)
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
    /// **하나라도 실패하면 아무것도 바뀌지 않는다.** 모두 통과하면 머리를 다시 계산한다.
    package mutating func inform(_ updates: [AUM]) throws(TKAError) {
        guard !updates.isEmpty else { throw .emptyUpdate }
        guard updates.count <= Self.maximumBatchCount else { throw .limitExceeded }
        // 한도는 서명을 검증하기 전에 본다: 넘는 묶음에 검증 비용을 쓰지 않는다.
        var encoded: [(hash: AUMHash, byteCount: Int)] = []
        var newHashes: Set<AUMHash> = []
        var newByteCount = 0
        for update in updates {
            let bytes = update.serialized()
            let hash = AUMHash(hashing: bytes)
            encoded.append((hash, bytes.count))
            if positions[hash] == nil, newHashes.insert(hash).inserted { newByteCount += bytes.count }
        }
        guard aums.count + newHashes.count <= Self.maximumAUMCount, byteCount + newByteCount <= Self.maximumByteCount
        else { throw .limitExceeded }

        var next = self
        var stateAt: [AUMHash: AuthorityState] = [head: state]
        for (update, (hash, count)) in zip(updates, encoded) {
            if next.positions[hash] != nil { continue }

            guard let parentBytes = update.prevAUMHash, !parentBytes.isEmpty else { throw .missingParent }
            // 32바이트가 아닌 부모 해시는 어느 상태의 `lastAUMHash`와도 같지 않다(Go에서는 적용에서 떨어진다).
            guard let parent = AUMHash(parentBytes) else { throw .rejectedUpdate }
            let parentState: AuthorityState
            if let known = stateAt[parent] {
                parentState = known
            } else {
                guard next.positions[parent] != nil else { throw .missingParent }
                parentState = try next.state(at: parent, iterationLimit: Self.maximumScanIterations)
                stateAt[parent] = parentState
            }

            try parentState.verify(update, isBootstrap: false)
            stateAt[hash] = try parentState.applying(update, hash: hash)
            next.append(update, hash: hash, byteCount: count)
        }
        guard next.aums.count > aums.count else { return }
        try next.recomputeHead()
        self = next
    }

    // MARK: 사슬

    /// 검증을 마친 AUM을 저장소에 더한다. 한도(동작 M)는 부르는 쪽이 먼저 본다.
    private mutating func append(_ aum: AUM, hash: AUMHash, byteCount count: Int) {
        let position = aums.count
        aums.append(aum)
        hashes.append(hash)
        positions[hash] = position
        byteCount += count
        if let parent = aum.parentHash {
            children[parent, default: []].append(position)
        }
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
