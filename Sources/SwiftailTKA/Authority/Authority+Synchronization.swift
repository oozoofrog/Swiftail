// 동기화 계산: 제안과 상대가 모르는 AUM. 노트 4.8, 계약 동작 Y1·Y4, 결정 L8, 5절 TL-11a의 3.
//
// 조상 목록, 머리 교차·꼬리 교차의 차례와 반복 한도는 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.7 `tka/sync.go`(`SyncOffer`, `computeSyncIntersection`, `MissingAUMs`), `tka/limits.go`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// 동기화에서 주고받는 제안: 머리와, 교차점을 찾을 조상들(Go `tka.SyncOffer`).
package struct SyncOffer: Sendable, Equatable {
    /// 그 쪽의 머리.
    package var head: AUMHash
    /// 새것부터. 마지막 것이 그 쪽 저장소의 가장 오래된 AUM이다.
    package var ancestors: [AUMHash]

    /// 머리와 조상으로 만든다. 받은 제안은 검사하지 않는다: `Authority.missingAUMs(for:)`가 조상의 중복과 개수를 다룬다.
    package init(head: AUMHash, ancestors: [AUMHash]) {
        self.head = head
        self.ancestors = ancestors
    }
}

extension Authority {
    /// 동기화의 앞으로 감기 한도(Go `maxSyncIter`).
    static let maximumSyncIterations = 2_000
    /// 머리에서 거꾸로 가는 한도(Go `maxSyncHeadIntersectionIter`).
    static let maximumSyncHeadIntersectionIterations = 1_000
    /// 상대의 조상 가운데 보는 수의 상한: Go가 내는 제안의 최대다. Go `SyncOffer`는 머리에서 거꾸로 1,000번 보며 만난
    /// 체크포인트(한 번에 하나)와 끝의 가장 오래된 AUM을 담는다(`tka/sync.go:88-109`).
    static let maximumSyncAncestorCount = maximumSyncHeadIntersectionIterations + 1

    /// 서버에 보낼 제안(Go `SyncOffer`, 동작 Y1).
    ///
    /// `ancestors`는 머리에서 거꾸로 1,000개까지 보며 만난 체크포인트의 해시(새것부터, 뿌리는 빼고)와 끝의 뿌리다.
    package func syncOffer() -> SyncOffer {
        var ancestors: [AUMHash] = []
        var cursor = head
        for _ in 0..<Self.maximumSyncHeadIntersectionIterations {
            guard cursor != bootstrap, let position = positions[cursor] else { break }
            let aum = aums[position]
            if aum.messageKind == AUM.Kind.checkpoint { ancestors.append(cursor) }
            guard let parent = aum.parentHash else { break }
            cursor = parent
        }
        ancestors.append(bootstrap)
        return SyncOffer(head: head, ancestors: ancestors)
    }

    /// 상대의 제안에 견줘 상대가 모르는 로컬 AUM을 부모가 먼저인 차례로(Go `MissingAUMs`, 동작 Y4).
    ///
    /// 머리가 같으면 빈 목록이다. 교차가 없으면 `noIntersection`, 반복 한도에 닿으면 `iterationLimit`을 던진다. 던지면
    /// 부르는 쪽은 동기화 전체를 끝낸다(상대의 AUM도 들이지 않는다).
    ///
    /// 상대의 조상은 중복을 지우고 앞의 1,001개(`maximumSyncAncestorCount`)까지만 본다(TL-11a 항목 3): 조상마다 체크포인트까지
    /// 거꾸로 가며 다시 적용하므로, 제어 서버가 진 갈래의 AUM을 되풀이해 넣으면 응답 하나로 계산이 부푼다. 되풀이한 조상의
    /// 답은 처음 것과 같고, Go가 낸 제안은 1,001개를 넘지 않으므로 판정은 Go와 같다.
    package func missingAUMs(for remote: SyncOffer) throws(TKAError) -> [AUM] {
        guard remote.head != head else { return [] }
        var seen: Set<AUMHash> = []
        var ancestors: [AUMHash] = []
        for ancestor in remote.ancestors {
            guard ancestors.count < Self.maximumSyncAncestorCount else { break }
            if seen.insert(ancestor).inserted { ancestors.append(ancestor) }
        }
        let intersection = try intersection(with: SyncOffer(head: remote.head, ancestors: ancestors))
        let start = try state(at: intersection, iterationLimit: Self.maximumSyncIterations)
        var missing: [AUM] = []
        _ = try fastForward(from: intersection, state: start, iterationLimit: Self.maximumSyncIterations) { hash in
            if hash != intersection, let position = positions[hash] { missing.append(aums[position]) }
            return false
        }
        return missing
    }

    /// 상대와 함께 가진 AUM(Go `computeSyncIntersection`). 교차 AUM 다음부터가 보낼 목록이다.
    ///
    /// 머리 교차: 상대의 머리가 로컬에 있으면 로컬 머리에서 거꾸로 1,000개까지 찾는다. 꼬리 교차: 상대의 조상을 앞에서부터
    /// 보며, 그 AUM의 상태에서 앞으로 감아(2,000번까지) 로컬 머리에 닿는 첫 것이다. 로컬에 없는 조상은 건너뛰고, 그 밖의
    /// 실패(반복 한도)는 곧바로 던진다.
    private func intersection(with remote: SyncOffer) throws(TKAError) -> AUMHash {
        if positions[remote.head] != nil {
            var cursor = head
            for _ in 0..<Self.maximumSyncHeadIntersectionIterations {
                guard let position = positions[cursor] else { break }
                if cursor == remote.head { return cursor }
                guard let parent = aums[position].parentHash else { break }
                cursor = parent
            }
        }
        for ancestor in remote.ancestors where positions[ancestor] != nil {
            let start = try state(at: ancestor, iterationLimit: Self.maximumSyncIterations)
            let end = try fastForward(from: ancestor, state: start, iterationLimit: Self.maximumSyncIterations) {
                $0 == head
            }
            if end.head == head { return ancestor }
        }
        throw .noIntersection
    }
}
