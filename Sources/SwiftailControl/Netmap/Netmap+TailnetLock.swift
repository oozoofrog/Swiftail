import SwiftailTKA

/// tailnet lock으로 netmap을 거른다. 입출력 없는 계산이고, 어느 것을 쓸지는 `ControlClient`가 정한다.
///
/// 받은 netmap마다 전체를 다시 거른다(증분 경로가 따로 없다). Go가 전체 netmap에서 내리는 판정과 같다.
/// 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 P, `docs/protocol-notes/tailnet-lock.md` 4.9
/// (출처: tailscale.com `ipn/ipnlocal/tailnet-lock.go` `tkaFilterNetmapLocked`, BSD-3-Clause).
extension Netmap {
    /// 검증한 서명 권한 상태로 거른 netmap(`.enforcing`).
    ///
    /// 서명이 없거나 검증되지 않는 피어와 회전으로 낡은 키의 피어를 순서를 지키며 뺀다. `UnsignedPeerAPIOnly` 피어는 서명
    /// 검사를 받지 않지만 낡은 키면 함께 빠진다. 자기 노드는 빼지 않는다: 자기 서명이 검증되지 않으면(잠김) 서명 기기에 넘길
    /// 두 값을 `signingRequest`에 채운다.
    ///
    /// - Parameter lockKey: 이 노드의 tailnet lock 공개 키. 서명 요청의 `tlpub:` 값이 된다.
    func filtered(by authority: Authority, lockKey: NLPublicKey) -> Netmap {
        // shortcut: 바뀌지 않은 피어의 서명도 netmap마다 다시 검증한다(피어마다 Ed25519 검증 한 번 이상).
        // 필요해지는 시점: 피어가 많은 tailnet에서 netmap 처리 시간이 눈에 띌 때(머리와 서명이 같으면 판정을 다시 쓴다).
        let admitted = authority.state.admitted(peers.map {
            PeerCredential(nodeKey: $0.key, keySignature: $0.keySignature, unsignedPeerAPIOnly: $0.unsignedPeerAPIOnly)
        })
        var result = self
        result.peers = zip(peers, admitted).compactMap { peer, isAdmitted in isAdmitted ? peer : nil }
        result.tailnetLock = TailnetLockStatus(
            mode: .enforcing, head: authority.head.text, filteredPeerCount: peers.count - result.peers.count
        )
        do {
            _ = try authority.state.authorize(selfNode.key, keySignature: selfNode.keySignature)
        } catch {
            result.tailnetLock.signingRequest = TailnetLockStatus.SigningRequest(
                nodeKey: selfNode.key.description, lockKey: lockKey.commandLineDescription
            )
        }
        return result
    }

    /// 거를 근거가 없을 때의 netmap(`.unverified`): 피어를 모두 뺀다(`UnsignedPeerAPIOnly` 포함).
    ///
    /// 자기 노드의 서명도 판정할 수 없으므로 `signingRequest`는 없다.
    func withholdingPeers() -> Netmap {
        var result = self
        result.peers = []
        result.tailnetLock = TailnetLockStatus(mode: .unverified, filteredPeerCount: peers.count)
        return result
    }
}
