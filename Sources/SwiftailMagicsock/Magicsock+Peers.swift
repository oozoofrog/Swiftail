import SwiftailBase

/// 피어 표와 disco 키의 주인(계약 동작 B, 노트 3.2 5·4.4).
///
/// netmap이 바뀔 때마다 노드가 피어 목록 전체를 넘긴다. 이 파일은 그것으로 세 가지를 맞춘다.
/// - **disco 키의 주인**: disco 키 하나에 피어 하나. 목록의 앞 피어가 갖고, 같은 키를 내세운 뒤의 피어와 0인 키의
///   피어는 disco 없이 DERP만 쓴다. 받은 disco는 보낸 쪽 키로 이 주인만 찾는다.
/// - **공유 키 캐시**: 주인이 된 disco 키마다 X25519를 한 번 하고, 빠진 키는 버린다. 받은 패킷이 계산을 일으키지
///   못하므로 모르는 키를 내세운 쓰레기로 CPU를 쓰게 할 수 없다. 계산이 실패한 저차수 키의 피어는 DERP만 쓴다.
/// - **피어별 경로 상태**: 새 피어는 만들고, 남은 피어는 netmap 값을 넣고, disco 키가 바뀐 피어는 신뢰와 진행 중인
///   Ping을 버린다(노트 4.4 3). 빠진 피어는 지우고 `.pathChanged(key, nil)`을 낸다.
extension Magicsock {
    /// netmap의 피어를 맞춘다. 순서가 주인을 정한다(같은 disco 키는 앞의 피어만 갖는다). 노드는 node ID 순으로 넘긴다.
    ///
    /// 같은 node 키가 두 번 오면 앞의 것만 쓴다. 출력은 빠진 피어의 `.pathChanged(_, nil)`, 그다음 목록 순서대로
    /// 경로가 바뀐(새 피어 포함) 피어의 `.pathChanged`다.
    public mutating func setPeers(_ newPeers: [Peer], at now: ContinuousClock.Instant) -> [Output] {
        var owners: [DiscoPublicKey: DiscoPeer] = [:]
        var entries: [NodePublicKey: PeerEntry] = [:]
        var order: [NodePublicKey] = []
        for peer in newPeers where entries[peer.key] == nil {
            let discoKey = claimDisco(for: peer, owners: &owners)
            entries[peer.key] = updatedEntry(peers[peer.key], with: peer, discoKey: discoKey, at: now)
            order.append(peer.key)
        }

        var outputs: [Output] = []
        for key in peerOrder where entries[key] == nil {
            outputs.append(.pathChanged(key, nil))
        }
        peers = entries
        peerOrder = order
        discoPeers = owners
        pendingCallMeMaybe.removeAll { entries[$0]?.discoKey == nil }
        for key in order {
            reportPathChange(of: key, at: now, into: &outputs)
        }
        return outputs
    }

    /// `peer`가 disco 키의 주인이 되면 그 키를 `owners`에 넣고 돌려준다. disco를 하지 않으면 nil.
    ///
    /// 공유 키는 지난 표에 있으면 다시 쓰고, 없을 때만 계산한다.
    private func claimDisco(for peer: Peer, owners: inout [DiscoPublicKey: DiscoPeer]) -> DiscoPublicKey? {
        let key = peer.discoKey
        guard !key.isZero, owners[key] == nil else { return nil }
        let sharedKey: DiscoSharedKey
        if let cached = discoPeers[key]?.sharedKey {
            sharedKey = cached
        } else {
            guard let computed = try? DiscoSharedKey(privateKey: discoPrivateKey, peerPublicKey: key) else { return nil }
            sharedKey = computed
        }
        owners[key] = DiscoPeer(node: peer.key, sharedKey: sharedKey)
        return key
    }

    /// 피어 하나의 다음 상태. disco를 하지 않는 피어에게는 후보를 주지 않아 Ping이 나가지 않는다(DERP만).
    private func updatedEntry(
        _ existing: PeerEntry?,
        with peer: Peer,
        discoKey: DiscoPublicKey?,
        at now: ContinuousClock.Instant
    ) -> PeerEntry {
        let endpoints = discoKey == nil ? [] : peer.endpoints
        guard var entry = existing else {
            return PeerEntry(discoKey: discoKey, path: PeerPathState(homeDERP: peer.homeDERP, endpoints: endpoints))
        }
        if entry.discoKey != discoKey {
            if discoKey == nil {
                // disco를 그만두면 Pong이 다시 오지 않으므로 직접 경로의 흔적을 모두 버린다.
                entry.path = PeerPathState(homeDERP: peer.homeDERP, endpoints: [])
            } else {
                entry.path.resetForNewDiscoKey()
            }
        }
        entry.path.update(homeDERP: peer.homeDERP, endpoints: endpoints, at: now)
        entry.discoKey = discoKey
        return entry
    }
}
