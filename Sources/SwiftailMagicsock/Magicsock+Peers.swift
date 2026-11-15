// disco 키 표와 TSMP disco 키 광고를 받는 규칙은 Go 구현을 따랐다.
// 출처: tailscale.com v1.104.7 `wgengine/magicsock/peermap.go` (`nodesOfDisco`, `upsertEndpoint`,
// `cleanFromNodesOfDisco`), `wgengine/magicsock/magicsock.go` (`HandleDiscoKeyAdvertisement`, `upsertPeerLocked`),
// `wgengine/magicsock/endpoint.go` (`checkAndUpdateDiscoKey`, `changedActiveDiscoLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 피어 표와 disco 키 표(계약 동작 B·T, 노트 3.2 5·4.4·4.10).
///
/// netmap이 바뀔 때마다 노드가 피어 목록 전체를 넘기고, 피어가 터널 안으로 TSMP disco 키 광고를 보내면 노드가 그
/// 피어의 node 키와 광고된 키를 넘긴다. 이 파일은 그것으로 세 가지를 맞춘다.
/// - **disco 키 표**: disco 키 하나를 여러 피어가 쥘 수 있다(Go `nodesOfDisco`). 피어는 netmap 키와 TSMP 키를 하나씩
///   쥐고 그 가운데 하나가 활성이다(`PeerDiscoKeys`). 피어가 바꿀 수 있는 것은 자기 자신의 키뿐이다: netmap은 각 피어의
///   netmap 키를, 광고는 보낸 피어의 TSMP 키를 바꾸고, 같은 키를 다른 피어가 쥐었어도 그 피어는 그대로다. 받은 disco의
///   주인은 `+Receiving`이 메시지마다 Go와 같은 규칙으로 가린다.
/// - **공유 키 캐시**: 표에 든 disco 키마다 X25519를 한 번 하고, 아무도 쥐지 않은 키는 버린다. 모르는 키를 내세운
///   UDP·DERP 쓰레기는 계산을 일으키지 못한다. 계산이 실패한 저차수 키는 없는 것으로 친다. TSMP 광고는 WireGuard가
///   인증한 피어에게서만 오고, 바뀐 키에만 계산한다(Go `discoInfoForKnownPeerLocked`와 같다).
/// - **피어별 경로 상태**: 새 피어는 만들고, 남은 피어는 netmap 값을 넣고, 키가 바뀐 피어는 신뢰와 진행 중인 Ping을
///   버린다(노트 4.4 3). 빠진 피어는 지우고, 경로를 알린 적이 있으면 `.pathChanged(key, nil)`을 낸다.

extension Magicsock {
    /// netmap의 피어를 맞춘다. 노드는 node ID 순으로 넘긴다(표의 피어 순서와 출력 순서가 이것을 따른다).
    ///
    /// 같은 node 키가 두 번 오면 앞의 것만 쓴다. 같은 disco 키를 여러 피어가 내세우면 모두 그 키로 disco를 한다(Go와
    /// 같다). 남은 피어의 TSMP 키는 그대로 둔다. 출력은 빠진 피어의 `.pathChanged(_, nil)`, 그다음 목록 순서대로 경로가
    /// 바뀐 피어의 `.pathChanged`다. 새 피어는 아직 보낸 것이 없어 유휴(nil)이므로 사건이 없다(동작 G3).
    public mutating func setPeers(_ newPeers: [Peer], at now: ContinuousClock.Instant) -> [Output] {
        var table: [DiscoPublicKey: DiscoKeyHolders] = [:]
        var entries: [NodePublicKey: PeerEntry] = [:]
        var order: [NodePublicKey] = []
        for peer in newPeers where entries[peer.key] == nil {
            let netmapKey = hold(peer.discoKey, for: peer.key, in: &table)
            // 이미 쥔 TSMP 키는 공유 키가 캐시에 있으므로 늘 다시 쥔다.
            _ = hold(peers[peer.key]?.discoKeys.tsmp, for: peer.key, in: &table)
            entries[peer.key] = updatedEntry(peers[peer.key], with: peer, netmapKey: netmapKey, at: now)
            order.append(peer.key)
        }

        var outputs: [Output] = []
        // 이미 nil(유휴)을 알린 피어는 빠져도 다시 알리지 않는다(동작 G2).
        for key in peerOrder where entries[key] == nil && peers[key]?.reportedPath != nil {
            outputs.append(.pathChanged(key, nil))
        }
        peers = entries
        peerOrder = order
        discoPeers = table
        pendingCallMeMaybe.removeAll { entries[$0]?.discoKey == nil }
        for key in order {
            reportPathChange(of: key, at: now, into: &outputs)
        }
        return outputs
    }

    /// 피어 `peer`가 WireGuard 터널 안으로 보낸 TSMP disco 키 광고(동작 T3~T5, Go `HandleDiscoKeyAdvertisement`).
    ///
    /// 노드는 WireGuard가 인증하고 출발지 검사를 통과한 광고만 넘긴다(엔진 `.discoKeyAdvertised`). 그 키가 `peer`의
    /// TSMP 키가 되고 활성이 된다. 다른 피어가 같은 키를 쥐고 있어도 받고, 그 피어는 바뀌지 않는다(Go와 같다). 0 키, 모르는
    /// 피어, 이전 TSMP 키와 같은 키, 공유 키를 계산할 수 없는 키는 아무것도 바꾸지 않는다. 바뀌면 그 피어의 신뢰와 진행
    /// 중인 Ping을 버리고(노트 4.4 3), 경로가 바뀌었으면 `.pathChanged`를 낸다.
    ///
    /// shortcut: netmap 키가 없던 피어(0인 키)는 netmap 엔드포인트를 후보로 쥐지 않았으므로, 광고로 키가 생겨도 후보는
    /// 다음 netmap이나 CallMeMaybe·받은 Ping에서 온다. 필요해지는 시점: netmap에 disco 키가 없는 피어가 광고를 보내는
    /// 일이 실제로 보일 때.
    public mutating func receiveDiscoKeyAdvertisement(
        _ key: DiscoPublicKey,
        from peer: NodePublicKey,
        at now: ContinuousClock.Instant
    ) -> [Output] {
        guard !key.isZero, var entry = peers[peer], entry.discoKeys.tsmp != key,
              let sharedKey = sharedKey(for: key)
        else { return [] }
        let previous = entry.discoKeys.tsmp
        if entry.discoKeys.updateTSMP(key) {
            entry.path.resetForNewDiscoKey()
        }
        peers[peer] = entry
        var holders = discoPeers[key] ?? DiscoKeyHolders(sharedKey: sharedKey, nodes: [])
        if !holders.nodes.contains(peer) {
            holders.nodes.append(peer)
        }
        discoPeers[key] = holders
        // 앞 TSMP 키가 아직 이 피어의 netmap 키면 표에 남긴다(Go는 여기서 빼서 그 키로 온 disco를 버린다. 계약 T5).
        if let previous, previous != entry.discoKeys.netmap {
            release(previous, from: peer)
        }
        var outputs: [Output] = []
        reportPathChange(of: peer, at: now, into: &outputs)
        return outputs
    }

    /// 피어 `peer`가 보낸 것으로 확인된 disco의 보낸 쪽 키를 그 피어의 키와 맞춘다(Go `checkAndUpdateDiscoKey`).
    ///
    /// 비활성 키였으면 활성을 그쪽으로 바꾸고 신뢰와 진행 중인 Ping을 버린다. 바꾸는 것은 `peer`의 상태뿐이다.
    ///
    /// - Returns: 그 피어의 키(활성이든 비활성이든)였는가.
    mutating func noteDiscoKeySeen(_ key: DiscoPublicKey, from peer: NodePublicKey) -> Bool {
        guard let seen = peers[peer]?.discoKeys.noteSeen(key) else { return false }
        if seen.changed {
            peers[peer]?.path.resetForNewDiscoKey()
        }
        return seen.known
    }

    /// `node`를 `key`를 쥔 피어로 `table`에 넣는다. 0이거나 공유 키를 계산할 수 없으면(저차수 키) 넣지 않고 nil.
    private func hold(_ key: DiscoPublicKey?, for node: NodePublicKey, in table: inout [DiscoPublicKey: DiscoKeyHolders]) -> DiscoPublicKey? {
        guard let key, !key.isZero else { return nil }
        if table[key] == nil {
            guard let sharedKey = sharedKey(for: key) else { return nil }
            table[key] = DiscoKeyHolders(sharedKey: sharedKey, nodes: [])
        }
        if table[key]?.nodes.contains(node) == false {
            table[key]?.nodes.append(node)
        }
        return key
    }

    /// `node`가 `key`를 놓는다. 쥔 피어가 남지 않으면 공유 키도 버린다(Go `cleanFromNodesOfDisco`).
    private mutating func release(_ key: DiscoPublicKey, from node: NodePublicKey) {
        discoPeers[key]?.nodes.removeAll { $0 == node }
        if discoPeers[key]?.nodes.isEmpty == true {
            discoPeers[key] = nil
        }
    }

    /// `key`와의 공유 키. 지난 표에 있으면 다시 쓰고, 없을 때만 계산한다. 저차수 키면 nil.
    private func sharedKey(for key: DiscoPublicKey) -> DiscoSharedKey? {
        if let cached = discoPeers[key]?.sharedKey { return cached }
        return try? DiscoSharedKey(privateKey: discoPrivateKey, peerPublicKey: key)
    }

    /// 피어 하나의 다음 상태. disco를 하지 않는 피어에게는 후보를 주지 않아 Ping이 나가지 않는다(DERP만).
    private func updatedEntry(
        _ existing: PeerEntry?,
        with peer: Peer,
        netmapKey: DiscoPublicKey?,
        at now: ContinuousClock.Instant
    ) -> PeerEntry {
        var keys = existing?.discoKeys ?? PeerDiscoKeys()
        let changed = keys.updateNetmap(netmapKey)
        let endpoints = keys.active == nil ? [] : peer.endpoints
        guard var entry = existing else {
            return PeerEntry(discoKeys: keys, path: PeerPathState(homeDERP: peer.homeDERP, endpoints: endpoints))
        }
        if changed {
            if keys.active == nil {
                // disco를 그만두면 Pong이 다시 오지 않으므로 직접 경로의 흔적을 모두 버린다.
                entry.path = PeerPathState(homeDERP: peer.homeDERP, endpoints: [])
            } else {
                entry.path.resetForNewDiscoKey()
            }
        }
        entry.path.update(homeDERP: peer.homeDERP, endpoints: endpoints, at: now)
        entry.discoKeys = keys
        return entry
    }
}
