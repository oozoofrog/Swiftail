// 피어 집합의 판정: 서명 검증과 회전으로 낡은 키. 노트 4.9, 계약 동작 P1~P5.
// Go `tailscale.com` v1.104.7 `ipn/ipnlocal/tailnet-lock.go:189-338`(`tkaFilterNetmapLocked`의 거르기와 `rotationTracker`)을 옮겼다.
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailBase

/// 피어 하나의 판정 입력(netmap의 `Node`에서 쓰는 것만).
package struct PeerCredential: Sendable {
    package var nodeKey: NodePublicKey
    /// `Node.KeySignature`의 바이트. 비면 서명 없음이다.
    package var keySignature: [UInt8]
    /// `Node.UnsignedPeerAPIOnly`. 서명 검사를 받지 않지만, 다른 피어의 회전으로 낡은 키가 되면 Go처럼 빠진다.
    package var unsignedPeerAPIOnly: Bool

    package init(nodeKey: NodePublicKey, keySignature: [UInt8], unsignedPeerAPIOnly: Bool) {
        self.nodeKey = nodeKey
        self.keySignature = keySignature
        self.unsignedPeerAPIOnly = unsignedPeerAPIOnly
    }
}

extension AuthorityState {
    /// 피어마다 netmap에 남기는가(Go `tkaFilterNetmapLocked`의 피어 부분). 입력과 같은 순서다.
    ///
    /// 빠지는 것: 서명이 없거나 `authorize`를 통과하지 못한 피어(`UnsignedPeerAPIOnly`는 보지 않는다), 그리고 node 키가
    /// 회전으로 낡은 키인 피어(`UnsignedPeerAPIOnly`를 포함해 모든 피어). 낡은 키는 통과한 rotation의 `previousNodeKeys` 전부와,
    /// `initialSignature`가 direct인 rotation을 그 `WrappingPubkey`로 묶은 묶음마다 내력이 가장 길지 않은 것이다. 가장 긴 것이
    /// 둘 이상이면 그 묶음 전부가 낡은 키다. credential에서 시작한 사슬은 묶지 않는다(재사용 인증 키로 여러 노드가 들어온다).
    ///
    /// 묶음을 보는 순서는 묶음이 처음 나온 피어의 순서다. Go는 맵을 돌아 순서가 정해지지 않는데, 한 묶음의 판정이 다른 묶음의
    /// 판정을 바꾸는 것은 같은 node 키가 서로 다른 회전 키의 묶음에 함께 들 때뿐이다.
    package func admitted(_ peers: [PeerCredential]) -> [Bool] {
        var rejected = [Bool](repeating: false, count: peers.count)
        var obsolete: Set<NodePublicKey> = []
        var groups: [(rotationKey: [UInt8], members: [(nodeKey: NodePublicKey, previousKeyCount: Int)])] = []
        for (index, peer) in peers.enumerated() where !peer.unsignedPeerAPIOnly {
            let details: RotationDetails?
            do {
                // 빈 서명(Go의 "missing signature")은 디코딩에서 떨어지므로 따로 보지 않는다.
                details = try authorize(peer.nodeKey, keySignature: peer.keySignature)
            } catch {
                rejected[index] = true
                continue
            }
            guard let details else { continue }
            obsolete.formUnion(details.previousNodeKeys)
            guard details.initialSignature.kind == NodeKeySignature.Kind.direct else { continue }
            let member = (nodeKey: peer.nodeKey, previousKeyCount: details.previousNodeKeys.count)
            let rotationKey = details.initialSignature.wrappingPublicKey
            if let group = groups.firstIndex(where: { $0.rotationKey == rotationKey }) {
                groups[group].members.append(member)
            } else {
                groups.append((rotationKey, [member]))
            }
        }
        for group in groups {
            // 다른 서명이 이미 낡은 키로 만든 것은 견주지 않는다.
            let members = group.members.filter { !obsolete.contains($0.nodeKey) }
            guard let longest = members.map(\.previousKeyCount).max() else { continue }
            let isUnique = members.count(where: { $0.previousKeyCount == longest }) == 1
            obsolete.formUnion(members.filter { !isUnique || $0.previousKeyCount != longest }.map(\.nodeKey))
        }
        return peers.indices.map { !rejected[$0] && !obsolete.contains(peers[$0].nodeKey) }
    }
}
