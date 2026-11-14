// 피어 자격과 AllowedIPs 분류는 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `net/routemanager/routemanager.go` (`peerPrefixes`, `isSelfPrefix`),
// `net/tsaddr/tsaddr.go` (`IsTailscaleIP`), `ipn/ipnlocal/expiry.go`.
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Foundation
import SwiftailBase
import SwiftailControl

/// netmap의 피어 하나를 데이터면에 올린 모습.
///
/// M3은 서브넷 경로와 exit node를 받지 않는다(Go의 `RouteAll=false`, exit node 없음과 같다). 그래서 피어가
/// 출발지로 쓸 수 있는 주소는 피어 자신의 tailnet 주소뿐이다. 지원하지 않는 피어는 올리지 않는다(닫힌 쪽).
///
/// `docs/protocol-notes/netmap-engine.md` 4.1·4.3, `docs/contracts/SwiftailEngine.md` 동작 2.
public struct EnginePeer: Sendable, Equatable {
    /// 피어의 node 키. WireGuard 공개 키와 같다.
    public var key: NodePublicKey
    /// 이 피어가 출발지로 쓸 수 있는 주소. WireGuard AllowedIPs가 된다.
    public var allowedIPs: [IPPrefix]
    /// 이 피어에게 보낼 때 쓸 DERP 지역. 0이면 모른다.
    public var homeDERP: Int64

    /// netmap에서 데이터면에 올릴 피어들을 고른다. 순서는 node ID 오름차순이다.
    ///
    /// 키 하나는 피어 하나에만, 접두 하나도 피어 하나에만 준다. 같은 키나 같은 접두를 여러 노드가 내세우면
    /// node ID가 작은 쪽이 갖는다. 접두의 주인이 하나여야 "이 출발 주소는 이 피어"가 성립한다
    /// (wireguard-go의 AllowedIPs도 접두마다 주인이 하나다).
    ///
    /// - Parameter now: 키 만료를 판단할 지금 시각(로컬 벽시계).
    public static func peers(in netmap: Netmap, at now: Date) -> [EnginePeer] {
        eligibleNodes(in: netmap, at: now).map(\.peer)
    }

    /// 올릴 피어와 그 노드. 엔진이 노드의 주소로 송신 경로 색인을 만들 때 쓴다.
    static func eligibleNodes(in netmap: Netmap, at now: Date) -> [(node: Node, peer: EnginePeer)] {
        var claimedKeys: Set<NodePublicKey> = []
        var claimedPrefixes: Set<IPPrefix> = []
        var result: [(node: Node, peer: EnginePeer)] = []
        for node in netmap.peers.sorted(by: { $0.id < $1.id }) {
            guard var peer = EnginePeer(node: node, at: now), !claimedKeys.contains(peer.key) else { continue }
            peer.allowedIPs.removeAll { claimedPrefixes.contains($0) }
            guard !peer.allowedIPs.isEmpty else { continue }
            claimedKeys.insert(peer.key)
            claimedPrefixes.formUnion(peer.allowedIPs)
            result.append((node, peer))
        }
        return result
    }

    /// 노드를 올릴 수 없으면 `nil`.
    private init?(node: Node, at now: Date) {
        guard node.id != 0, !node.key.isZero,
              !Self.isExpired(node, at: now),
              // disco 키도 홈 DERP도 없으면 닿을 길이 없다.
              !(node.discoKey.isZero && node.homeDERP == 0),
              Self.isSupported(node)
        else { return nil }

        // AllowedIPs 가운데 피어 자신의 주소만 남긴다: 한 주소짜리 tailnet 주소이거나 `addresses`에 있는 것.
        // 서브넷 경로와 /0은 여기서 빠진다. `addresses`에 있다고 새로 더하지는 않는다.
        // shortcut: Go는 호스트 비트가 남은 원문 접두를 빼지만, 여기서는 구분하지 못한다(`IPPrefix`가 해독할 때 지운다).
        var allowedIPs: [IPPrefix] = []
        for prefix in node.allowedIPs where !allowedIPs.contains(prefix) {
            if (Self.isSingleAddress(prefix) && Self.isTailscaleAddress(prefix.address)) || node.addresses.contains(prefix) {
                allowedIPs.append(prefix)
            }
        }
        guard !allowedIPs.isEmpty else { return nil }

        key = node.key
        self.allowedIPs = allowedIPs
        homeDERP = node.homeDERP
    }

    /// 만료 표지가 있거나 키 만료 시각이 지났다(같은 시각 포함).
    // shortcut: 로컬 시계로 판단한다. Go는 ControlTime과 1분 넘게 어긋난 시계를 보정한다.
    private static func isExpired(_ node: Node, at now: Date) -> Bool {
        if node.expired { return true }
        guard let expiry = node.keyExpiry else { return false }
        return expiry <= now
    }

    /// M3이 지원하지 않는 피어: WireGuard 전용, jailed, masquerade 주소가 있는 피어, 그리고 tailnet lock의
    /// 서명이 없어 PeerAPI만 허용되는 피어(`UnsignedPeerAPIOnly`). 마지막 것은 Go가 필터의 패킷 규칙과
    /// 겹치면 규칙 전체를 비우는 안전장치를 두는 피어다(노트 4.5의 4). 여기서는 아예 올리지 않는다.
    private static func isSupported(_ node: Node) -> Bool {
        !node.isWireGuardOnly
            && !node.isJailed
            && !node.unsignedPeerAPIOnly
            && node.selfNodeV4MasqAddrForThisPeer == nil
            && node.selfNodeV6MasqAddrForThisPeer == nil
    }

    /// /32 또는 /128.
    static func isSingleAddress(_ prefix: IPPrefix) -> Bool {
        prefix.length == prefix.address.bytes.count * 8
    }

    /// Tailscale 주소 범위: `100.64.0.0/10`(`100.115.92.0/23` 제외)과 `fd7a:115c:a1e0::/48`.
    static func isTailscaleAddress(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        if address.isIPv4 {
            let inCGNAT = bytes[0] == 100 && bytes[1] & 0xC0 == 64
            // ChromeOS VM 대역 100.115.92.0/23은 CGNAT 안에 있지만 tailnet 주소가 아니다.
            let inChromeOSRange = bytes[0] == 100 && bytes[1] == 115 && bytes[2] & 0xFE == 92
            return inCGNAT && !inChromeOSRange
        }
        return bytes.starts(with: [0xFD, 0x7A, 0x11, 0x5C, 0xA1, 0xE0])
    }
}
