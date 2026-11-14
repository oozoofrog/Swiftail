// 경로 집계는 Go 구현을 따라 옮겼다(iOS 규칙, 서브넷 경로·exit node 없음).
// 출처: tailscale.com v1.104.6 `net/routemanager/routemanager.go` (`classify`, `applyDirty`의 CGNAT·ULA 집계,
// `cgnatThreshold`), `ipn/ipnlocal/local.go` (서비스 IP 경로), `tailcfg/nodecap/nodecap.go` (`OneCGNATEnable`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 터널로 보낼 경로의 산출(계약 동작 S2~S4).
///
/// 데이터면에 올린 피어의 AllowedIPs에서 OS 경로를 만든다. OS 경로는 WireGuard AllowedIPs와 다르다. 집계한
/// `/10`·`/48`은 OS에만 주고 AllowedIPs로 쓰지 않는다(`netmap-engine.md` 4.8).
///
/// shortcut: 서브넷 경로·exit node·VIP 서비스 경로는 만들지 않는다. M3부터 `EnginePeer`가 서브넷 경로와 /0을
/// AllowedIPs에서 빼므로(엔진 계약 M3 동작 2) 피어 경로에는 한 주소짜리와 피어 자신의 주소만 온다. 필요해지는
/// 시점: plan 범위를 넓힐 때.
extension TunnelNetworkSettings {
    /// 제어 서버가 `one-cgnat?v=true`를 주면 `/32`를 피어마다 두지 않고 CGNAT `/10` 하나로 모으는 문턱이 1이 된다.
    /// `one-cgnat?v=false`와 아무것도 없는 경우는 같다: iOS의 기본 문턱(`cgnatThreshold`)을 쓴다. 둘이 함께 오면
    /// Go는 `true`를 앞세운다(`control/controlknobs/controlknobs.go`의 `UpdateFromNodeAttributes`).
    static let oneCGNATCapability = "one-cgnat?v=true"

    /// 피어별 CGNAT `/32`를 하나씩 두는 상한. 고유한 `/32`가 이보다 많으면 `100.64.0.0/10` 하나로 모은다.
    /// Go `routemanager.cgnatThreshold`.
    static let cgnatThreshold = 10_000

    /// 피어 경로(정렬)에 서비스 IP 경로를 이어, 자기 주소가 있는 계열만 남긴 경로 목록.
    ///
    /// - Parameters:
    ///   - peers: 데이터면에 올린 피어. 접두는 피어 하나에만 있다(`EnginePeer.peers`가 보장한다).
    ///   - oneCGNAT: 제어 지시 `one-cgnat?v=true`. 참이면 CGNAT `/32`가 둘만 돼도 `/10` 하나로 모은다.
    static func routes(for peers: [EnginePeer], oneCGNAT: Bool, hasIPv4: Bool, hasIPv6: Bool) -> [IPPrefix] {
        let serviceRoutes = Self.serviceRoutes(hasIPv4: hasIPv4, hasIPv6: hasIPv6)
        let cgnatRange = IPPrefix("100.64.0.0/10")
        let tailscaleULA = IPPrefix("fd7a:115c:a1e0::/48")

        var cgnatHosts: Set<IPPrefix> = []
        var hasULAHost = false
        var others: Set<IPPrefix> = []
        // 서비스 IP는 아래에서 한 번만, 맨 뒤에 둔다. 피어가 그 주소를 내세워도 경로가 겹치지 않게 뺀다.
        for prefix in peers.lazy.flatMap(\.allowedIPs) where !Self.allServiceRoutes.contains(prefix) {
            let isSingleAddress = EnginePeer.isSingleAddress(prefix)
            if isSingleAddress, cgnatRange?.contains(prefix.address) == true {
                cgnatHosts.insert(prefix)
            } else if isSingleAddress, tailscaleULA?.contains(prefix.address) == true {
                // 한 주소짜리 ULA는 하나라도 있으면 /48 하나로 모은다(개별 /128은 두지 않는다).
                hasULAHost = true
            } else {
                others.insert(prefix)
            }
        }

        var routes = others
        if cgnatHosts.count > (oneCGNAT ? 1 : Self.cgnatThreshold) {
            routes.formUnion([cgnatRange].compactMap { $0 })
        } else {
            routes.formUnion(cgnatHosts)
        }
        if hasULAHost {
            routes.formUnion([tailscaleULA].compactMap { $0 })
        }

        // 계열 거르기(동작 S4): 자기 주소가 없는 계열로는 패킷이 나가지 않으므로 경로를 두지 않는다.
        let ordered = routes
            .filter { $0.address.isIPv4 ? hasIPv4 : hasIPv6 }
            .sorted(by: Self.precedes)
        return ordered + serviceRoutes
    }

    /// 서비스 IP 경로: 자기 주소에 IPv4가 있으면 `100.100.100.100/32`, IPv6가 있으면 `fd7a:115c:a1e0::53/128`.
    private static func serviceRoutes(hasIPv4: Bool, hasIPv6: Bool) -> [IPPrefix] {
        // 리터럴이라 해석에 실패하지 않는다. 시험이 내용을 확인한다.
        [("\(ServiceIP.ipv4Text)/32", hasIPv4), ("\(ServiceIP.ipv6Text)/128", hasIPv6)]
            .compactMap { text, wanted in wanted ? IPPrefix(text) : nil }
    }

    /// 두 서비스 IP의 경로(IPv4가 먼저).
    private static var allServiceRoutes: [IPPrefix] {
        serviceRoutes(hasIPv4: true, hasIPv6: true)
    }

    /// IPv4가 먼저, 같은 계열은 주소 바이트 순, 같으면 접두 길이 순(계약 동작 S2).
    private static func precedes(_ lhs: IPPrefix, _ rhs: IPPrefix) -> Bool {
        if lhs.address.isIPv4 != rhs.address.isIPv4 { return lhs.address.isIPv4 }
        if lhs.address.bytes != rhs.address.bytes {
            return lhs.address.bytes.lexicographicallyPrecedes(rhs.address.bytes)
        }
        return lhs.length < rhs.length
    }
}
