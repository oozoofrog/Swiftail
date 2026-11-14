// STUN 주소 고르기는 Go 구현을 따랐다.
// 출처: tailscale.com v1.104.6 `net/netcheck/netcheck.go` (`nodeAddrPort`). Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailMagicsock

/// DERPMap(tailcfg)에서 `Magicsock`이 쓸 홈 후보 지역을 뽑는다. `SwiftailMagicsock`은 tailcfg를 모르므로 노드가 옮긴다.
///
/// 입출력 없는 순수 함수다. 노드가 netmap을 받을 때마다 부르고 결과를 `Magicsock.setRegions`에 넣는다(같은 목록이면
/// `Magicsock`이 무시한다). 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N3,
/// `docs/contracts/SwiftailMagicsock.md` 동작 E3.
extension Magicsock.Region {
    /// STUN 포트가 0인 노드의 기본 포트(RFC 5389).
    static let defaultSTUNPort = 3478

    /// 홈으로 고를 수 있는 지역. 지역 ID 오름차순이다.
    ///
    /// `noMeasureNoHome`이 아니고 연결할 수 있는 서버(`DERPServer`)가 하나 이상인 지역만 넣는다(M3의 홈 조건).
    /// STUN 주소는 그 지역의 노드를 순서대로 보며 모은다(`stunOnly` 노드 포함). 점수는 `homeParams.regionScore`.
    static func homeCandidates(in derpMap: DERPMap?) -> [Magicsock.Region] {
        let regions = derpMap?.regions ?? [:]
        let scores = derpMap?.homeParams?.regionScore ?? [:]
        return regions.keys.sorted().compactMap { id in
            guard let region = regions[id], !region.noMeasureNoHome,
                  region.nodes.contains(where: { DERPServer($0) != nil })
            else { return nil }
            return Magicsock.Region(id: id, stunServers: region.nodes.compactMap(stunServer), score: scores[id] ?? 0)
        }
    }

    /// 노드 하나에 STUN을 물을 IPv4 주소. 물을 수 없으면 nil.
    ///
    /// `stunPort`가 음수(또는 범위 밖)면 STUN을 끈 노드다. 0이면 3478. 주소는 `stunTestIP`가 있으면 그것(IPv4가 아니면
    /// 이 노드를 쓰지 않는다), 없으면 `ipv4`가 IPv4 리터럴일 때 그것이다.
    // shortcut: `ipv4`가 빈 노드의 DNS 조회는 하지 않는다(계약 E3). 필요해지는 시점: 리터럴 없는 DERPMap을 만날 때.
    static func stunServer(of node: DERPNode) -> IPEndpoint? {
        let portNumber = node.stunPort == 0 ? defaultSTUNPort : node.stunPort
        guard let port = UInt16(exactly: portNumber) else { return nil }
        let text = node.stunTestIP.isEmpty ? node.ipv4 : node.stunTestIP
        guard let address = IPAddress(text), address.isIPv4 else { return nil }
        return IPEndpoint(address: address, port: port)
    }
}
