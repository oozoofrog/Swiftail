// 엔드포인트 모으기와 집합 비교는 Tailscale의 `net/netcheck/netcheck.go`(`GetGlobalAddrs`, :137-167)와
// `wgengine/magicsock/magicsock.go`(`determineEndpoints`, `endpointSetsEqual`, :1278-1473)(BSD-3-Clause,
// Copyright (c) Tailscale Inc & contributors)를 따른다. 코드는 Swift로 새로 썼다.

import SwiftailBase

extension Netcheck {
    /// 끝난 회차에서 자기 엔드포인트 목록을 만든다(`disco-magicsock.md` 4.9 1, 계약 E4).
    ///
    /// 순서: STUN 전역 주소들(`.stun`), 인터페이스 주소마다 `주소:소켓 포트`(`.local`). 둘 다 비면 loopback 주소들
    /// (`.local`)을 쓴다. 같은 주소는 처음 것만 남긴다. STUN 전역 주소는 회차의 첫 응답 주소와, 그 밖에 두 번 이상 관측된
    /// 주소다. NAT가 새 매핑을 내 주는 망에서 옛 매핑도 함께 알리기 위해서다(Go `GetGlobalAddrs`).
    ///
    /// - `shortcut:` 포트 매핑, 목적지에 따라 달라지는 매핑의 고정 포트 엔드포인트, 5분 10초 광고 캐시, 고정 엔드포인트는 만들지
    ///   않는다(노트 6.2). 필요해지는 시점: 단단한 NAT에서 마무리 관문이 실패할 때.
    func endpointList(from round: Round) -> [Magicsock.Endpoint] {
        let global = round.observations.enumerated()
            .filter { $0.offset == 0 || $0.element.count > 1 }
            .map(\.element.address)
        let local = localAddresses.map { IPEndpoint(address: $0, port: localPort) }
        let fallback = global.isEmpty && local.isEmpty ? loopbackAddresses.map { IPEndpoint(address: $0, port: localPort) } : []

        var list: [Magicsock.Endpoint] = []
        let candidates = global.map { ($0, Magicsock.Endpoint.Source.stun) } + (local + fallback).map { ($0, .local) }
        for (address, source) in candidates where !list.contains(where: { $0.address == address }) {
            list.append(Magicsock.Endpoint(address: address, source: source))
        }
        return list
    }

    /// 두 목록이 집합으로 같은가. 순서는 보지 않는다(Go `endpointSetsEqual`). 두 목록 모두 주소가 겹치지 않는다.
    static func sameSet(_ first: [Magicsock.Endpoint], _ second: [Magicsock.Endpoint]) -> Bool {
        first.count == second.count && first.allSatisfy { second.contains($0) }
    }
}
