// DNS 영역 산출은 Go 구현을 따라 옮겼고, 이름 검사는 Go `dnsname.ToFQDN`보다 엄격하다.
// 출처: tailscale.com v1.104.6 `ipn/ipnlocal/node_backend.go` (`dnsConfigForNetmap`), `ipn/ipnlocal/local.go`
// (`magicDNSRootDomains`), `types/netmap/netmap.go` (`MagicDNSSuffixOfNodeName`), `net/dns/config.go`
// (`serviceIPs`, `matchDomains`), `util/dnsname/dnsname.go` (`ToFQDN`, `FQDN.Contains`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Foundation
import SwiftailBase
import SwiftailControl

/// OS에 줄 DNS 설정의 산출(계약 동작 S5, DNS 노트 4.1.4).
///
/// 노드가 직접 답하는 영역(`localZones`)만 OS의 match 도메인으로 준다. 이 영역의 질의만 서비스 IP로 오고,
/// 그 밖의 이름은 OS의 기본 DNS가 푼다(결정 D1). 같은 `localZones`가 MagicDNS 응답기의 영역이 된다(동작 S7).
///
/// shortcut: 전역 `Resolvers`, 리졸버가 있는 `Routes`, `FallbackResolvers`는 쓰지 않고(결정 D2), 검색 도메인
/// `Domains`도 내지 않는다(결정 D3). 4via6 이름과 `dns-subdomain-resolve`도 없다. 필요해지는 시점: 사용자 지정 분할
/// DNS를 터널로 풀어야 하거나 짧은 이름 해석이 요구될 때.
extension TunnelNetworkSettings {
    /// 제어 서버가 이 속성을 주면 IPv6 서비스 IP를 DNS 서버로 알리지 않는다(Go `ForceRegisterMagicDNSIPv4Only`).
    static let ipv4OnlyDNSCapability = "force-register-magicdns-ipv4-only"

    /// DNS 서버로 알릴 서비스 IP. 자기 주소가 있는 계열만, IPv4가 먼저다.
    ///
    /// Go의 `serviceIPs`는 IPv4 전용 노드에도 IPv6 서비스 IP를 넣지만, 그 노드에는 IPv6 서비스 경로가 없어
    /// 질의가 닿지 않는다. 그래서 자기 주소 계열로 거른다. 속성이 있어도 IPv6 전용 노드는 IPv6 서비스 IP를 쓴다
    /// (Go도 `OnlyIPv6`를 속성보다 앞세운다).
    static func dnsServers(hasIPv4: Bool, hasIPv6: Bool, ipv4Only: Bool) -> [IPAddress] {
        let wantsIPv6 = hasIPv6 && !(ipv4Only && hasIPv4)
        return [("100.100.100.100", hasIPv4), ("fd7a:115c:a1e0::53", wantsIPv6)]
            .compactMap { text, wanted in wanted ? IPAddress(text) : nil }
    }

    /// 노드가 직접 답하는 영역. 소문자 FQDN(끝 점 포함)이고 끝 점 포함 문자열 순으로 정렬되어 있다.
    /// 자기 키가 만료됐거나 DNS 설정이 없으면 비어 있다(닫힌 쪽: DNS를 설정하지 않는다).
    ///
    /// 영역은 다음의 합집합이다.
    /// - `Proxied`(MagicDNS)면 MagicDNS 접미사, `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.`, `64`~`127.100.in-addr.arpa.`.
    /// - 리졸버 목록이 빈 `Routes`의 키.
    /// - 어느 영역에도 덮이지 않는 유효한 `ExtraRecords` 이름. "덮임"은 Go처럼 리졸버가 있는 `Routes`의 키도 센다.
    ///
    /// 제어 서버가 준 이름은 match 도메인으로 쓸 수 있는 것만 받는다(`zoneName`). 루트(`.`)는 받지 않는다.
    /// iOS에서 빈 match 도메인은 모든 이름을 이 리졸버에 보내는 뜻이라서다.
    static func localZones(in netmap: Netmap, at now: Date) -> [String] {
        guard let dns = netmap.dnsConfig, !isExpired(netmap.selfNode, at: now) else { return [] }

        var zones: Set<String> = []
        // Go의 `dcfg.Routes` 키. `ExtraRecords`가 덮였는지 가릴 때 쓴다.
        var routeKeys: [String] = []

        if dns.proxied {
            for zone in magicDNSZones(selfName: netmap.selfNode.name) {
                zones.insert(zone)
                routeKeys.append(zone)
            }
        }
        for (suffix, resolvers) in dns.routes {
            guard let zone = zoneName(suffix) else { continue }
            routeKeys.append(zone)
            if resolvers.isEmpty, zone != "." {
                zones.insert(zone)
            }
        }
        // `routes`가 사전이라 순서가 없지만, 덮임은 키 전체와의 비교이므로 순서와 무관하다. 앞선 `ExtraRecords`가 만든
        // 영역은 뒤의 것을 덮는다(Go와 같다).
        for record in dns.extraRecords {
            guard ["", "A", "AAAA"].contains(record.type),
                  IPAddress(record.value) != nil,
                  let name = zoneName(record.name), name != ".",
                  !routeKeys.contains(where: { contains(zone: $0, name: name) })
            else { continue }
            zones.insert(name)
            routeKeys.append(name)
        }

        return zones.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
    }

    /// MagicDNS 영역 66개: 접미사 하나, IPv6 역방향 하나, `64`~`127.100.in-addr.arpa.` 64개.
    /// 접미사는 자기 노드 `Name`에서 앞뒤 점을 떼고 첫 레이블을 뗀 나머지다. 접미사가 없거나 이름으로 쓸 수 없으면
    /// 영역이 하나도 없다(Go `magicDNSRootDomains`).
    private static func magicDNSZones(selfName: String) -> [String] {
        let name = selfName.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let suffix = name.firstIndex(of: ".").map { String(name[name.index(after: $0)...]) } ?? name
        guard !suffix.isEmpty, let suffixZone = zoneName(suffix), suffixZone != "." else { return [] }
        return [suffixZone, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."] + (64...127).map { "\($0).100.in-addr.arpa." }
    }

    /// 노드의 키가 만료됐다: 만료 표지가 있거나 키 만료 시각이 지났다(같은 시각 포함. `EnginePeer`와 같은 규칙).
    // shortcut: 로컬 시계로 판단한다. Go는 ControlTime과 1분 넘게 어긋난 시계를 보정한다.
    private static func isExpired(_ node: Node, at now: Date) -> Bool {
        node.expired || (node.keyExpiry.map { $0 <= now } ?? false)
    }

    /// DNS 이름을 소문자 FQDN(끝 점 포함)으로 바꾼다. match 도메인으로 쓸 수 없으면 `nil`. 루트는 `"."`다.
    ///
    /// Go `ToFQDN`처럼 앞 점 하나와 끝 점을 허용하고, 전체 길이가 254바이트를 넘거나 공백·제어 문자가 있으면
    /// 거절한다. 더해서 모든 레이블이 1…63바이트여야 하고(Go는 마지막 레이블을 보지 않는다), ASCII가 아닌 바이트는
    /// 거절한다. 이 이름은 OS 설정과 질의 비교에 그대로 쓰이므로 닫힌 쪽으로 좁힌다.
    private static func zoneName(_ text: String) -> String? {
        var name = text.utf8[...]
        if name.first == UInt8(ascii: ".") { name = name.dropFirst() }
        if name.last == UInt8(ascii: ".") { name = name.dropLast() }
        if name.isEmpty { return "." }
        guard name.count + 1 <= 254,
              name.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
              name.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false).allSatisfy({ (1...63).contains($0.count) })
        else { return nil }
        let lowercased = name.map { ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z")) ? $0 + 32 : $0 }
        return String(decoding: lowercased, as: UTF8.self) + "."
    }

    /// `zone`이 `name`과 같거나 그 상위 영역이다(Go `FQDN.Contains`). 루트는 모든 이름을 덮는다.
    private static func contains(zone: String, name: String) -> Bool {
        zone == name || zone == "." || name.hasSuffix("." + zone)
    }
}
