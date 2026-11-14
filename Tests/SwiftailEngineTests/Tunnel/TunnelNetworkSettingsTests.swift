// 계약 동작 S(설정 산출)의 시험. 기대값은 계약과 노트(엔진 노트 4.8, DNS 노트 4.1.4), Go 소스에서 정했다.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("터널 설정: 자기 주소")
struct TunnelSettingsAddressTests {
    @Test("IPv4와 IPv6가 모두 있으면 netmap 순서대로 /32, /128")
    func dualStack() throws {
        let settings = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128", "100.64.0.1/32"]))
        #expect(settings.addresses.map(\.description) == ["fd7a:115c:a1e0::1/128", "100.64.0.1/32"])
    }

    @Test("IPv4만, IPv6만")
    func singleFamily() throws {
        let v4 = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"]))
        #expect(v4.addresses.map(\.description) == ["100.64.0.1/32"])
        let v6 = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128"]))
        #expect(v6.addresses.map(\.description) == ["fd7a:115c:a1e0::1/128"])
    }

    @Test("자기 주소가 없으면 nil, 한 주소짜리가 아닌 접두만 있어도 nil")
    func noAddress() throws {
        #expect(try TunnelNetworkSettings(netmap: SettingsFixture.netmap(selfAddresses: []), mtu: 1280, at: wallClockStart) == nil)
        let wide = try SettingsFixture.netmap(selfAddresses: ["100.64.0.0/24", "fd7a:115c:a1e0::/64"])
        #expect(TunnelNetworkSettings(netmap: wide, mtu: 1280, at: wallClockStart) == nil)
    }

    @Test("한 주소짜리가 아닌 접두와 중복은 버린다")
    func filtersAddresses() throws {
        let netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.0/24", "100.64.0.1/32", "100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
        #expect(try SettingsFixture.settings(netmap).addresses.map(\.description) == ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
    }

    @Test("MTU는 장치 값 그대로다")
    func mtuPassesThrough() throws {
        let netmap = try SettingsFixture.netmap()
        for mtu in [1280, 1420, 1500] {
            #expect(try SettingsFixture.settings(netmap, mtu: mtu).mtu == mtu)
        }
    }
}

@Suite("터널 설정: 경로")
struct TunnelSettingsRouteTests {
    @Test("피어마다 /32, 뒤에 서비스 IP 경로")
    func perPeerAndService() throws {
        let netmap = try SettingsFixture.netmap(
            selfAddresses: ["100.64.0.1/32"],
            peers: [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32"]), SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32"])])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == ["100.64.0.2/32", "100.64.0.3/32", "100.100.100.100/32"])
    }

    @Test("피어 IPv6는 /128 대신 ULA /48 하나, 서비스 경로는 IPv4 다음 IPv6")
    func ulaAggregate() throws {
        let netmap = try SettingsFixture.netmap(peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32", "fd7a:115c:a1e0::3/128"]),
        ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == [
            "100.64.0.2/32", "100.64.0.3/32", "fd7a:115c:a1e0::/48", "100.100.100.100/32", "fd7a:115c:a1e0::53/128",
        ])
    }

    @Test("피어가 없어도 서비스 IP 경로는 있다")
    func serviceRoutesOnly() throws {
        #expect(try SettingsFixture.settings(SettingsFixture.netmap()).routes.map(\.description) == ["100.100.100.100/32", "fd7a:115c:a1e0::53/128"])
        #expect(try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"])).routes.map(\.description) == ["100.100.100.100/32"])
        #expect(try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128"])).routes.map(\.description) == ["fd7a:115c:a1e0::53/128"])
    }

    @Test("자기 주소가 없는 계열의 경로는 뺀다")
    func familyFilter() throws {
        let peers = [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])]
        let v4Only = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: peers))
        #expect(v4Only.routes.map(\.description) == ["100.64.0.2/32", "100.100.100.100/32"])
        let v6Only = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128"], peers: peers))
        #expect(v6Only.routes.map(\.description) == ["fd7a:115c:a1e0::/48", "fd7a:115c:a1e0::53/128"])
    }

    @Test("정렬: IPv4가 먼저, 주소 바이트 순(문자열 순이 아니다), 접두 길이 순")
    func ordering() throws {
        let netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.200/32"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.9/32"]),
            SettingsFixture.peer(id: 4, addresses: ["100.64.0.5/32"]),
            // 피어 자신의 주소는 tailnet 범위 밖이어도 올라간다. CGNAT가 아니므로 집계되지 않고 그대로 나온다.
            SettingsFixture.peer(id: 5, addresses: ["10.1.2.3/32"]),
        ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == [
            "10.1.2.3/32", "100.64.0.5/32", "100.64.0.9/32", "100.64.0.200/32", "100.100.100.100/32",
        ])
    }

    @Test("만료됐거나 지원하지 않는 피어는 경로에서 빠진다")
    func excludedPeers() throws {
        let netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32"], extra: #","Expired":true"#),
            // 키 만료 시각이 지금과 같으면 만료다(EnginePeer와 같은 규칙).
            SettingsFixture.peer(id: 4, addresses: ["100.64.0.4/32"], extra: #","KeyExpiry":"2027-01-15T08:00:00Z""#),
            SettingsFixture.peer(id: 5, addresses: ["100.64.0.5/32"], extra: #","IsWireGuardOnly":true"#),
            SettingsFixture.peer(id: 6, addresses: ["100.64.0.6/32"], extra: #","IsJailed":true"#),
            // disco 키도 홈 DERP도 없는 피어는 닿을 길이 없다.
            SettingsFixture.node(id: 7, addresses: ["100.64.0.7/32"]),
            SettingsFixture.peer(id: 8, addresses: ["100.64.0.8/32"], extra: #","KeyExpiry":"2027-01-15T09:00:00Z""#),
        ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == ["100.64.0.2/32", "100.64.0.8/32", "100.100.100.100/32"])
    }

    @Test("피어가 서비스 IP를 주소로 내세워도 서비스 경로는 하나이고 맨 뒤에 있다")
    func peerClaimingServiceIP() throws {
        let netmap = try SettingsFixture.netmap(
            selfAddresses: ["100.64.0.1/32"],
            peers: [SettingsFixture.peer(id: 2, addresses: ["100.100.100.100/32", "100.64.0.2/32"])])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == ["100.64.0.2/32", "100.100.100.100/32"])
    }

    @Test("CGNAT 문턱: 고유한 /32가 10,000개면 하나씩, 10,001개면 100.64.0.0/10 하나")
    func cgnatThresholdBoundary() throws {
        let peers = (0...10_000).map { SettingsFixture.peer(id: Int64($0) + 2, addresses: [SettingsFixture.cgnatAddress($0 + 256)]) }
        var netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: peers)

        #expect(netmap.peers.count == 10_001)
        let coarse = try SettingsFixture.settings(netmap)
        #expect(coarse.routes.map(\.description) == ["100.64.0.0/10", "100.100.100.100/32"])

        netmap.peers.removeLast()
        let fine = try SettingsFixture.settings(netmap)
        #expect(fine.routes.count == 10_001)
        #expect(fine.routes.first?.description == "100.64.1.0/32")
        #expect(fine.routes.last?.description == "100.100.100.100/32")
        #expect(Set(fine.routes).count == 10_001)
    }

    @Test("OneCGNAT 제어 지시: v=true면 문턱 1(둘부터 /10), v=false와 없음은 기본")
    func oneCGNATDirective() throws {
        let one = [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32"])]
        let two = one + [SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32"])]
        let enable = #","CapMap":{"one-cgnat?v=true":[]}"#
        let disable = #","CapMap":{"one-cgnat?v=false":[]}"#
        let both = #","CapMap":{"one-cgnat?v=true":[],"one-cgnat?v=false":[]}"#

        func routes(_ peers: [String], _ capMap: String) throws -> [String] {
            try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], selfExtra: capMap, peers: peers)).routes.map(\.description)
        }
        #expect(try routes(one, enable) == ["100.64.0.2/32", "100.100.100.100/32"])
        #expect(try routes(two, enable) == ["100.64.0.0/10", "100.100.100.100/32"])
        #expect(try routes(two, disable) == ["100.64.0.2/32", "100.64.0.3/32", "100.100.100.100/32"])
        #expect(try routes(two, "") == ["100.64.0.2/32", "100.64.0.3/32", "100.100.100.100/32"])
        // 둘이 함께 오면 Go는 true를 앞세운다.
        #expect(try routes(two, both) == ["100.64.0.0/10", "100.100.100.100/32"])
        // 옛 `Capabilities` 목록으로 와도 같다(세션이 CapMap에 합친다).
        let legacy = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], selfExtra: #","Capabilities":["one-cgnat?v=true"]"#, peers: two)
        #expect(try SettingsFixture.settings(legacy).routes.map(\.description) == ["100.64.0.0/10", "100.100.100.100/32"])
    }

    @Test("OneCGNAT가 IPv6 ULA 집계에는 영향이 없다")
    func oneCGNATKeepsULA() throws {
        let netmap = try SettingsFixture.netmap(
            selfExtra: #","CapMap":{"one-cgnat?v=true":[]}"#,
            peers: [
                SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"]),
                SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32", "fd7a:115c:a1e0::3/128"]),
            ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == [
            "100.64.0.0/10", "fd7a:115c:a1e0::/48", "100.100.100.100/32", "fd7a:115c:a1e0::53/128",
        ])
    }

    @Test("피어 순서를 섞어도 같은 값이다")
    func determinism() throws {
        let peers = (2...40).map { SettingsFixture.peer(id: Int64($0), addresses: ["100.64.0.\(100 - $0)/32", "fd7a:115c:a1e0::\($0)/128"]) }
        let netmap = try SettingsFixture.netmap(peers: peers)
        let expected = try SettingsFixture.settings(netmap)
        var random = FuzzRandom(seed: 5)
        for _ in 0..<5 {
            var shuffled = netmap
            shuffled.peers.shuffle(using: &random)
            #expect(try SettingsFixture.settings(shuffled) == expected)
        }
        var reversed = netmap
        reversed.peers.reverse()
        #expect(try SettingsFixture.settings(reversed) == expected)
    }
}

@Suite("터널 설정: DNS")
struct TunnelSettingsDNSTests {
    /// 접미사 하나(`tail0001.ts.net`)와 역방향 영역 65개. 계약 동작 S5의 66개를 독립적으로 적었다.
    static let magicDNSDomains: [String] = {
        let zones = ["tail0001.ts.net", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"] + (64...127).map { "\($0).100.in-addr.arpa" }
        // 끝 점 포함 문자열 순으로 정렬한 뒤 점을 뗀다.
        return zones.map { $0 + "." }.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }.map { String($0.dropLast()) }
    }()

    private func dns(_ dnsConfig: String?, selfAddresses: [String] = SettingsFixture.selfAddresses, selfName: String? = nil, selfExtra: String = "") throws -> TunnelNetworkSettings {
        try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: selfAddresses, selfName: selfName, selfExtra: selfExtra, dns: dnsConfig))
    }

    @Test("MagicDNS가 켜지면 서비스 IP(IPv4 먼저)와 66개 영역")
    func magicDNSOn() throws {
        let settings = try dns(#"{"Proxied":true}"#)
        #expect(settings.dnsServers.map(\.description) == ["100.100.100.100", "fd7a:115c:a1e0::53"])
        #expect(Self.magicDNSDomains.count == 66)
        #expect(settings.dnsMatchDomains == Self.magicDNSDomains)
        #expect(settings.dnsMatchDomains.allSatisfy { !$0.hasSuffix(".") })
    }

    @Test("DNS 서버는 자기 주소 계열에 맞춘다")
    func serversFollowFamily() throws {
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["100.64.0.1/32"]).dnsServers.map(\.description) == ["100.100.100.100"])
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["fd7a:115c:a1e0::1/128"]).dnsServers.map(\.description) == ["fd7a:115c:a1e0::53"])
    }

    @Test("force-register-magicdns-ipv4-only면 IPv4 서비스 IP만. IPv6 전용 노드는 IPv6를 쓴다")
    func ipv4OnlyKnob() throws {
        let knob = #","CapMap":{"force-register-magicdns-ipv4-only":[]}"#
        #expect(try dns(#"{"Proxied":true}"#, selfExtra: knob).dnsServers.map(\.description) == ["100.100.100.100"])
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["100.64.0.1/32"], selfExtra: knob).dnsServers.map(\.description) == ["100.100.100.100"])
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["fd7a:115c:a1e0::1/128"], selfExtra: knob).dnsServers.map(\.description) == ["fd7a:115c:a1e0::53"])
    }

    @Test("MagicDNS가 꺼지면(영역이 없으면) DNS를 설정하지 않는다")
    func magicDNSOff() throws {
        for config in [#"{"Proxied":false}"#, "{}", #"{"Proxied":false,"Routes":{}}"#] {
            let settings = try dns(config)
            #expect(settings.dnsServers.isEmpty, "\(config)")
            #expect(settings.dnsMatchDomains.isEmpty, "\(config)")
        }
    }

    @Test("DNS 설정 자체가 없어도 DNS를 설정하지 않는다")
    func noDNSConfig() throws {
        let settings = try dns(nil)
        #expect(settings.dnsServers.isEmpty && settings.dnsMatchDomains.isEmpty)
        #expect(!settings.addresses.isEmpty && !settings.routes.isEmpty)
    }

    @Test("MagicDNS 접미사가 없으면(자기 이름이 없으면) 영역이 없다")
    func noSuffix() throws {
        let settings = try dns(#"{"Proxied":true}"#, selfName: "")
        #expect(settings.dnsServers.isEmpty && settings.dnsMatchDomains.isEmpty)
        // 이름의 점만 있어도 접미사가 없다.
        #expect(try dns(#"{"Proxied":true}"#, selfName: "...").dnsMatchDomains.isEmpty)
        // 접미사가 없어도 다른 영역은 그대로 낸다.
        let extra = try dns(#"{"Proxied":true,"Routes":{"corp.example.com":[]}}"#, selfName: "")
        #expect(extra.dnsMatchDomains == ["corp.example.com"])
        #expect(extra.dnsServers.count == 2)
    }

    @Test("자기 노드 이름의 앞 레이블을 뗀 것이 접미사다")
    func suffixFromSelfName() throws {
        #expect(try dns(#"{"Proxied":true}"#, selfName: "Phone-1.TAIL0002.example.net").dnsMatchDomains.contains("tail0002.example.net"))
        #expect(try dns(#"{"Proxied":true}"#, selfName: ".phone.tail0003.ts.net.").dnsMatchDomains.contains("tail0003.ts.net"))
    }

    @Test("리졸버가 빈 Routes는 영역이고, 리졸버가 있는 Routes와 전역 Resolvers는 쓰지 않는다")
    func routesAndResolvers() throws {
        let config = #"""
        {"Proxied":false,"Resolvers":[{"Addr":"192.0.2.53"}],"FallbackResolvers":[{"Addr":"192.0.2.54"}],
         "Domains":["search.example.com"],
         "Routes":{"corp.example.com":[],"null.example.com":null,"split.example.com":[{"Addr":"192.0.2.55"}]}}
        """#
        let settings = try dns(config)
        #expect(settings.dnsMatchDomains == ["corp.example.com", "null.example.com"])
        #expect(settings.dnsServers.map(\.description) == ["100.100.100.100", "fd7a:115c:a1e0::53"])

        // 전역 Resolvers만 있고 영역이 없으면 DNS를 설정하지 않는다(OS 기본 DNS가 푼다).
        let globalOnly = try dns(#"{"Proxied":false,"Resolvers":[{"Addr":"192.0.2.53"}],"Routes":{"split.example.com":[{"Addr":"192.0.2.55"}]}}"#)
        #expect(globalOnly.dnsServers.isEmpty && globalOnly.dnsMatchDomains.isEmpty)
    }

    @Test("루트 영역(\"\"·\".\")은 match 도메인이 되지 않는다")
    func rootIsNeverMatchDomain() throws {
        for key in ["", ".", ".."] {
            let off = try dns(#"{"Proxied":false,"Routes":{"\#(key)":[]}}"#)
            #expect(off.dnsMatchDomains.isEmpty && off.dnsServers.isEmpty, "\(key)")
            let on = try dns(#"{"Proxied":true,"Routes":{"\#(key)":[]}}"#)
            #expect(on.dnsMatchDomains == Self.magicDNSDomains, "\(key)")
        }
        // ExtraRecords의 루트 이름도 같다.
        let extra = try dns(#"{"ExtraRecords":[{"Name":".","Value":"100.64.0.9"},{"Name":"","Value":"100.64.0.9"}]}"#)
        #expect(extra.dnsMatchDomains.isEmpty)
    }

    @Test("ExtraRecords: 덮이지 않은 이름만 영역이 된다")
    func extraRecordCoverage() throws {
        let config = #"""
        {"Proxied":true,"Routes":{"example.org":[{"Addr":"192.0.2.55"}]},
         "ExtraRecords":[
           {"Name":"host.tail0001.ts.net.","Value":"100.64.0.9"},
           {"Name":"svc.example.com","Value":"100.64.0.10"},
           {"Name":"b.svc.example.com.","Type":"A","Value":"100.64.0.11"},
           {"Name":"v6.example.net","Type":"AAAA","Value":"fd7a:115c:a1e0::9"},
           {"Name":"covered.example.org","Value":"100.64.0.12"},
           {"Name":"1.100.in-addr.arpa","Value":"100.64.0.13"}]}
        """#
        let settings = try dns(config)
        let added = ["svc.example.com", "v6.example.net", "1.100.in-addr.arpa"]
        // 접미사 아래의 이름, 앞선 ExtraRecords 아래의 이름, 리졸버가 있는 Routes 아래의 이름은 더하지 않는다.
        #expect(Set(settings.dnsMatchDomains) == Set(Self.magicDNSDomains + added))
        #expect(!settings.dnsMatchDomains.contains("host.tail0001.ts.net"))
        #expect(!settings.dnsMatchDomains.contains("b.svc.example.com"))
        #expect(!settings.dnsMatchDomains.contains("covered.example.org"))
        #expect(!settings.dnsMatchDomains.contains("example.org"))
    }

    @Test("ExtraRecords: MagicDNS가 꺼져 있으면 이름만 영역이 된다")
    func extraRecordsWithoutMagicDNS() throws {
        let settings = try dns(#"{"ExtraRecords":[{"Name":"svc.example.com","Value":"100.64.0.10"}]}"#)
        #expect(settings.dnsMatchDomains == ["svc.example.com"])
        #expect(settings.dnsServers.map(\.description) == ["100.100.100.100", "fd7a:115c:a1e0::53"])
    }

    @Test("ExtraRecords: 종류가 A·AAAA·빈 값이 아니거나 값이 주소가 아니거나 이름이 잘못되면 무시한다")
    func invalidExtraRecords() throws {
        let longLabel = String(repeating: "a", count: 64)
        let longName = (0..<10).map { _ in String(repeating: "b", count: 30) }.joined(separator: ".")
        let invalid = [
            #"{"Name":"txt.example.com","Type":"TXT","Value":"100.64.0.9"}"#,
            #"{"Name":"cname.example.com","Type":"CNAME","Value":"100.64.0.9"}"#,
            #"{"Name":"badvalue.example.com","Value":"not-an-address"}"#,
            #"{"Name":"emptyvalue.example.com","Value":""}"#,
            #"{"Name":"has space.example.com","Value":"100.64.0.9"}"#,
            #"{"Name":"tab\there.example.com","Value":"100.64.0.9"}"#,
            #"{"Name":"empty..label.example.com","Value":"100.64.0.9"}"#,
            #"{"Name":"trailing..","Value":"100.64.0.9"}"#,
            #"{"Name":"\#(longLabel).example.com","Value":"100.64.0.9"}"#,
            #"{"Name":"\#(longName).example.com","Value":"100.64.0.9"}"#,
            #"{"Name":"é.example.com","Value":"100.64.0.9"}"#,
        ]
        let settings = try dns(#"{"ExtraRecords":[\#(invalid.joined(separator: ","))]}"#)
        #expect(settings.dnsMatchDomains.isEmpty)
        #expect(settings.dnsServers.isEmpty)

        // 같은 설정에 유효한 것이 하나 있으면 그것만 영역이 된다.
        let mixed = try dns(#"{"ExtraRecords":[\#(invalid.joined(separator: ",")),{"Name":"ok.example.com","Type":"A","Value":"100.64.0.9"},{"Name":"ok6.example.com","Type":"AAAA","Value":"fd7a:115c:a1e0::9"}]}"#)
        #expect(mixed.dnsMatchDomains == ["ok.example.com", "ok6.example.com"])
    }

    @Test("이름 경계: 레이블 63바이트와 전체 253바이트는 받고 64바이트와 254바이트는 거절한다")
    func nameLimits() throws {
        let label63 = String(repeating: "a", count: 63)
        let name253 = ([label63, label63, label63, String(repeating: "c", count: 61)]).joined(separator: ".")
        #expect(name253.utf8.count == 253)
        let name254 = ([label63, label63, label63, String(repeating: "c", count: 62)]).joined(separator: ".")
        let config = #"{"Routes":{"\#(label63).example.com":[],"\#(name253)":[],"\#(name254)":[],"\#(label63)a.example.com":[]}}"#
        let settings = try dns(config)
        #expect(Set(settings.dnsMatchDomains) == ["\(label63).example.com", name253])
    }

    @Test("이름을 소문자로 바꾸고 앞 점·끝 점을 정리한다")
    func normalizesNames() throws {
        let config = #"{"Routes":{"Corp.Example.COM.":[],".dotted.example.com":[],"UPPER.example.com":[]},"ExtraRecords":[{"Name":"Svc.EXAMPLE.net","Value":"100.64.0.9"}]}"#
        let settings = try dns(config)
        #expect(settings.dnsMatchDomains == ["corp.example.com", "dotted.example.com", "svc.example.net", "upper.example.com"])
    }

    @Test("match 도메인은 끝 점을 포함한 문자열 순으로 정렬한 뒤 점을 뗀다")
    func sortsWithTrailingDot() throws {
        // 점을 떼고 정렬하면 a < a.b < a.b-c이지만, 점을 붙이면 "a." < "a.b-c." < "a.b."다('-' 0x2D < '.' 0x2E).
        let settings = try dns(#"{"Routes":{"a.b":[],"a.b-c":[],"a":[]}}"#)
        #expect(settings.dnsMatchDomains == ["a", "a.b-c", "a.b"])
    }

    @Test("자기 키가 만료되면 DNS가 없다. 주소와 경로는 그대로다")
    func selfKeyExpired() throws {
        let peers = [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32"])]
        func settings(_ extra: String) throws -> TunnelNetworkSettings {
            try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], selfExtra: extra, peers: peers))
        }
        let live = try settings("")
        #expect(!live.dnsServers.isEmpty)
        for extra in [#","Expired":true"#, #","KeyExpiry":"2027-01-15T08:00:00Z""#, #","KeyExpiry":"2027-01-15T07:59:59Z""#] {
            let expired = try settings(extra)
            #expect(expired.dnsServers.isEmpty && expired.dnsMatchDomains.isEmpty, "\(extra)")
            #expect(expired.addresses == live.addresses && expired.routes == live.routes, "\(extra)")
        }
        // 만료 시각이 아직 오지 않았으면 DNS가 있다.
        #expect(try settings(#","KeyExpiry":"2027-01-15T08:00:01Z""#) == live)
    }

    @Test("DNS 서버가 있으면 match 도메인도 있고, 없으면 둘 다 없다")
    func serversAndDomainsTogether() throws {
        let configs: [String?] = [
            nil, "{}", #"{"Proxied":true}"#, #"{"Proxied":false}"#,
            #"{"Routes":{"a.example":[]}}"#, #"{"Routes":{"a.example":[{"Addr":"192.0.2.1"}]}}"#,
            #"{"ExtraRecords":[{"Name":"x.example","Value":"100.64.0.1"}]}"#, #"{"Resolvers":[{"Addr":"192.0.2.1"}]}"#,
        ]
        for config in configs {
            for addresses in [SettingsFixture.selfAddresses, ["100.64.0.1/32"], ["fd7a:115c:a1e0::1/128"]] {
                let settings = try dns(config, selfAddresses: addresses)
                #expect(settings.dnsServers.isEmpty == settings.dnsMatchDomains.isEmpty, "\(config ?? "nil") \(addresses)")
            }
        }
    }
}

@Suite("터널 설정: 값 비교")
struct TunnelSettingsEqualityTests {
    private func sample(dns: String = #"{"Proxied":true}"#, peers: [String]? = nil) throws -> Netmap {
        try SettingsFixture.netmap(
            peers: peers ?? [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])], dns: dns)
    }

    @Test("같은 netmap에서는 늘 같은 값이다")
    func sameNetmapSameValue() throws {
        let netmap = try sample()
        let first = try SettingsFixture.settings(netmap)
        for _ in 0..<3 {
            #expect(try SettingsFixture.settings(netmap) == first)
        }
        #expect(try SettingsFixture.settings(sample()) == first)
    }

    @Test("DNS만 바뀌어도 다른 값이다")
    func dnsChangeDiffers() throws {
        let before = try SettingsFixture.settings(sample())
        let after = try SettingsFixture.settings(sample(dns: #"{"Proxied":true,"Routes":{"corp.example.com":[]}}"#))
        #expect(before != after)
        #expect(before.addresses == after.addresses && before.routes == after.routes && before.mtu == after.mtu)
        #expect(before.dnsServers == after.dnsServers)
        #expect(before.dnsMatchDomains != after.dnsMatchDomains)

        let serversOnly = try SettingsFixture.settings(SettingsFixture.netmap(selfExtra: #","CapMap":{"force-register-magicdns-ipv4-only":[]}"#, peers: [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])]))
        #expect(before != serversOnly)
        #expect(before.dnsMatchDomains == serversOnly.dnsMatchDomains)
    }

    @Test("경로나 MTU만 바뀌어도 다른 값이다")
    func routeAndMTUChangeDiffer() throws {
        let base = try SettingsFixture.settings(sample())
        let morePeers = try SettingsFixture.settings(sample(peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32"]),
        ]))
        #expect(base != morePeers)
        #expect(base.dnsServers == morePeers.dnsServers && base.dnsMatchDomains == morePeers.dnsMatchDomains)
        #expect(try SettingsFixture.settings(sample(), mtu: 1420) != base)
        #expect(try SettingsFixture.settings(sample(), mtu: 1280) == base)
    }
}
