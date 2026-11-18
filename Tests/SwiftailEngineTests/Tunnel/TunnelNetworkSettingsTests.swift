// Tests for contract behavior S (settings computation). Expected values come from the contract, the notes (engine 4.8, DNS 4.1.4), and the Go sources.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("Tunnel settings for local addresses")
struct TunnelSettingsAddressTests {
    @Test("With both IPv4 and IPv6 present, return /32 and /128 in netmap order")
    func dualStack() throws {
        let settings = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128", "100.64.0.1/32"]))
        #expect(settings.addresses.map(\.description) == ["fd7a:115c:a1e0::1/128", "100.64.0.1/32"])
    }

    @Test("IPv4 only and IPv6 only")
    func singleFamily() throws {
        let v4 = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"]))
        #expect(v4.addresses.map(\.description) == ["100.64.0.1/32"])
        let v6 = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128"]))
        #expect(v6.addresses.map(\.description) == ["fd7a:115c:a1e0::1/128"])
    }

    @Test("Return nil with no local addresses or with only prefixes that span multiple addresses")
    func noAddress() throws {
        #expect(try TunnelNetworkSettings(netmap: SettingsFixture.netmap(selfAddresses: []), mtu: 1280, at: wallClockStart) == nil)
        let wide = try SettingsFixture.netmap(selfAddresses: ["100.64.0.0/24", "fd7a:115c:a1e0::/64"])
        #expect(TunnelNetworkSettings(netmap: wide, mtu: 1280, at: wallClockStart) == nil)
    }

    @Test("Drop prefixes spanning multiple addresses and duplicates")
    func filtersAddresses() throws {
        let netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.0/24", "100.64.0.1/32", "100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
        #expect(try SettingsFixture.settings(netmap).addresses.map(\.description) == ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
    }

    @Test("Preserve the device's MTU")
    func mtuPassesThrough() throws {
        let netmap = try SettingsFixture.netmap()
        for mtu in [1280, 1420, 1500] {
            #expect(try SettingsFixture.settings(netmap, mtu: mtu).mtu == mtu)
        }
    }
}

@Suite("Tunnel settings for routes")
struct TunnelSettingsRouteTests {
    @Test("A /32 per peer followed by the service IP routes")
    func perPeerAndService() throws {
        let netmap = try SettingsFixture.netmap(
            selfAddresses: ["100.64.0.1/32"],
            peers: [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32"]), SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32"])])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == ["100.64.0.2/32", "100.64.0.3/32", "100.100.100.100/32"])
    }

    @Test("Peer IPv6 uses one ULA /48 instead of /128 routes. The IPv4 service route precedes IPv6")
    func ulaAggregate() throws {
        let netmap = try SettingsFixture.netmap(peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32", "fd7a:115c:a1e0::3/128"]),
        ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == [
            "100.64.0.2/32", "100.64.0.3/32", "fd7a:115c:a1e0::/48", "100.100.100.100/32", "fd7a:115c:a1e0::53/128",
        ])
    }

    @Test("Include service IP routes even without peers")
    func serviceRoutesOnly() throws {
        #expect(try SettingsFixture.settings(SettingsFixture.netmap()).routes.map(\.description) == ["100.100.100.100/32", "fd7a:115c:a1e0::53/128"])
        #expect(try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"])).routes.map(\.description) == ["100.100.100.100/32"])
        #expect(try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128"])).routes.map(\.description) == ["fd7a:115c:a1e0::53/128"])
    }

    @Test("Omit routes for address families without a local address")
    func familyFilter() throws {
        let peers = [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])]
        let v4Only = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: peers))
        #expect(v4Only.routes.map(\.description) == ["100.64.0.2/32", "100.100.100.100/32"])
        let v6Only = try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: ["fd7a:115c:a1e0::1/128"], peers: peers))
        #expect(v6Only.routes.map(\.description) == ["fd7a:115c:a1e0::/48", "fd7a:115c:a1e0::53/128"])
    }

    @Test("Sort IPv4 first, then by address bytes instead of strings, then by prefix length")
    func ordering() throws {
        let netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.200/32"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.9/32"]),
            SettingsFixture.peer(id: 4, addresses: ["100.64.0.5/32"]),
            // A peer's own address is included even outside the tailnet range. It is outside CGNAT, so it is returned unchanged without aggregation.
            SettingsFixture.peer(id: 5, addresses: ["10.1.2.3/32"]),
        ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == [
            "10.1.2.3/32", "100.64.0.5/32", "100.64.0.9/32", "100.64.0.200/32", "100.100.100.100/32",
        ])
    }

    @Test("Omit expired or unsupported peers from routes")
    func excludedPeers() throws {
        let netmap = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], peers: [
            SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32"]),
            SettingsFixture.peer(id: 3, addresses: ["100.64.0.3/32"], extra: #","Expired":true"#),
            // The key is expired when its expiry time equals the current time (the same rule as EnginePeer).
            SettingsFixture.peer(id: 4, addresses: ["100.64.0.4/32"], extra: #","KeyExpiry":"2027-01-15T08:00:00Z""#),
            SettingsFixture.peer(id: 5, addresses: ["100.64.0.5/32"], extra: #","IsWireGuardOnly":true"#),
            SettingsFixture.peer(id: 6, addresses: ["100.64.0.6/32"], extra: #","IsJailed":true"#),
            // A peer with neither a disco key nor a home DERP is unreachable.
            SettingsFixture.node(id: 7, addresses: ["100.64.0.7/32"]),
            SettingsFixture.peer(id: 8, addresses: ["100.64.0.8/32"], extra: #","KeyExpiry":"2027-01-15T09:00:00Z""#),
        ])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == ["100.64.0.2/32", "100.64.0.8/32", "100.100.100.100/32"])
    }

    @Test("The service route appears once at the end even if a peer advertises the service IP as its address")
    func peerClaimingServiceIP() throws {
        let netmap = try SettingsFixture.netmap(
            selfAddresses: ["100.64.0.1/32"],
            peers: [SettingsFixture.peer(id: 2, addresses: ["100.100.100.100/32", "100.64.0.2/32"])])
        #expect(try SettingsFixture.settings(netmap).routes.map(\.description) == ["100.64.0.2/32", "100.100.100.100/32"])
    }

    @Test("CGNAT threshold. Use individual routes for 10,000 unique /32s and one 100.64.0.0/10 route at 10,001")
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

    @Test("OneCGNAT control directive. v=true sets the threshold to 1 (use /10 from two onward). v=false or absent uses the default")
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
        // If both arrive together, Go gives true precedence.
        #expect(try routes(two, both) == ["100.64.0.0/10", "100.100.100.100/32"])
        // The same applies to the legacy `Capabilities` list (the session merges it into CapMap).
        let legacy = try SettingsFixture.netmap(selfAddresses: ["100.64.0.1/32"], selfExtra: #","Capabilities":["one-cgnat?v=true"]"#, peers: two)
        #expect(try SettingsFixture.settings(legacy).routes.map(\.description) == ["100.64.0.0/10", "100.100.100.100/32"])
    }

    @Test("OneCGNAT does not affect IPv6 ULA aggregation")
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

    @Test("Shuffling the peer order yields the same value")
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

@Suite("Tunnel settings for DNS")
struct TunnelSettingsDNSTests {
    /// One suffix (`tail0001.ts.net`) and 65 reverse zones. These are the 66 zones from contract behavior S5, listed independently.
    static let magicDNSDomains: [String] = {
        let zones = ["tail0001.ts.net", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"] + (64...127).map { "\($0).100.in-addr.arpa" }
        // Sort strings with the trailing dot, then remove the dot.
        return zones.map { $0 + "." }.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }.map { String($0.dropLast()) }
    }()

    private func dns(_ dnsConfig: String?, selfAddresses: [String] = SettingsFixture.selfAddresses, selfName: String? = nil, selfExtra: String = "") throws -> TunnelNetworkSettings {
        try SettingsFixture.settings(SettingsFixture.netmap(selfAddresses: selfAddresses, selfName: selfName, selfExtra: selfExtra, dns: dnsConfig))
    }

    @Test("With MagicDNS enabled, include the service IPs (IPv4 first) and 66 zones")
    func magicDNSOn() throws {
        let settings = try dns(#"{"Proxied":true}"#)
        #expect(settings.dnsServers.map(\.description) == ["100.100.100.100", "fd7a:115c:a1e0::53"])
        #expect(Self.magicDNSDomains.count == 66)
        #expect(settings.dnsMatchDomains == Self.magicDNSDomains)
        #expect(settings.dnsMatchDomains.allSatisfy { !$0.hasSuffix(".") })
    }

    @Test("DNS servers match the local address families")
    func serversFollowFamily() throws {
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["100.64.0.1/32"]).dnsServers.map(\.description) == ["100.100.100.100"])
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["fd7a:115c:a1e0::1/128"]).dnsServers.map(\.description) == ["fd7a:115c:a1e0::53"])
    }

    @Test("force-register-magicdns-ipv4-only uses only the IPv4 service IP. IPv6-only nodes use IPv6")
    func ipv4OnlyKnob() throws {
        let knob = #","CapMap":{"force-register-magicdns-ipv4-only":[]}"#
        #expect(try dns(#"{"Proxied":true}"#, selfExtra: knob).dnsServers.map(\.description) == ["100.100.100.100"])
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["100.64.0.1/32"], selfExtra: knob).dnsServers.map(\.description) == ["100.100.100.100"])
        #expect(try dns(#"{"Proxied":true}"#, selfAddresses: ["fd7a:115c:a1e0::1/128"], selfExtra: knob).dnsServers.map(\.description) == ["fd7a:115c:a1e0::53"])
    }

    @Test("With MagicDNS disabled (no zones), DNS is unset")
    func magicDNSOff() throws {
        for config in [#"{"Proxied":false}"#, "{}", #"{"Proxied":false,"Routes":{}}"#] {
            let settings = try dns(config)
            #expect(settings.dnsServers.isEmpty, "\(config)")
            #expect(settings.dnsMatchDomains.isEmpty, "\(config)")
        }
    }

    @Test("DNS is also unset when the DNS configuration itself is absent")
    func noDNSConfig() throws {
        let settings = try dns(nil)
        #expect(settings.dnsServers.isEmpty && settings.dnsMatchDomains.isEmpty)
        #expect(!settings.addresses.isEmpty && !settings.routes.isEmpty)
    }

    @Test("There are no zones when the MagicDNS suffix is absent (no local name)")
    func noSuffix() throws {
        let settings = try dns(#"{"Proxied":true}"#, selfName: "")
        #expect(settings.dnsServers.isEmpty && settings.dnsMatchDomains.isEmpty)
        // There is also no suffix when the name consists of just a dot.
        #expect(try dns(#"{"Proxied":true}"#, selfName: "...").dnsMatchDomains.isEmpty)
        // Other zones are still emitted without a suffix.
        let extra = try dns(#"{"Proxied":true,"Routes":{"corp.example.com":[]}}"#, selfName: "")
        #expect(extra.dnsMatchDomains == ["corp.example.com"])
        #expect(extra.dnsServers.count == 2)
    }

    @Test("The suffix is the local node name with the leading label removed")
    func suffixFromSelfName() throws {
        #expect(try dns(#"{"Proxied":true}"#, selfName: "Phone-1.TAIL0002.example.net").dnsMatchDomains.contains("tail0002.example.net"))
        #expect(try dns(#"{"Proxied":true}"#, selfName: ".phone.tail0003.ts.net.").dnsMatchDomains.contains("tail0003.ts.net"))
    }

    @Test("Routes with no resolvers are zones. Routes with resolvers and global Resolvers are unused")
    func routesAndResolvers() throws {
        let config = #"""
        {"Proxied":false,"Resolvers":[{"Addr":"192.0.2.53"}],"FallbackResolvers":[{"Addr":"192.0.2.54"}],
         "Domains":["search.example.com"],
         "Routes":{"corp.example.com":[],"null.example.com":null,"split.example.com":[{"Addr":"192.0.2.55"}]}}
        """#
        let settings = try dns(config)
        #expect(settings.dnsMatchDomains == ["corp.example.com", "null.example.com"])
        #expect(settings.dnsServers.map(\.description) == ["100.100.100.100", "fd7a:115c:a1e0::53"])

        // If there are only global Resolvers and no zones, leave DNS unset (the default OS DNS resolves names).
        let globalOnly = try dns(#"{"Proxied":false,"Resolvers":[{"Addr":"192.0.2.53"}],"Routes":{"split.example.com":[{"Addr":"192.0.2.55"}]}}"#)
        #expect(globalOnly.dnsServers.isEmpty && globalOnly.dnsMatchDomains.isEmpty)
    }

    @Test("Root zones (\"\" and \".\") are excluded from match domains")
    func rootIsNeverMatchDomain() throws {
        for key in ["", ".", ".."] {
            let off = try dns(#"{"Proxied":false,"Routes":{"\#(key)":[]}}"#)
            #expect(off.dnsMatchDomains.isEmpty && off.dnsServers.isEmpty, "\(key)")
            let on = try dns(#"{"Proxied":true,"Routes":{"\#(key)":[]}}"#)
            #expect(on.dnsMatchDomains == Self.magicDNSDomains, "\(key)")
        }
        // The same applies to root names in ExtraRecords.
        let extra = try dns(#"{"ExtraRecords":[{"Name":".","Value":"100.64.0.9"},{"Name":"","Value":"100.64.0.9"}]}"#)
        #expect(extra.dnsMatchDomains.isEmpty)
    }

    @Test("Only uncovered ExtraRecords names become zones")
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
        // Skip names under the suffix, under earlier ExtraRecords, or under Routes with resolvers.
        #expect(Set(settings.dnsMatchDomains) == Set(Self.magicDNSDomains + added))
        #expect(!settings.dnsMatchDomains.contains("host.tail0001.ts.net"))
        #expect(!settings.dnsMatchDomains.contains("b.svc.example.com"))
        #expect(!settings.dnsMatchDomains.contains("covered.example.org"))
        #expect(!settings.dnsMatchDomains.contains("example.org"))
    }

    @Test("With MagicDNS disabled, only the names in ExtraRecords become zones")
    func extraRecordsWithoutMagicDNS() throws {
        let settings = try dns(#"{"ExtraRecords":[{"Name":"svc.example.com","Value":"100.64.0.10"}]}"#)
        #expect(settings.dnsMatchDomains == ["svc.example.com"])
        #expect(settings.dnsServers.map(\.description) == ["100.100.100.100", "fd7a:115c:a1e0::53"])
    }

    @Test("Ignore ExtraRecords whose type is neither A, AAAA, nor empty, whose value is not an address, or whose name is invalid")
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

        // If the same configuration has one valid entry, only that entry becomes a zone.
        let mixed = try dns(#"{"ExtraRecords":[\#(invalid.joined(separator: ",")),{"Name":"ok.example.com","Type":"A","Value":"100.64.0.9"},{"Name":"ok6.example.com","Type":"AAAA","Value":"fd7a:115c:a1e0::9"}]}"#)
        #expect(mixed.dnsMatchDomains == ["ok.example.com", "ok6.example.com"])
    }

    @Test("Accept 63-byte labels and 253-byte names. Reject 64-byte labels and 254-byte names")
    func nameLimits() throws {
        let label63 = String(repeating: "a", count: 63)
        let name253 = ([label63, label63, label63, String(repeating: "c", count: 61)]).joined(separator: ".")
        #expect(name253.utf8.count == 253)
        let name254 = ([label63, label63, label63, String(repeating: "c", count: 62)]).joined(separator: ".")
        let config = #"{"Routes":{"\#(label63).example.com":[],"\#(name253)":[],"\#(name254)":[],"\#(label63)a.example.com":[]}}"#
        let settings = try dns(config)
        #expect(Set(settings.dnsMatchDomains) == ["\(label63).example.com", name253])
    }

    @Test("Lowercase names and normalize leading and trailing dots")
    func normalizesNames() throws {
        let config = #"{"Routes":{"Corp.Example.COM.":[],".dotted.example.com":[],"UPPER.example.com":[]},"ExtraRecords":[{"Name":"Svc.EXAMPLE.net","Value":"100.64.0.9"}]}"#
        let settings = try dns(config)
        #expect(settings.dnsMatchDomains == ["corp.example.com", "dotted.example.com", "svc.example.net", "upper.example.com"])
    }

    @Test("Sort match domains as strings with trailing dots, then remove the dots")
    func sortsWithTrailingDot() throws {
        // Sorting without the trailing dot gives a < a.b < a.b-c. With trailing dots, "a." < "a.b-c." < "a.b." ('-' 0x2D < '.' 0x2E).
        let settings = try dns(#"{"Routes":{"a.b":[],"a.b-c":[],"a":[]}}"#)
        #expect(settings.dnsMatchDomains == ["a", "a.b-c", "a.b"])
    }

    @Test("Local key expiry removes DNS. Addresses and routes stay the same")
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
        // DNS remains present before the expiry time.
        #expect(try settings(#","KeyExpiry":"2027-01-15T08:00:01Z""#) == live)
    }

    @Test("DNS servers and match domains are either both present or both absent")
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

@Suite("Tunnel settings value comparison")
struct TunnelSettingsEqualityTests {
    private func sample(dns: String = #"{"Proxied":true}"#, peers: [String]? = nil) throws -> Netmap {
        try SettingsFixture.netmap(
            peers: peers ?? [SettingsFixture.peer(id: 2, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])], dns: dns)
    }

    @Test("The same netmap always yields the same value")
    func sameNetmapSameValue() throws {
        let netmap = try sample()
        let first = try SettingsFixture.settings(netmap)
        for _ in 0..<3 {
            #expect(try SettingsFixture.settings(netmap) == first)
        }
        #expect(try SettingsFixture.settings(sample()) == first)
    }

    @Test("Changing only DNS yields a different value")
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

    @Test("Changing only routes or MTU yields a different value")
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
