// DNS zone derivation is ported from the Go implementation. Name validation is stricter than Go `dnsname.ToFQDN`.
// Origin: tailscale.com v1.104.6 `ipn/ipnlocal/node_backend.go` (`dnsConfigForNetmap`), `ipn/ipnlocal/local.go`
// (`magicDNSRootDomains`), `types/netmap/netmap.go` (`MagicDNSSuffixOfNodeName`), `net/dns/config.go`
// (`serviceIPs`, `matchDomains`), `util/dnsname/dnsname.go` (`ToFQDN`, `FQDN.Contains`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Foundation
import SwiftailBase
import SwiftailControl

/// Derives DNS settings to pass to the OS (contract behavior S5, DNS notes 4.1.4).
///
/// Passes only zones the node answers directly (`localZones`) to the OS as match domains. Only queries for these zones reach the service IP.
/// The default OS DNS resolves all other names (decision D1). The same `localZones` become MagicDNS responder zones (behavior S7).
///
/// shortcut: Omits global `Resolvers`, `Routes` with resolvers, and `FallbackResolvers` (decision D2), and does not emit search
/// `Domains` (decision D3). Also omits 4via6 names and `dns-subdomain-resolve`. This will be needed when custom split
/// DNS must resolve through the tunnel or short-name resolution is required.
extension TunnelNetworkSettings {
    /// When the control server supplies this attribute, omits the IPv6 service IP as a DNS server (Go `ForceRegisterMagicDNSIPv4Only`).
    static let ipv4OnlyDNSCapability = "force-register-magicdns-ipv4-only"

    /// The service IPs to announce as DNS servers, only for families with a local address, with IPv4 first.
    ///
    /// Go's `serviceIPs` includes the IPv6 service IP even on an IPv4-only node, which has no IPv6 service route
    /// and cannot receive queries to it. Filter by the local address families. An IPv6-only node uses the IPv6 service IP even with the attribute
    /// (Go also gives `OnlyIPv6` precedence over the attribute).
    static func dnsServers(hasIPv4: Bool, hasIPv6: Bool, ipv4Only: Bool) -> [IPAddress] {
        let wantsIPv6 = hasIPv6 && !(ipv4Only && hasIPv4)
        return [(ServiceIP.ipv4Text, hasIPv4), (ServiceIP.ipv6Text, wantsIPv6)]
            .compactMap { text, wanted in wanted ? IPAddress(text) : nil }
    }

    /// Zones the node answers directly. Lowercase FQDNs with trailing dots, sorted by the strings including those dots.
    /// Empty if the local key expired or no DNS configuration exists (fail closed by leaving DNS unconfigured).
    ///
    /// The zones are the union of the following.
    /// - With `Proxied` (MagicDNS), the MagicDNS suffix, `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.`, and `64`~`127.100.in-addr.arpa.`.
    /// - `Routes` keys with an empty resolver list.
    /// - Valid `ExtraRecords` names not covered by any zone. As in Go, coverage also includes `Routes` keys with resolvers.
    ///
    /// Accepts only names from the control server that can serve as match domains (`zoneName`). Rejects the root (`.`).
    /// On iOS an empty match domain sends all names to this resolver.
    static func localZones(in netmap: Netmap, at now: Date) -> [String] {
        guard let dns = netmap.dnsConfig, !isExpired(netmap.selfNode, at: now) else { return [] }

        var zones: Set<String> = []
        // Go's `dcfg.Routes` keys. Used to determine whether `ExtraRecords` are covered.
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
        // The `routes` dictionary has no order, but coverage compares against all keys and is independent of order. A zone created by an earlier `ExtraRecords` entry
        // covers later entries (as in Go).
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

    /// The 66 MagicDNS zones include one suffix, one IPv6 reverse zone, and 64 zones from `64`~`127.100.in-addr.arpa.`.
    /// The suffix is what remains after stripping leading and trailing dots and removing the first label from the local node's `Name`. If the suffix is absent or unusable as a name,
    /// there are no zones (Go `magicDNSRootDomains`).
    private static func magicDNSZones(selfName: String) -> [String] {
        let name = selfName.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let suffix = name.firstIndex(of: ".").map { String(name[name.index(after: $0)...]) } ?? name
        guard !suffix.isEmpty, let suffixZone = zoneName(suffix), suffixZone != "." else { return [] }
        return [suffixZone, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."] + (64...127).map { "\($0).100.in-addr.arpa." }
    }

    /// The node key expired if the expiration flag is set or the expiration time has passed, including the exact time (same rule as `EnginePeer`).
    // shortcut: Uses the local clock. Go corrects a clock that differs from ControlTime by more than 1 minute.
    static func isExpired(_ node: Node, at now: Date) -> Bool {
        node.expired || (node.keyExpiry.map { $0 <= now } ?? false)
    }

    /// Converts a DNS name to a lowercase FQDN with a trailing dot. Returns `nil` if it cannot serve as a match domain. The root is `"."`.
    ///
    /// Like Go `ToFQDN`, allows one leading dot and a trailing dot, and rejects a total length over 254 bytes or any space or control character.
    /// Also requires every label to be 1…63 bytes (Go does not check the last label), and rejects
    /// non-ASCII bytes. This fails closed because the name is used as is in OS settings and query comparisons.
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

    /// Whether `zone` equals `name` or is its parent zone (Go `FQDN.Contains`). The root covers every name.
    private static func contains(zone: String, name: String) -> Bool {
        zone == name || zone == "." || name.hasSuffix("." + zone)
    }
}
