// Route aggregation is ported from the Go implementation (iOS rules, with no subnet routes or exit nodes).
// Origin: tailscale.com v1.104.6 `net/routemanager/routemanager.go` (`classify`, CGNAT and ULA aggregation in `applyDirty`,
// `cgnatThreshold`), `ipn/ipnlocal/local.go` (service IP routes), and `tailcfg/nodecap/nodecap.go` (`OneCGNATEnable`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Derives routes for traffic that should go through the tunnel (contract behaviors S2~S4).
///
/// Builds OS routes from AllowedIPs for peers installed in the data plane. OS routes differ from WireGuard AllowedIPs. The aggregated
/// `/10` and `/48` are passed only to the OS and never used as AllowedIPs (`netmap-engine.md` 4.8).
///
/// shortcut: Creates no subnet, exit node, or VIP service routes. Since M3, `EnginePeer` excludes subnet routes and /0
/// from AllowedIPs (engine contract M3 behavior 2), so peer routes carry only single-address prefixes for the peers' own addresses. This will be needed
/// when the plan scope expands.
extension TunnelNetworkSettings {
    /// If the control server supplies `one-cgnat?v=true`, the threshold for aggregating per-peer `/32` routes into one CGNAT `/10` becomes 1.
    /// `one-cgnat?v=false` and an absent setting both use the iOS default threshold (`cgnatThreshold`). If both arrive,
    /// Go gives `true` precedence (`UpdateFromNodeAttributes` in `control/controlknobs/controlknobs.go`).
    static let oneCGNATCapability = "one-cgnat?v=true"

    /// The maximum number of separate per-peer CGNAT `/32` routes. Aggregates to one `100.64.0.0/10` if there are more unique `/32` entries.
    /// Go `routemanager.cgnatThreshold`.
    static let cgnatThreshold = 10_000

    /// Sorted peer routes followed by service IP routes, retaining only families with local addresses.
    ///
    /// - Parameters:
    ///   - peers: Peers installed in the data plane. Each prefix belongs to just one peer (`EnginePeer.peers` guarantees this).
    ///   - oneCGNAT: The control directive `one-cgnat?v=true`. If true, even two CGNAT `/32` routes aggregate into one `/10`.
    static func routes(for peers: [EnginePeer], oneCGNAT: Bool, hasIPv4: Bool, hasIPv6: Bool) -> [IPPrefix] {
        let serviceRoutes = Self.serviceRoutes(hasIPv4: hasIPv4, hasIPv6: hasIPv6)
        let cgnatRange = IPPrefix("100.64.0.0/10")
        let tailscaleULA = IPPrefix("fd7a:115c:a1e0::/48")

        var cgnatHosts: Set<IPPrefix> = []
        var hasULAHost = false
        var others: Set<IPPrefix> = []
        // Adds service IP routes only once, at the end. Exclude them here to avoid duplicate routes even if a peer claims the address.
        for prefix in peers.lazy.flatMap(\.allowedIPs) where !Self.allServiceRoutes.contains(prefix) {
            let isSingleAddress = EnginePeer.isSingleAddress(prefix)
            if isSingleAddress, cgnatRange?.contains(prefix.address) == true {
                cgnatHosts.insert(prefix)
            } else if isSingleAddress, tailscaleULA?.contains(prefix.address) == true {
                // Aggregates single-address ULAs into one /48 if there is at least one (no individual /128 routes).
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

        // Filters by family (behavior S4). Omits routes for families without local addresses because packets cannot be sent over them.
        let ordered = routes
            .filter { $0.address.isIPv4 ? hasIPv4 : hasIPv6 }
            .sorted(by: Self.precedes)
        return ordered + serviceRoutes
    }

    /// Adds the service IP route `100.100.100.100/32` for a local IPv4 address and `fd7a:115c:a1e0::53/128` for a local IPv6 address.
    private static func serviceRoutes(hasIPv4: Bool, hasIPv6: Bool) -> [IPPrefix] {
        // The literals always parse. Tests verify their contents.
        [("\(ServiceIP.ipv4Text)/32", hasIPv4), ("\(ServiceIP.ipv6Text)/128", hasIPv6)]
            .compactMap { text, wanted in wanted ? IPPrefix(text) : nil }
    }

    /// The routes for the two service IPs, with IPv4 first.
    private static var allServiceRoutes: [IPPrefix] {
        serviceRoutes(hasIPv4: true, hasIPv6: true)
    }

    /// IPv4 first, then address byte order within a family, then prefix length for equal addresses (contract behavior S2).
    private static func precedes(_ lhs: IPPrefix, _ rhs: IPPrefix) -> Bool {
        if lhs.address.isIPv4 != rhs.address.isIPv4 { return lhs.address.isIPv4 }
        if lhs.address.bytes != rhs.address.bytes {
            return lhs.address.bytes.lexicographicallyPrecedes(rhs.address.bytes)
        }
        return lhs.length < rhs.length
    }
}
