import Foundation
import SwiftailBase
import SwiftailControl

/// Settings the app converts to `NEPacketTunnelNetworkSettings` and applies. The library has no dependency on NetworkExtension.
/// List order is deterministic. The same netmap produces the same value.
///
/// Computed purely from one netmap, with no socket or clock. The time is an argument. The node recomputes this value whenever it applies a netmap,
/// compares it to the last emitted value with `==`, and sends it to the app only if it differs (contract behavior E).
///
/// The values are split across three files. This file handles addresses and assembly, `TunnelNetworkSettings+Routes.swift` handles routes,
/// and `TunnelNetworkSettings+DNS.swift` handles DNS.
///
/// `docs/contracts/SwiftailTunnel.md` behavior S, `docs/protocol-notes/netmap-engine.md` 4.8,
/// `docs/protocol-notes/dns-state-node.md` 4.1.4.
public struct TunnelNetworkSettings: Sendable, Equatable {
    /// Local addresses, /32 for IPv4 and /128 for IPv6. Never empty.
    public var addresses: [IPPrefix]
    /// Routes to send through the tunnel. Sorted peer routes come before service IP routes. Families without a local address have no routes.
    public var routes: [IPPrefix]
    /// An empty list leaves DNS unconfigured. If present, the IPv4 service IP is first.
    public var dnsServers: [IPAddress]
    /// Lowercase names without trailing dots. Nonempty whenever `dnsServers` is nonempty.
    public var dnsMatchDomains: [String]
    /// The device MTU. Preserves the supplied value, which the app applies directly to the tunnel settings.
    public var mtu: Int

    /// Derives settings from the netmap (contract behavior S). Returns nil if there are no local addresses.
    ///
    /// Treats values from the control server as untrusted. Accepts only single-address prefixes for local addresses and only DNS names usable
    /// as match domains (`TunnelNetworkSettings+DNS.swift`).
    ///
    /// - Parameters:
    ///   - mtu: The device MTU, stored as given. The code accepting the device is responsible for the range check (1280…1420) (contract behavior U1).
    ///   - now: The time for checking key expiration for peers and the local node (the same clock as engine contract M3 behavior 2).
    public init?(netmap: Netmap, mtu: Int, at now: Date) {
        // Go uses the local address list as is. An OS tunnel address must be a single host address (contract behavior S1).
        var addresses: [IPPrefix] = []
        for prefix in netmap.selfNode.addresses where EnginePeer.isSingleAddress(prefix) && !addresses.contains(prefix) {
            addresses.append(prefix)
        }
        guard !addresses.isEmpty else { return nil }
        let hasIPv4 = addresses.contains { $0.address.isIPv4 }
        let hasIPv6 = addresses.contains { !$0.address.isIPv4 }

        self.addresses = addresses
        routes = Self.routes(
            for: EnginePeer.peers(in: netmap, at: now),
            oneCGNAT: Self.hasCapability(Self.oneCGNATCapability, in: netmap),
            hasIPv4: hasIPv4, hasIPv6: hasIPv6)
        dnsServers = []
        dnsMatchDomains = []
        self.mtu = mtu

        let zones = Self.localZones(in: netmap, at: now)
        if !zones.isEmpty {
            dnsServers = Self.dnsServers(
                hasIPv4: hasIPv4, hasIPv6: hasIPv6,
                ipv4Only: Self.hasCapability(Self.ipv4OnlyDNSCapability, in: netmap))
            dnsMatchDomains = zones.map { String($0.dropLast()) }
        }
    }

    /// Attributes in the local node's `CapMap`. The session has already merged the legacy `Capabilities` list into `CapMap`.
    static func hasCapability(_ name: String, in netmap: Netmap) -> Bool {
        netmap.selfNode.capMap[name] != nil
    }
}
