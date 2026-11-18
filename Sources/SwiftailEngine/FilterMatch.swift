// Rule conversion and matching control flow are ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/filter/tailcfg.go` (`MatchesFromFilterRules`, `parseIPSet`),
// `wgengine/filter/match.go` (`match`, `matchIPsOnly`, `matchProtoAndIPsOnlyIfAllPorts`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl

/// A parsed allow rule. Expands strings from the control server's `FilterRule` once at the boundary.
///
/// The rules form a union of permissions, with no deny rules or precedence. Unparseable address entries are dropped individually, so they can only
/// narrow the rule (fail closed).
///
/// `docs/protocol-notes/netmap-engine.md` 4.4 and `docs/contracts/SwiftailEngine.md` behavior 6.
struct FilterMatch: Sendable {
    /// One destination address range and port range.
    struct Destination: Sendable {
        let addresses: AddressRange
        /// Both endpoints are inclusive. If `first > last`, no port matches (as in Go).
        let firstPort: UInt16
        let lastPort: UInt16

        func contains(port: UInt16) -> Bool { firstPort <= port && port <= lastPort }
        var coversAllPorts: Bool { firstPort == 0 && lastPort == .max }
    }

    /// Allowed IP protocol numbers.
    let protocols: Set<UInt8>
    /// Source addresses. A match in any one is sufficient. The source port is ignored.
    let sources: [AddressRange]
    let destinations: [Destination]

    /// The default for an empty `IPProto` is TCP, UDP, ICMPv4, and ICMPv6.
    private static let defaultProtocols: Set<UInt8> = [6, 17, 1, 58]

    /// For TCP SYN, UDP, and SCTP, checks whether protocol, source address, destination address, and destination port all match.
    func matches(_ packet: IPPacket) -> Bool {
        protocols.contains(packet.protocolNumber)
            && containsSource(of: packet)
            && destinations.contains { $0.addresses.contains(packet.destination) && $0.contains(port: packet.destinationPort) }
    }

    /// For ICMP, checks only source and destination addresses, ignoring protocol and port (an address open on any port also allows ICMP).
    func matchesAddresses(of packet: IPPacket) -> Bool {
        containsSource(of: packet) && destinations.contains { $0.addresses.contains(packet.destination) }
    }

    /// For other protocols, checks for a matching protocol and addresses, and a destination with the full 0…65535 port range.
    func matchesAllPorts(of packet: IPPacket) -> Bool {
        protocols.contains(packet.protocolNumber)
            && containsSource(of: packet)
            && destinations.contains { $0.coversAllPorts && $0.addresses.contains(packet.destination) }
    }

    private func containsSource(of packet: IPPacket) -> Bool {
        sources.contains { $0.contains(packet.source) }
    }
}

extension FilterMatch {
    /// Parses a list of rules.
    ///
    /// Returns an empty list (blocks everything) if any legacy `SrcBits` or `DstPorts[].Bits` is present. Go also discards
    /// the entire conversion result in this case. Blocking everything is safer than preserving a subset of the legacy rules and changing their meaning.
    /// Omits rules with no remaining source or destination (for example, a rule with only `CapGrant`) because they allow no packets.
    static func matches(from rules: [FilterRule]) -> [FilterMatch] {
        guard rules.allSatisfy({ $0.srcBits.isEmpty && $0.dstPorts.allSatisfy { $0.bits == nil } }) else {
            return []
        }
        return rules.compactMap(FilterMatch.init(rule:))
    }

    private init?(rule: FilterRule) {
        let sources = rule.srcIPs.flatMap(AddressRange.ranges(parsing:))
        let destinations = rule.dstPorts.flatMap { port in
            AddressRange.ranges(parsing: port.ip).map {
                Destination(addresses: $0, firstPort: port.ports.first, lastPort: port.ports.last)
            }
        }
        guard !sources.isEmpty, !destinations.isEmpty else { return nil }
        self.sources = sources
        self.destinations = destinations
        // Keeps only 0…255 from an explicit list. If all values are out of range, the set is empty and does not fall back to the default set.
        protocols = rule.ipProto.isEmpty ? Self.defaultProtocols : Set(rule.ipProto.compactMap(UInt8.init(exactly:)))
    }
}
