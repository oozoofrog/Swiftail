// Decision order is ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/filter/filter.go` (`pre`, `runIn4`, `runIn6`, `UpdateOutboundFlowState`),
// `net/packet/packet.go` (`IsEchoResponse`, `IsError`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl

/// Decides whether to accept an incoming packet. Built from tailcfg filter rules and local addresses.
///
/// Outgoing packets bypass the rules. Only UDP and SCTP flow state is recorded (as in Go). Incoming packets are evaluated in this order.
/// 1. Drop if the destination is multicast or link-local.
/// 2. Drop if the destination is not a local address, even if an allow rule is broad (prevents peers from targeting other destinations).
/// 3. Apply protocol-specific rules. TCP checks rules only for new connections (SYN without ACK). UDP and SCTP accept replies to previously sent flows.
///    ICMP accepts echo replies and errors, and otherwise checks rules for an address match only.
///
/// `docs/protocol-notes/netmap-engine.md` 4.4~4.6 and `docs/contracts/SwiftailEngine.md` behavior 6.
public struct PacketFilter: Sendable {
    /// The decision.
    public enum Verdict: Sendable, Equatable {
        /// Delivers up the stack.
        case accept
        /// Drops the packet.
        case drop(DropReason)
    }

    /// The reason for a discard.
    public enum DropReason: Sendable, Equatable {
        /// The destination is not a local address.
        case notForUs
        /// No matching allow rule exists.
        case noRuleMatched
        /// The destination is multicast or link-local.
        case multicastOrLinkLocal
    }

    private var matches: [FilterMatch]
    private var localAddresses: Set<IPAddress>
    private var flows = FlowTable()

    /// No rules or local addresses. Drops all packets (the state before receiving a netmap).
    public static var allowNone: PacketFilter {
        PacketFilter(matches: [], localAddresses: [])
    }

    /// - Parameters:
    ///   - rules: `Netmap.packetFilter` verbatim. Drops only the individual entries that cannot be parsed.
    ///     Any legacy form (`SrcBits` or `DstPorts[].Bits`) produces a filter with no rules.
    ///   - localAddresses: The local node's addresses. Drops packets with destinations absent from this list.
    public init(rules: [FilterRule], localAddresses: [IPAddress]) {
        self.init(matches: FilterMatch.matches(from: rules), localAddresses: Set(localAddresses))
    }

    private init(matches: [FilterMatch], localAddresses: Set<IPAddress>) {
        self.matches = matches
        self.localAddresses = localAddresses
    }

    /// Evaluates an incoming packet. Replies to previously sent UDP or SCTP can pass without an allow rule.
    public mutating func checkInbound(_ packet: IPPacket) -> Verdict {
        if Self.isMulticastOrLinkLocal(packet.destination) {
            return .drop(.multicastOrLinkLocal)
        }
        guard localAddresses.contains(packet.destination) else {
            return .drop(.notForUs)
        }
        return isAllowed(packet) ? .accept : .drop(.noRuleMatched)
    }

    /// Records outgoing UDP and SCTP packets so their replies can be accepted.
    public mutating func recordOutbound(_ packet: IPPacket) {
        guard packet.transportProtocol == .udp || packet.transportProtocol == .sctp else { return }
        flows.recordReply(to: packet)
    }

    /// Replaces the rules and local addresses while retaining UDP and SCTP flow records.
    public mutating func replaceRules(_ rules: [FilterRule], localAddresses: [IPAddress]) {
        matches = FilterMatch.matches(from: rules)
        self.localAddresses = Set(localAddresses)
    }

    // MARK: - Protocol-specific decisions

    private mutating func isAllowed(_ packet: IPPacket) -> Bool {
        switch packet.transportProtocol {
        case .tcp:
            // The filter does no TCP connection tracking. Only SYN packets with ACK clear are treated as new connections and checked against the rules.
            return !packet.isTCPSYN || matches.contains { $0.matches(packet) }
        case .udp, .sctp:
            return flows.containsFlow(of: packet) || matches.contains { $0.matches(packet) }
        case .icmpv4, .icmpv6:
            return Self.isICMPReplyOrError(packet) || matches.contains { $0.matchesAddresses(of: packet) }
        case .tsmp:
            // The engine consumes TSMP before filtering. If it reaches this point, accept it as Go does.
            return true
        case .other:
            return matches.contains { $0.matchesAllPorts(of: packet) }
        }
    }

    /// Whether this is an echo reply (v4 type 0 or v6 type 129, code 0) or an error message.
    ///
    /// The error types are v4 3 (unreachable), 11 (time exceeded), and 12 (parameter problem), and v6 1, 2, 3, and 4. Go's v4 constant is
    /// 0x12 (18) instead of 12, but RFC 792 sets Parameter Problem to 12, so use 12 (a known difference documented in the contract).
    private static func isICMPReplyOrError(_ packet: IPPacket) -> Bool {
        guard let (type, code) = packet.icmpTypeAndCode else { return false }
        if packet.transportProtocol == .icmpv4 {
            return (type == 0 && code == 0) || [3, 11, 12].contains(type)
        }
        return (type == 129 && code == 0) || (1...4).contains(type)
    }

    /// IPv4 `224.0.0.0/4`·`169.254.0.0/16`, IPv6 `ff00::/8`·`fe80::/10`.
    private static func isMulticastOrLinkLocal(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        if address.isIPv4 {
            return bytes[0] & 0xF0 == 224 || (bytes[0] == 169 && bytes[1] == 254)
        }
        return bytes[0] == 0xFF || (bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80)
    }
}
