// Response headers are ported from the Go implementation. This includes TTL and hop limit 64, no fragmentation or DF, bitwise inversion of the request's
// IP identifier (flow label for IPv6), swapped addresses and ports, and ICMP echo reply type and code.
// Origin: tailscale.com v1.104.6 `net/packet/ip4.go` (`Marshal`, `ToResponse`), `net/packet/ip6.go`,
// `net/packet/udp4.go`, `net/packet/icmp4.go` and `icmp6.go` (`ToResponse`), and `net/tstun/wrap.go` (echo reply injection).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Builds the IP packets the node sends directly in response to packets to the service IP (`100.100.100.100`, `fd7a:115c:a1e0::53`).
///
/// Pure functions with no I/O. The received packet was already parsed as `IPPacket`, and the answer is the IP packet bytes to send back.
/// Swaps source and destination addresses and ports, and fills in the IPv4 header and ICMPv4 checksums, along with the UDP, TCP, and ICMPv6 checksums
/// that include a pseudo-header (the UDP checksum is mandatory for IPv6, RFC 8200 8.1). Returns `nil` for input it cannot answer.
///
/// The caller chooses which packets to answer (whether to the service IP or UDP 53). This code checks only whether a reply can be built. Contract behavior L2
/// specifies DNS responses for UDP 53, replies for ICMP echo, RST for TCP, and discarding the rest (no response or ICMP unreachable).
///
/// shortcut: Does not copy request IPv4 options or IPv6 traffic class into the reply (as in Go). Does not check the request checksum
/// (`IPPacket` does not check it, and neither does the Go wrapper before the filter).
///
/// `docs/contracts/SwiftailTunnel.md` behavior L2 and `docs/protocol-notes/dns-state-node.md` 4.3.
enum ServiceIPReply {
    /// The reply IP packet's TTL and hop limit. Matches Go `net/packet/ip4.go` and `ip6.go`.
    static let hopLimit: UInt8 = 64

    /// A UDP packet carrying `payload` in reply to a UDP datagram. Returns `nil` if the request is not UDP or the reply does not fit in one packet.
    ///
    /// Computes UDP checksums for both IPv4 and IPv6. Writes 0xFFFF for a computed 0 to distinguish it from "no checksum" (RFC 768).
    static func udp(payload: [UInt8], inReplyTo datagram: IPPacket) -> [UInt8]? {
        guard datagram.transportProtocol == .udp else { return nil }
        let length = 8 + payload.count
        guard length <= Int(UInt16.max) else { return nil }
        // Leaves the checksum field (6~7) at 0 for `reply` to fill in.
        let transport = Self.bytes(datagram.destinationPort) + Self.bytes(datagram.sourcePort)
            + Self.bytes(UInt16(length)) + [0, 0] + payload
        return reply(to: datagram, protocolNumber: 17, transport: transport, checksum: .udp)
    }

    /// An echo reply to an ICMP echo request. Returns the identifier, sequence, and payload unchanged.
    /// Accepts only requests of ICMPv4 type 8 or ICMPv6 type 128 with code 0 (Go `Parsed.IsEchoRequest`). Otherwise returns `nil`.
    static func icmpEchoReply(inReplyTo request: IPPacket) -> [UInt8]? {
        guard let (type, code) = request.icmpTypeAndCode, code == 0 else { return nil }
        let isIPv4 = request.transportProtocol == .icmpv4
        guard type == (isIPv4 ? 8 : 128) else { return nil }
        // Copies the identifier, sequence, and payload after the 4-byte header (type, code, checksum). Parsing validated 8 bytes.
        let rest = request.bytes[(request.transportOffset + 4)...]
        let transport: [UInt8] = [isIPv4 ? 0 : 129, 0, 0, 0] + rest
        return reply(to: request, protocolNumber: isIPv4 ? 1 : 58, transport: transport, checksum: isIPv4 ? .icmpv4 : .icmpv6)
    }

    // MARK: - IP layer

    /// Fills the transport segment's checksum field (initially 0) and adds the IP header. Returns `nil` if it does not fit in one packet.
    /// `ServiceIPReply+TCPReset.swift` uses the same path to emit an RST.
    static func reply(to request: IPPacket, protocolNumber: UInt8, transport: [UInt8], checksum: TransportChecksum) -> [UInt8]? {
        let isIPv4 = request.source.isIPv4
        guard transport.count <= Int(UInt16.max) - (isIPv4 ? 20 : 0) else { return nil }
        // The reply's source is the request's destination.
        let source = request.destination.bytes
        let destination = request.source.bytes

        var transport = transport
        let sum = checksum.compute(
            over: transport, source: source, destination: destination, protocolNumber: protocolNumber)
        transport.replaceSubrange(checksum.offset..<checksum.offset + 2, with: Self.bytes(sum))

        let header: [UInt8]
        if isIPv4 {
            // Inverts identifier bits to distinguish the reply from the request (Go `IP4Header.ToResponse`). Flags and fragment offset are 0.
            let identification = ~(UInt16(request.bytes[4]) << 8 | UInt16(request.bytes[5]))
            var ipv4: [UInt8] = [0x45, 0] + Self.bytes(UInt16(20 + transport.count)) + Self.bytes(identification)
                + [0, 0, hopLimit, protocolNumber, 0, 0] + source + destination
            ipv4.replaceSubrange(10..<12, with: Self.bytes(TransportChecksum.internetChecksum(of: ipv4)))
            header = ipv4
        } else {
            // Inverts the 20 flow label bits (Go `IP6Header.ToResponse`). Traffic class is 0.
            let flow = ~(UInt32(request.bytes[1] & 0x0F) << 16 | UInt32(request.bytes[2]) << 8 | UInt32(request.bytes[3])) & 0xF_FFFF
            header = [0x60, UInt8(flow >> 16), UInt8(truncatingIfNeeded: flow >> 8), UInt8(truncatingIfNeeded: flow)]
                + Self.bytes(UInt16(transport.count)) + [protocolNumber, hopLimit] + source + destination
        }
        return header + transport
    }

    /// Two bytes in network byte order (big-endian).
    static func bytes(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }
}
