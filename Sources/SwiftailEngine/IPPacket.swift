import SwiftailBase

/// The validated header of an IP packet. Holds only fields read by the filter and path selection.
///
/// Bytes from a peer or upper layer are untrusted. At the boundary, validate the length and header once,
/// trim to the declared length, and convert to this value. Later code does not recheck index bounds.
///
/// Stricter than Go's `packet.Parsed`. Validates the minimum IHL and TCP header length, and rejects fragments and IPv6 extension headers
/// without parsing them (there is no reassembly stack). A fresh value for each packet prevents fields from a prior packet from carrying over.
///
/// `docs/protocol-notes/netmap-engine.md` 3.1 and 3.2, and `docs/contracts/SwiftailEngine.md` behavior 1.
public struct IPPacket: Sendable, Equatable {
    /// The transport-layer protocol. Its number is the IP header's protocol (IPv4) or next-header (IPv6) field.
    public enum TransportProtocol: Sendable, Equatable {
        /// 6. Has ports. The filter checks rules only for the start of a new connection (SYN).
        case tcp
        /// 17. Has ports. Replies to previously sent flows are accepted without checking the rules.
        case udp
        /// 132. Treated like UDP by the filter.
        case sctp
        /// 1.
        case icmpv4
        /// 58.
        case icmpv6
        /// 99. Tailscale control messages exchanged through the tunnel and consumed by the engine.
        case tsmp
        /// Any other number. Has no ports.
        case other(UInt8)
    }

    /// A packet that cannot be parsed or is unsupported in M3.
    public enum ParseError: Error, Sendable, Equatable {
        /// Invalid length, version, or header length.
        case malformed
        /// A fragment, including the first fragment.
        case fragment
        /// An IPv6 extension header.
        case extensionHeader
    }

    /// The entire packet truncated to the declared length.
    public let bytes: [UInt8]
    /// The source address in the IP header.
    public let source: IPAddress
    /// The destination address in the IP header.
    public let destination: IPAddress
    /// The transport-layer protocol.
    public let transportProtocol: TransportProtocol
    /// The source port for TCP, UDP, or SCTP. Otherwise 0.
    public let sourcePort: UInt16
    /// The destination port for TCP, UDP, or SCTP. Otherwise 0.
    public let destinationPort: UInt16
    /// A TCP packet with SYN set and ACK clear (the start of a new connection).
    public let isTCPSYN: Bool

    /// The protocol number in the IP header. Compared with the filter rule's `IPProto`.
    let protocolNumber: UInt8
    /// The transport header offset (the IP header length).
    let transportOffset: Int

    /// Parses a sequence of bytes as an IP packet.
    ///
    /// - Throws: `malformed` if the length, version, or header length is invalid, or the transport header is below its minimum length,
    ///   `malformed` if the IPv4 protocol number or IPv6 next-header is 255, or the IPv4 protocol number is 0,
    ///   `fragment` for a fragment, or `extensionHeader` for an IPv6 extension header.
    public init(parsing bytes: [UInt8]) throws(ParseError) {
        guard let first = bytes.first else { throw .malformed }
        let header: Header
        switch first >> 4 {
        case 4: header = try Header(ipv4: bytes)
        case 6: header = try Header(ipv6: bytes)
        default: throw .malformed
        }
        guard let source = IPAddress(bytes: bytes[header.sourceRange]),
              let destination = IPAddress(bytes: bytes[header.destinationRange])
        else { throw .malformed }

        // Strips bytes beyond the declared length (such as link-layer padding). All further checks use the truncated packet.
        let packet = Array(bytes[..<header.totalLength])
        let offset = header.length
        let transportLength = packet.count - offset
        let isIPv4 = header.isIPv4

        var sourcePort: UInt16 = 0
        var destinationPort: UInt16 = 0
        var isTCPSYN = false
        let transportProtocol: TransportProtocol
        switch header.protocolNumber {
        case 6:
            // The TCP header must be at least 20 bytes, and the header end indicated by data offset must lie within the packet.
            guard transportLength >= 20 else { throw .malformed }
            let dataOffset = Int(packet[offset + 12] >> 4) * 4
            guard dataOffset >= 20, dataOffset <= transportLength else { throw .malformed }
            sourcePort = Self.uint16(packet, at: offset)
            destinationPort = Self.uint16(packet, at: offset + 2)
            // SYN (0x02) set and ACK (0x10) clear. Go `Parsed.IsTCPSyn`.
            isTCPSYN = packet[offset + 13] & 0x12 == 0x02
            transportProtocol = .tcp
        case 17:
            guard transportLength >= 8 else { throw .malformed }
            sourcePort = Self.uint16(packet, at: offset)
            destinationPort = Self.uint16(packet, at: offset + 2)
            transportProtocol = .udp
        case 132:
            // The 12-byte SCTP common header. Ports are in the same positions as UDP.
            guard transportLength >= 12 else { throw .malformed }
            sourcePort = Self.uint16(packet, at: offset)
            destinationPort = Self.uint16(packet, at: offset + 2)
            transportProtocol = .sctp
        case 1 where isIPv4, 58 where !isIPv4:
            // The 8-byte ICMP header contains type, code, checksum, and a 4-byte remainder. Echo and error detection use this length.
            guard transportLength >= 8 else { throw .malformed }
            transportProtocol = isIPv4 ? .icmpv4 : .icmpv6
        case 99:
            transportProtocol = .tsmp
        case 0, 255:
            // The Go parser maps both to Unknown and discards them regardless of rules. IPv6 0 (hop-by-hop) was already filtered.
            throw .malformed
        case let number:
            // Treats an ICMP number from another family (such as 58 in IPv4) as another protocol, as Go does.
            transportProtocol = .other(number)
        }

        self.bytes = packet
        self.source = source
        self.destination = destination
        self.transportProtocol = transportProtocol
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.isTCPSYN = isTCPSYN
        self.protocolNumber = header.protocolNumber
        self.transportOffset = offset
    }

    /// The type and code of an ICMP message, or `nil` for a non-ICMP message. Parsing validated the 8-byte ICMP header.
    var icmpTypeAndCode: (type: UInt8, code: UInt8)? {
        switch transportProtocol {
        case .icmpv4, .icmpv6: (bytes[transportOffset], bytes[transportOffset + 1])
        default: nil
        }
    }

    /// Call only after checking the header length.
    private static func uint16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    /// Values read from the IP header. All ranges are checked against the buffer at construction.
    private struct Header {
        let isIPv4: Bool
        /// The IP header length, including IPv4 options.
        let length: Int
        /// The declared total packet length, at least `length` and no more than the buffer length.
        let totalLength: Int
        let protocolNumber: UInt8
        let sourceRange: Range<Int>
        let destinationRange: Range<Int>

        /// IPv4 requires at least 20 bytes, IHL of at least 5, and a header length in bytes no greater than the declared packet length, which must fit in the buffer. MF or a nonzero fragment offset indicates a fragment.
        init(ipv4 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 20 else { throw .malformed }
            let headerLength = Int(bytes[0] & 0x0F) * 4
            let totalLength = Int(IPPacket.uint16(bytes, at: 2))
            guard headerLength >= 20, headerLength <= totalLength, totalLength <= bytes.count else { throw .malformed }
            // The MF bit (0x2000) and 13-bit fragment offset at 6:2. The first fragment (only MF set) is also a fragment.
            let flagsAndOffset = IPPacket.uint16(bytes, at: 6)
            guard flagsAndOffset & 0x3FFF == 0 else { throw .fragment }

            isIPv4 = true
            length = headerLength
            self.totalLength = totalLength
            protocolNumber = bytes[9]
            sourceRange = 12..<16
            destinationRange = 16..<20
        }

        /// IPv6 requires at least 40 bytes and 40 + payload length ≤ buffer. Next-header 44 indicates a fragment. Extension headers are rejected.
        init(ipv6 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 40 else { throw .malformed }
            let totalLength = 40 + Int(IPPacket.uint16(bytes, at: 4))
            guard totalLength <= bytes.count else { throw .malformed }
            let nextHeader = bytes[6]
            guard nextHeader != 44 else { throw .fragment }
            // hop-by-hop(0), routing(43), ESP(50), AH(51), destination options(60), mobility(135),
            // HIP (139) and shim6 (140). Does not follow the chain to read the inner transport header.
            guard ![0, 43, 50, 51, 60, 135, 139, 140].contains(nextHeader) else { throw .extensionHeader }

            isIPv4 = false
            length = 40
            self.totalLength = totalLength
            protocolNumber = nextHeader
            sourceRange = 8..<24
            destinationRange = 24..<40
        }
    }
}
