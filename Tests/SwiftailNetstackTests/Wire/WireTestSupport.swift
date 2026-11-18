// Shared codec test helpers. Testing the serializer (`TCPSegment.ipPacket`) and parser against one another requires building expected bytes independently of the implementation,
// so IP headers, TCP headers, and checksums are built independently inside the test here.

import SwiftailBase

@testable import SwiftailNetstack

/// Fake addresses used for tests. They are not real tailnet addresses.
enum WireHosts {
    static let v4a = address("100.64.0.1")
    static let v4b = address("100.64.0.2")
    static let v6a = address("fd7a:115c:a1e0::1")
    static let v6b = address("fd7a:115c:a1e0::2")

    static func address(_ text: String) -> IPAddress {
        guard let address = IPAddress(text) else { fatalError("Invalid test address text: \(text)") }
        return address
    }

    static func endpoint(_ address: IPAddress, _ port: UInt16) -> IPEndpoint {
        IPEndpoint(address: address, port: port)
    }
}

/// A packet built directly from bytes without using the implementation's serializer or parser.
enum RawPacket {
    /// An Internet checksum independent of the implementation: sum the words, add the carry back, then complement the result.
    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum = 0
        for index in stride(from: 0, to: bytes.count, by: 2) {
            let low = index + 1 < bytes.count ? Int(bytes[index + 1]) : 0
            sum += Int(bytes[index]) << 8 | low
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
        }
        return UInt16(~sum & 0xFFFF)
    }

    static func be16(_ value: Int) -> [UInt8] {
        [UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    /// A TCP segment (checksum field 0). Pads options with 0 (EOL) to a multiple of 4 bytes. If `dataOffset` is given, uses it for the header field.
    static func segment(
        sourcePort: UInt16 = 40_000, destinationPort: UInt16 = 443,
        sequence: UInt32 = 1, acknowledgment: UInt32 = 0,
        flags: UInt8 = 0x10, window: UInt16 = 1000, urgent: UInt16 = 0,
        options: [UInt8] = [], dataOffset: Int? = nil, payload: [UInt8] = []
    ) -> [UInt8] {
        var options = options
        while options.count % 4 != 0 { options.append(0) }
        let words = dataOffset ?? (5 + options.count / 4)
        return be16(Int(sourcePort)) + be16(Int(destinationPort)) + be32(sequence) + be32(acknowledgment)
            + [UInt8(words << 4), flags] + be16(Int(window)) + [0, 0] + be16(Int(urgent)) + options + payload
    }

    /// Calculates the TCP checksum from the addresses and writes it to bytes 16~17 of `segment`.
    static func withTCPChecksum(_ segment: [UInt8], source: IPAddress, destination: IPAddress) -> [UInt8] {
        guard segment.count >= 18 else { return segment }
        var segment = segment
        segment[16] = 0
        segment[17] = 0
        let pseudo: [UInt8]
        if source.isIPv4 {
            pseudo = source.bytes + destination.bytes + [0, 6] + be16(segment.count)
        } else {
            pseudo = source.bytes + destination.bytes + be32(UInt32(segment.count)) + [0, 0, 0, 6]
        }
        let sum = checksum(pseudo + segment)
        segment[16] = UInt8(sum >> 8)
        segment[17] = UInt8(sum & 0xFF)
        return segment
    }

    /// An IPv4 packet. `ipOptions` is a multiple of 4 bytes. Sets the TCP and IPv4 header checksums (skips both if `fixChecksums` is false).
    static func ipv4(
        source: IPAddress = WireHosts.v4a, destination: IPAddress = WireHosts.v4b,
        segment: [UInt8], ipOptions: [UInt8] = [], protocolNumber: UInt8 = 6,
        flagsAndOffset: UInt16 = 0x4000, ttl: UInt8 = 64, fixChecksums: Bool = true
    ) -> [UInt8] {
        let segment = fixChecksums && protocolNumber == 6
            ? withTCPChecksum(segment, source: source, destination: destination) : segment
        let headerLength = 20 + ipOptions.count
        var header: [UInt8] = [UInt8(0x40 | headerLength / 4), 0] + be16(headerLength + segment.count) + [0, 0]
            + be16(Int(flagsAndOffset)) + [ttl, protocolNumber, 0, 0] + source.bytes + destination.bytes + ipOptions
        if fixChecksums {
            let sum = checksum(header)
            header[10] = UInt8(sum >> 8)
            header[11] = UInt8(sum & 0xFF)
        }
        return header + segment
    }

    /// An IPv6 packet (no extension headers). Skips the TCP checksum if `nextHeader` is not 6.
    static func ipv6(
        source: IPAddress = WireHosts.v6a, destination: IPAddress = WireHosts.v6b,
        segment: [UInt8], nextHeader: UInt8 = 6, hopLimit: UInt8 = 64, fixChecksums: Bool = true
    ) -> [UInt8] {
        let segment = fixChecksums && nextHeader == 6
            ? withTCPChecksum(segment, source: source, destination: destination) : segment
        return [0x60, 0, 0, 0] + be16(segment.count) + [nextHeader, hopLimit] + source.bytes + destination.bytes + segment
    }

    /// Recalculates the TCP checksum from an IP packet's addresses and updates it (for tests that modify option or header lengths). Leaves packets alone if they are too short or their addresses cannot be read.
    static func refixingTCPChecksum(_ packet: [UInt8]) -> [UInt8] {
        guard let first = packet.first else { return packet }
        let isIPv4 = first >> 4 == 4
        let headerLength = isIPv4 ? Int(first & 0x0F) * 4 : 40
        let addressLength = isIPv4 ? 4 : 16
        let sourceStart = isIPv4 ? 12 : 8
        guard headerLength >= sourceStart + 2 * addressLength, headerLength <= packet.count,
              let source = IPAddress(bytes: packet[sourceStart..<sourceStart + addressLength]),
              let destination = IPAddress(bytes: packet[sourceStart + addressLength..<sourceStart + 2 * addressLength])
        else { return packet }
        var packet = packet
        let segment = withTCPChecksum(Array(packet[headerLength...]), source: source, destination: destination)
        packet.replaceSubrange(headerLength..., with: segment)
        return packet
    }
}

/// Reproducible pseudorandom numbers (SplitMix64).
struct WireFuzzRandom: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &self) }
    }
}
