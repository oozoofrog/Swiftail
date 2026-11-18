import SwiftailBase
import Testing

/// Uses headers from RFC 791, RFC 768, and RFC 9293, and the one's-complement sum from RFC 1071. No Go implementation is copied.
/// Uses a pseudo-header checked against gVisor's pkg/tcpip/header/{ipv4,udp,tcp,checksum}.go.
enum Packets {
    static func word(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    static func long(_ value: UInt32) -> [UInt8] {
        word(UInt16(truncatingIfNeeded: value >> 16)) + word(UInt16(truncatingIfNeeded: value))
    }

    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        for index in stride(from: 0, to: bytes.count, by: 2) {
            sum += UInt32(bytes[index]) << 8
            if index + 1 < bytes.count { sum += UInt32(bytes[index + 1]) }
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }

    static func pseudoHeader(_ source: IPAddress, _ destination: IPAddress, _ proto: UInt8, _ length: Int) -> [UInt8] {
        source.bytes + destination.bytes + (source.isIPv4
            ? [0, proto] + word(UInt16(length))
            : long(UInt32(length)) + [0, 0, 0, proto])
    }

    static func udp(from source: IPAddress, port: UInt16, to destination: IPAddress,
                    destinationPort: UInt16 = 7, payload: [UInt8]) -> [UInt8] {
        let transport = word(port) + word(destinationPort) + word(UInt16(8 + payload.count)) + [0, 0] + payload
        return ip(source, destination, proto: 17, transport: transport, checksumOffset: 6)
    }

    static func syn(from source: IPAddress, port: UInt16, to destination: IPAddress,
                    destinationPort: UInt16, sequence: UInt32) -> [UInt8] {
        let transport = word(port) + word(destinationPort) + long(sequence) + long(0)
            + [0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]
        return ip(source, destination, proto: 6, transport: transport, checksumOffset: 16)
    }

    private static func ip(_ source: IPAddress, _ destination: IPAddress, proto: UInt8,
                           transport: [UInt8], checksumOffset: Int) -> [UInt8] {
        var transport = transport
        var sum = checksum(pseudoHeader(source, destination, proto, transport.count) + transport)
        // Encode a computed UDP checksum of 0 as 0xffff to distinguish it from "no checksum" (RFC 768).
        if proto == 17 && sum == 0 { sum = 0xffff }
        transport.replaceSubrange(checksumOffset..<checksumOffset + 2, with: word(sum))
        if !source.isIPv4 {
            return [0x60, 0, 0, 0] + word(UInt16(transport.count)) + [proto, 64]
                + source.bytes + destination.bytes + transport
        }
        var header: [UInt8] = [0x45, 0] + word(UInt16(20 + transport.count)) + [0, 0, 0x40, 0, 64, proto, 0, 0]
            + source.bytes + destination.bytes
        header.replaceSubrange(10..<12, with: word(checksum(header)))
        return header + transport
    }
}

/// Validates boundaries and checksums of the bytes actually received without reusing the engine's parser.
struct ReceivedPacket: Sendable {
    let source: IPAddress
    let destination: IPAddress
    let proto: UInt8
    let sourcePort: UInt16
    let destinationPort: UInt16
    let flags: UInt8
    let sequence: UInt32
    let acknowledgement: UInt32
    let payload: [UInt8]

    init(_ bytes: [UInt8]) throws {
        guard let first = bytes.first else { throw GateFailure("Empty received IP packet") }
        let headerLength: Int
        let totalLength: Int
        let sourceBytes: [UInt8]
        let destinationBytes: [UInt8]
        switch first >> 4 {
        case 4:
            guard bytes.count >= 20 else { throw GateFailure("Short received IPv4 header") }
            headerLength = Int(first & 15) * 4
            totalLength = Int(Self.word(bytes, 2))
            guard headerLength >= 20, headerLength <= totalLength, totalLength <= bytes.count,
                  Self.word(bytes, 6) & 0x3fff == 0,
                  Packets.checksum(Array(bytes[..<headerLength])) == 0 else {
                throw GateFailure("Invalid received IPv4 length, fragmentation, or header checksum")
            }
            proto = bytes[9]
            sourceBytes = Array(bytes[12..<16]); destinationBytes = Array(bytes[16..<20])
        case 6:
            guard bytes.count >= 40 else { throw GateFailure("Short received IPv6 header") }
            headerLength = 40
            totalLength = 40 + Int(Self.word(bytes, 4))
            guard totalLength <= bytes.count else { throw GateFailure("Invalid received IPv6 length") }
            proto = bytes[6]
            sourceBytes = Array(bytes[8..<24]); destinationBytes = Array(bytes[24..<40])
        default: throw GateFailure("Invalid received IP version")
        }
        source = try #require(IPAddress(bytes: sourceBytes))
        destination = try #require(IPAddress(bytes: destinationBytes))
        let transport = Array(bytes[headerLength..<totalLength])
        guard (proto == 17 && transport.count >= 8) || (proto == 6 && transport.count >= 20) else {
            throw GateFailure("Unexpected received protocol or short transport header: \(proto)")
        }
        guard Packets.checksum(Packets.pseudoHeader(source, destination, proto, transport.count) + transport) == 0 else {
            throw GateFailure("Invalid received TCP or UDP checksum (protocol \(proto))")
        }
        sourcePort = Self.word(transport, 0); destinationPort = Self.word(transport, 2)
        if proto == 17 {
            guard Int(Self.word(transport, 4)) == transport.count else { throw GateFailure("Invalid received UDP length") }
            flags = 0; sequence = 0; acknowledgement = 0
            payload = Array(transport.dropFirst(8))
        } else {
            let offset = Int(transport[12] >> 4) * 4
            guard offset >= 20, offset <= transport.count else { throw GateFailure("Invalid received TCP data offset") }
            flags = transport[13]
            sequence = Self.long(transport, 4); acknowledgement = Self.long(transport, 8)
            payload = Array(transport.dropFirst(offset))
        }
    }

    private static func word(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
    private static func long(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(word(bytes, offset)) << 16 | UInt32(word(bytes, offset + 2))
    }
}

@Test("Packet helpers cover known checksums, odd-length payloads, and both address families")
func packetChecksum() throws {
    // Fixed vector from RFC 1071 §3 (sum 0xddf2).
    #expect(Packets.checksum([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]) == 0x220d)
    for (sourceText, destinationText) in [("100.64.0.1", "100.64.0.2"), ("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2")] {
        let source = try #require(IPAddress(sourceText)), destination = try #require(IPAddress(destinationText))
        let udp = Packets.udp(from: source, port: 42000, to: destination, payload: [1, 2, 3])
        let decoded = try ReceivedPacket(udp)
        #expect(decoded.payload == [1, 2, 3])
        #expect(decoded.source == source && decoded.destination == destination)
        #expect(decoded.sourcePort == 42000 && decoded.destinationPort == 7)
        let syn = try ReceivedPacket(Packets.syn(from: source, port: 42001, to: destination, destinationPort: 7, sequence: 0x10203040))
        #expect(syn.flags == 2 && syn.sequence == 0x10203040)
        var corrupt = udp; corrupt[corrupt.count - 1] ^= 1
        #expect(throws: GateFailure.self) { try ReceivedPacket(corrupt) }
    }
}
