// Shared test helpers for building IP packets and creating netmaps and filter rules from JSON, plus reproducible pseudorandom numbers.
// tailcfg fields cannot be set from outside their module, so decode the same JSON the control server sends.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// The monotonic reference time for tests. Pass this time plus a Duration instead of waiting for wall-clock time to elapse.
let clockStart = ContinuousClock.now
/// The wall-clock time at clockStart is 2027-01-15T08:00:00Z.
let wallClockStart = Date(timeIntervalSince1970: 1_800_000_000)

// MARK: - IP packets

/// IP packets for tests. Checksums are 0 because the engine ignores them.
enum TestPacket {
    /// Builds an IPv4 header followed by transport bytes. The length of options must be a multiple of 4 bytes.
    static func ipv4(
        from source: String, to destination: String, protocolNumber: UInt8, transport: [UInt8],
        flagsAndOffset: UInt16 = 0, options: [UInt8] = []
    ) -> [UInt8] {
        let headerLength = 20 + options.count
        let total = headerLength + transport.count
        return [0x40 | UInt8(headerLength / 4), 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0,
                UInt8(flagsAndOffset >> 8), UInt8(flagsAndOffset & 0xFF), 64, protocolNumber, 0, 0]
            + address(source) + address(destination) + options + transport
    }

    /// Builds an IPv6 header followed by transport bytes.
    static func ipv6(from source: String, to destination: String, nextHeader: UInt8, transport: [UInt8]) -> [UInt8] {
        [0x60, 0, 0, 0, UInt8(transport.count >> 8), UInt8(transport.count & 0xFF), nextHeader, 64]
            + address(source) + address(destination) + transport
    }

    /// Prepends an IP header for the address family.
    static func ip(from source: String, to destination: String, protocolNumber: UInt8, transport: [UInt8]) -> [UInt8] {
        source.contains(":")
            ? ipv6(from: source, to: destination, nextHeader: protocolNumber, transport: transport)
            : ipv4(from: source, to: destination, protocolNumber: protocolNumber, transport: transport)
    }

    static func udp(from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16, payload: [UInt8] = [0xAB]) -> [UInt8] {
        let length = 8 + payload.count
        let header = bigEndian(sourcePort) + bigEndian(destinationPort) + [UInt8(length >> 8), UInt8(length & 0xFF), 0, 0]
        return ip(from: source, to: destination, protocolNumber: 17, transport: header + payload)
    }

    /// Builds a 12-byte SCTP common header with a verification tag and checksum of 0.
    static func sctp(from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16) -> [UInt8] {
        ip(from: source, to: destination, protocolNumber: 132, transport: bigEndian(sourcePort) + bigEndian(destinationPort) + [UInt8](repeating: 0, count: 8))
    }

    /// Builds a 20-byte TCP header (data offset 5). flags is the 13th byte (SYN 0x02, ACK 0x10, RST 0x04).
    static func tcp(from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16, flags: UInt8) -> [UInt8] {
        let header = bigEndian(sourcePort) + bigEndian(destinationPort) + [0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xFF, 0xFF, 0, 0, 0, 0]
        return ip(from: source, to: destination, protocolNumber: 6, transport: header)
    }

    /// Builds an 8-byte ICMP header. The address family determines whether it is ICMPv4 (1) or ICMPv6 (58).
    static func icmp(from source: String, to destination: String, type: UInt8, code: UInt8 = 0) -> [UInt8] {
        ip(from: source, to: destination, protocolNumber: source.contains(":") ? 58 : 1, transport: [type, code, 0, 0, 0, 1, 0, 1])
    }

    static func address(_ text: String) -> [UInt8] {
        IPAddress(text)?.bytes ?? []
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }
}

// MARK: - tailcfg JSON

/// Decodes a JSON array of filter rules.
func decodeFilterRules(_ json: String) throws -> [FilterRule] {
    try JSONDecoder().decode([FilterRule].self, from: Data(json.utf8))
}

/// Returns the netmap from a session initialized with one map response.
/// - Parameters:
///   - selfNode: The self node's JSON.
///   - peers: The peer nodes' JSON.
///   - packetFilter: The JSON array for the `PacketFilter` field.
func makeNetmap(selfNode: String, peers: [String], packetFilter: String = "[]") throws -> Netmap {
    let json = #"{"Node":\#(selfNode),"Peers":[\#(peers.joined(separator: ","))],"PacketFilter":\#(packetFilter)}"#
    let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
    var session = MapSession()
    return try #require(try session.apply(response, receivedAt: wallClockStart).netmap)
}

/// Returns node JSON. extra starts with a comma, as in `,"HomeDERP":1`.
func makeNodeJSON(id: Int64, key: NodePublicKey, addresses: [String], extra: String = "") -> String {
    let addressList = addresses.map { "\"\($0)\"" }.joined(separator: ",")
    return #"{"ID":\#(id),"Name":"node\#(id).tail0001.ts.net.","User":\#(100 + id),"Key":"\#(key)","Addresses":[\#(addressList)]\#(extra)}"#
}

/// A nonzero disco key in text form.
let discoKeyText = "discokey:" + [UInt8](repeating: 0xD1, count: 32).hex

/// Creates a node public key from 32 identical bytes.
func makeNodeKey(byte: UInt8) -> NodePublicKey {
    NodePublicKey(rawValue: [UInt8](repeating: byte, count: 32)) ?? .zero
}

// MARK: - Pseudorandom numbers

/// A reproducible pseudorandom number generator (SplitMix64) for fuzz input.
struct FuzzRandom: RandomNumberGenerator {
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
