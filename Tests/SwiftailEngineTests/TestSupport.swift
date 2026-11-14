// 시험 공용 도우미: IP 패킷 만들기, JSON에서 netmap·필터 규칙 만들기, 재현 가능한 의사 난수.
// tailcfg 값의 필드는 바깥에서 쓸 수 없으므로 제어 서버가 보내는 것과 같은 JSON을 해독해 만든다.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// 시험의 기준 단조 시각. 실제 시간은 기다리지 않고 여기에 Duration을 더해 넘긴다.
let clockStart = ContinuousClock.now
/// clockStart 시점의 벽시계: 2027-01-15T08:00:00Z.
let wallClockStart = Date(timeIntervalSince1970: 1_800_000_000)

// MARK: - IP 패킷

/// 시험용 IP 패킷. 체크섬은 0이다(엔진은 보지 않는다).
enum TestPacket {
    /// IPv4 머리 + transport. options는 4바이트 배수여야 한다.
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

    /// IPv6 머리 + transport.
    static func ipv6(from source: String, to destination: String, nextHeader: UInt8, transport: [UInt8]) -> [UInt8] {
        [0x60, 0, 0, 0, UInt8(transport.count >> 8), UInt8(transport.count & 0xFF), nextHeader, 64]
            + address(source) + address(destination) + transport
    }

    /// 주소 종류에 맞는 IP 머리를 붙인다.
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

    /// SCTP 공통 머리 12바이트(verification tag와 checksum은 0).
    static func sctp(from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16) -> [UInt8] {
        ip(from: source, to: destination, protocolNumber: 132, transport: bigEndian(sourcePort) + bigEndian(destinationPort) + [UInt8](repeating: 0, count: 8))
    }

    /// TCP 머리 20바이트(data offset 5). flags는 13번째 바이트(SYN 0x02, ACK 0x10, RST 0x04).
    static func tcp(from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16, flags: UInt8) -> [UInt8] {
        let header = bigEndian(sourcePort) + bigEndian(destinationPort) + [0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xFF, 0xFF, 0, 0, 0, 0]
        return ip(from: source, to: destination, protocolNumber: 6, transport: header)
    }

    /// ICMP 머리 8바이트. 주소 종류에 따라 ICMPv4(1) 또는 ICMPv6(58).
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

/// 필터 규칙 JSON 배열을 해독한다.
func decodeFilterRules(_ json: String) throws -> [FilterRule] {
    try JSONDecoder().decode([FilterRule].self, from: Data(json.utf8))
}

/// 맵 응답 하나로 시작한 세션의 netmap.
/// - Parameters:
///   - selfNode: self 노드 JSON.
///   - peers: 피어 노드 JSON들.
///   - packetFilter: `PacketFilter` 필드의 JSON 배열.
func makeNetmap(selfNode: String, peers: [String], packetFilter: String = "[]") throws -> Netmap {
    let json = #"{"Node":\#(selfNode),"Peers":[\#(peers.joined(separator: ","))],"PacketFilter":\#(packetFilter)}"#
    let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
    var session = MapSession()
    return try #require(try session.apply(response, receivedAt: wallClockStart).netmap)
}

/// 노드 JSON. extra는 `,"HomeDERP":1`처럼 쉼표로 시작한다.
func makeNodeJSON(id: Int64, key: NodePublicKey, addresses: [String], extra: String = "") -> String {
    let addressList = addresses.map { "\"\($0)\"" }.joined(separator: ",")
    return #"{"ID":\#(id),"Name":"node\#(id).tail0001.ts.net.","User":\#(100 + id),"Key":"\#(key)","Addresses":[\#(addressList)]\#(extra)}"#
}

/// 0이 아닌 disco 키 텍스트.
let discoKeyText = "discokey:" + [UInt8](repeating: 0xD1, count: 32).hex

/// 같은 바이트 32개로 만든 node 공개 키.
func makeNodeKey(byte: UInt8) -> NodePublicKey {
    NodePublicKey(rawValue: [UInt8](repeating: byte, count: 32)) ?? .zero
}

// MARK: - 의사 난수

/// 재현할 수 있는 의사 난수(SplitMix64). 퍼즈 입력용이다.
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
