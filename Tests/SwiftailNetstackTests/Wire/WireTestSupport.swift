// 코덱 시험 공용 도우미. 만드는 쪽(`TCPSegment.ipPacket`)과 해석하는 쪽을 서로 시험하려면 기대 바이트를 구현과 따로 만들어야
// 하므로, 여기에 IP 머리·TCP 머리·체크섬을 시험 안에서 독립적으로 짜 둔다.

import SwiftailBase

@testable import SwiftailNetstack

/// 시험에 쓰는 가짜 주소. 실제 tailnet 주소가 아니다.
enum WireHosts {
    static let v4a = address("100.64.0.1")
    static let v4b = address("100.64.0.2")
    static let v6a = address("fd7a:115c:a1e0::1")
    static let v6b = address("fd7a:115c:a1e0::2")

    static func address(_ text: String) -> IPAddress {
        guard let address = IPAddress(text) else { fatalError("시험의 주소 글자가 틀렸다: \(text)") }
        return address
    }

    static func endpoint(_ address: IPAddress, _ port: UInt16) -> IPEndpoint {
        IPEndpoint(address: address, port: port)
    }
}

/// 바이트로 직접 짜는 패킷. 구현의 만들기·해석을 쓰지 않는다.
enum RawPacket {
    /// 구현과 공유하지 않는 인터넷 체크섬: 낱말마다 더하고 올림을 되돌려 더한 뒤 보수.
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

    /// TCP 세그먼트(체크섬 필드는 0). 옵션은 0(EOL)으로 4바이트 배수까지 채운다. `dataOffset`을 주면 머리의 값을 그것으로 쓴다.
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

    /// TCP 체크섬을 주소에서 계산해 `segment`의 16~17번 바이트에 쓴다.
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

    /// IPv4 패킷. `ipOptions`는 4바이트 배수다. TCP 체크섬과 IPv4 머리 체크섬을 채운다(`fixChecksums`가 거짓이면 채우지 않는다).
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

    /// IPv6 패킷(확장 헤더 없음). `nextHeader`가 6이 아니면 TCP 체크섬은 채우지 않는다.
    static func ipv6(
        source: IPAddress = WireHosts.v6a, destination: IPAddress = WireHosts.v6b,
        segment: [UInt8], nextHeader: UInt8 = 6, hopLimit: UInt8 = 64, fixChecksums: Bool = true
    ) -> [UInt8] {
        let segment = fixChecksums && nextHeader == 6
            ? withTCPChecksum(segment, source: source, destination: destination) : segment
        return [0x60, 0, 0, 0] + be16(segment.count) + [nextHeader, hopLimit] + source.bytes + destination.bytes + segment
    }

    /// IP 패킷 안의 TCP 체크섬을 패킷의 주소로 다시 계산해 쓴다(옵션·머리 길이를 고친 시험용). 패킷이 너무 짧거나 주소를 읽을 수 없으면 그대로 둔다.
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

/// 재현할 수 있는 의사 난수(SplitMix64).
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
