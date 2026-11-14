// 서비스 IP 응답 시험의 보조 코드. 구현(`ServiceIPReply`)과 무관하게 응답 바이트를 읽고 체크섬을 다시 계산한다.
// RFC 1071의 1의 보수 합과 RFC 768·9293·8200·4443의 의사 머리를 시험 쪽에서 따로 적었다.

import Foundation
import Testing

import SwiftailBase
import SwiftailEngine

enum ReplyFixture {
    /// 16진 문자열을 바이트로 바꾼다.
    static func bytes(hex: String) -> [UInt8] {
        let digits = Array(hex.utf8)
        return stride(from: 0, to: digits.count - 1, by: 2).compactMap { index in
            UInt8(String(decoding: digits[index..<index + 2], as: UTF8.self), radix: 16)
        }
    }

    static func ip(_ text: String) throws -> IPAddress {
        try #require(IPAddress(text))
    }

    static func parse(_ bytes: [UInt8]) throws -> IPPacket {
        try IPPacket(parsing: bytes)
    }

    static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    /// 요청 TCP 세그먼트(IP 패킷). 체크섬은 0이다(응답을 만드는 쪽은 보지 않는다).
    static func tcpRequest(
        from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16,
        sequence: UInt32, acknowledgement: UInt32 = 0, flags: UInt8, options: [UInt8] = [], payload: [UInt8] = []
    ) -> [UInt8] {
        let dataOffset = UInt8((20 + options.count) / 4) << 4
        let header = TestPacket.bigEndian(sourcePort) + TestPacket.bigEndian(destinationPort)
            + be32(sequence) + be32(acknowledgement) + [dataOffset, flags, 0xFF, 0xFF, 0, 0, 0, 0] + options
        return TestPacket.ip(from: source, to: destination, protocolNumber: 6, transport: header + payload)
    }

    /// ICMP echo request(IP 패킷). `body`는 identifier·sequence·data다. 체크섬은 0이다.
    static func echoRequest(from source: String, to destination: String, body: [UInt8], type: UInt8? = nil, code: UInt8 = 0) -> [UInt8] {
        let isIPv6 = source.contains(":")
        return TestPacket.ip(
            from: source, to: destination, protocolNumber: isIPv6 ? 58 : 1,
            transport: [type ?? (isIPv6 ? 128 : 8), code, 0, 0] + body)
    }

    // MARK: - 독립 계산

    /// 바이트의 1의 보수 합(보수를 취하지 않은 것). 홀수 길이는 0을 덧붙인다.
    static func onesComplementSum(_ bytes: [UInt8]) -> UInt16 {
        var sum = 0
        for index in stride(from: 0, to: bytes.count, by: 2) {
            sum += Int(bytes[index]) << 8 + (index + 1 < bytes.count ? Int(bytes[index + 1]) : 0)
        }
        while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
        return UInt16(sum)
    }

    /// IPv4(RFC 768)·IPv6(RFC 8200 8.1)의 의사 머리.
    static func pseudoHeader(source: [UInt8], destination: [UInt8], protocolNumber: UInt8, length: Int) -> [UInt8] {
        let high = UInt8((length >> 8) & 0xFF), low = UInt8(length & 0xFF)
        if source.count == 4 {
            return source + destination + [0, protocolNumber, high, low]
        }
        return source + destination + [0, 0, high, low] + [0, 0, 0, protocolNumber]
    }

    /// 응답 IP 패킷을 시험 쪽에서 읽은 모습. 읽는 동안 머리의 일관성(버전, 길이 필드, IPv4 머리 체크섬, 조각 없음)을
    /// 검사해 어긋나면 시험을 실패시킨다.
    struct Decoded {
        let isIPv4: Bool
        let source: [UInt8]
        let destination: [UInt8]
        let protocolNumber: UInt8
        let hopLimit: UInt8
        /// IPv4 identification 또는 IPv6 flow label.
        let identification: UInt32
        let transport: [UInt8]

        init(_ packet: [UInt8]) throws {
            let first = try #require(packet.first)
            if first >> 4 == 4 {
                #expect(first == 0x45, "옵션 없는 IPv4 머리")
                try #require(packet.count >= 20)
                #expect(Int(packet[2]) << 8 | Int(packet[3]) == packet.count, "IPv4 전체 길이")
                #expect(ReplyFixture.onesComplementSum(Array(packet[0..<20])) == 0xFFFF, "IPv4 머리 체크섬")
                #expect(packet[6] == 0 && packet[7] == 0, "플래그·조각 오프셋 없음")
                isIPv4 = true
                protocolNumber = packet[9]
                hopLimit = packet[8]
                identification = UInt32(packet[4]) << 8 | UInt32(packet[5])
                source = Array(packet[12..<16])
                destination = Array(packet[16..<20])
                transport = Array(packet[20...])
            } else {
                #expect(first >> 4 == 6)
                try #require(packet.count >= 40)
                #expect(Int(packet[4]) << 8 | Int(packet[5]) == packet.count - 40, "IPv6 payload 길이")
                #expect(first == 0x60 && packet[1] & 0xF0 == 0, "traffic class 0")
                isIPv4 = false
                protocolNumber = packet[6]
                hopLimit = packet[7]
                identification = UInt32(packet[1] & 0x0F) << 16 | UInt32(packet[2]) << 8 | UInt32(packet[3])
                source = Array(packet[8..<24])
                destination = Array(packet[24..<40])
                transport = Array(packet[40...])
            }
        }

        /// 전송 계층 체크섬이 맞다: 의사 머리(ICMPv4는 없음)와 전송 계층 전체의 합이 0xFFFF다.
        var transportChecksumIsValid: Bool {
            let message = protocolNumber == 1
                ? transport
                : ReplyFixture.pseudoHeader(source: source, destination: destination, protocolNumber: protocolNumber, length: transport.count) + transport
            return ReplyFixture.onesComplementSum(message) == 0xFFFF
        }

        func word(_ offset: Int) -> UInt16 { UInt16(transport[offset]) << 8 | UInt16(transport[offset + 1]) }
        func long(_ offset: Int) -> UInt32 { UInt32(word(offset)) << 16 | UInt32(word(offset + 2)) }
    }
}
