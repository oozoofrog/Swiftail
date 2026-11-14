import SwiftailBase

/// 검증을 마친 IP 패킷 하나의 머리. 필터와 경로 선택이 읽는 필드만 담는다.
///
/// 피어가 보냈거나 위층이 내려보낸 바이트열은 신뢰하지 않는다. 경계에서 한 번 길이와 머리를 검사하고,
/// 선언된 길이로 잘라 이 값으로 바꾼다. 그 뒤의 코드는 인덱스 범위를 다시 따지지 않는다.
///
/// Go의 `packet.Parsed`보다 엄격하다. IHL의 최솟값과 TCP 머리 길이를 검사하고, 조각과 IPv6 확장 헤더는
/// 해석하지 않고 거절한다(재조립하는 스택이 없다). 매 패킷을 새 값으로 만들므로 이전 패킷의 필드가 남지 않는다.
///
/// `docs/protocol-notes/netmap-engine.md` 3.1·3.2, `docs/contracts/SwiftailEngine.md` 동작 1.
public struct IPPacket: Sendable, Equatable {
    /// 전송 계층 프로토콜. 번호는 IP 머리의 protocol(IPv4)·next-header(IPv6) 필드다.
    public enum TransportProtocol: Sendable, Equatable {
        /// 6. 포트가 있고, 새 연결의 시작(SYN)만 필터 규칙을 본다.
        case tcp
        /// 17. 포트가 있고, 먼저 보낸 흐름의 응답은 규칙 없이 받는다.
        case udp
        /// 132. 필터에서는 UDP와 같다.
        case sctp
        /// 1.
        case icmpv4
        /// 58.
        case icmpv6
        /// 99. Tailscale이 터널 안에서 주고받는 제어 메시지. 엔진이 소비한다.
        case tsmp
        /// 그 밖의 번호. 포트가 없다.
        case other(UInt8)
    }

    /// 해석할 수 없거나 M3에서 받지 않는 패킷.
    public enum ParseError: Error, Sendable, Equatable {
        /// 길이·버전·머리 길이가 맞지 않음.
        case malformed
        /// 조각(첫 조각 포함).
        case fragment
        /// IPv6 확장 헤더.
        case extensionHeader
    }

    /// 선언된 길이로 자른 패킷 전체.
    public let bytes: [UInt8]
    /// IP 머리의 출발 주소.
    public let source: IPAddress
    /// IP 머리의 목적 주소.
    public let destination: IPAddress
    /// 전송 계층 프로토콜.
    public let transportProtocol: TransportProtocol
    /// TCP·UDP·SCTP의 출발 포트. 그 밖에는 0.
    public let sourcePort: UInt16
    /// TCP·UDP·SCTP의 목적 포트. 그 밖에는 0.
    public let destinationPort: UInt16
    /// TCP에서 SYN이 켜지고 ACK가 꺼진 패킷(새 연결의 시작).
    public let isTCPSYN: Bool

    /// IP 머리의 프로토콜 번호. 필터 규칙의 `IPProto`와 견준다.
    let protocolNumber: UInt8
    /// 전송 머리가 시작하는 위치(IP 머리의 길이).
    let transportOffset: Int

    /// 바이트열을 IP 패킷으로 해석한다.
    ///
    /// - Throws: 길이·버전·머리 길이가 맞지 않거나 전송 머리가 최소 길이보다 짧으면 `malformed`,
    ///   IPv4 프로토콜 번호나 IPv6 next-header가 255이거나 IPv4 프로토콜 번호가 0이면 `malformed`,
    ///   조각이면 `fragment`, IPv6 확장 헤더면 `extensionHeader`.
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

        // 선언 길이 뒤의 바이트(링크 계층 패딩 등)는 떼어 낸다. 이후의 검사는 모두 잘린 패킷 안에서 한다.
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
            // TCP 머리는 20바이트 이상이고, data offset이 가리키는 머리 끝이 패킷 안에 있어야 한다.
            guard transportLength >= 20 else { throw .malformed }
            let dataOffset = Int(packet[offset + 12] >> 4) * 4
            guard dataOffset >= 20, dataOffset <= transportLength else { throw .malformed }
            sourcePort = Self.uint16(packet, at: offset)
            destinationPort = Self.uint16(packet, at: offset + 2)
            // SYN(0x02)이 켜지고 ACK(0x10)가 꺼진 것. Go `Parsed.IsTCPSyn`.
            isTCPSYN = packet[offset + 13] & 0x12 == 0x02
            transportProtocol = .tcp
        case 17:
            guard transportLength >= 8 else { throw .malformed }
            sourcePort = Self.uint16(packet, at: offset)
            destinationPort = Self.uint16(packet, at: offset + 2)
            transportProtocol = .udp
        case 132:
            // SCTP 공통 머리 12바이트. 포트는 UDP와 같은 자리다.
            guard transportLength >= 12 else { throw .malformed }
            sourcePort = Self.uint16(packet, at: offset)
            destinationPort = Self.uint16(packet, at: offset + 2)
            transportProtocol = .sctp
        case 1 where isIPv4, 58 where !isIPv4:
            // ICMP 머리는 type·code·checksum과 4바이트 나머지로 8바이트다. echo·오류 판별이 이 길이를 쓴다.
            guard transportLength >= 8 else { throw .malformed }
            transportProtocol = isIPv4 ? .icmpv4 : .icmpv6
        case 99:
            transportProtocol = .tsmp
        case 0, 255:
            // Go 파서는 둘을 Unknown으로 바꿔 규칙과 상관없이 버린다. IPv6의 0(hop-by-hop)은 앞에서 걸렀다.
            throw .malformed
        case let number:
            // 다른 계열의 ICMP 번호(IPv4 안의 58 등)도 Go처럼 그 밖의 프로토콜로 본다.
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

    /// ICMP 메시지의 type과 code. ICMP가 아니면 `nil`. 해석할 때 ICMP 머리 8바이트를 확인했다.
    var icmpTypeAndCode: (type: UInt8, code: UInt8)? {
        switch transportProtocol {
        case .icmpv4, .icmpv6: (bytes[transportOffset], bytes[transportOffset + 1])
        default: nil
        }
    }

    /// 머리 길이를 확인한 뒤에만 부른다.
    private static func uint16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    /// IP 머리에서 읽은 값. 만들 때 모든 범위가 버퍼 안에 있음을 확인한다.
    private struct Header {
        let isIPv4: Bool
        /// IP 머리의 길이(IPv4 옵션 포함).
        let length: Int
        /// 선언된 패킷 전체 길이. `length` 이상이고 버퍼 길이 이하다.
        let totalLength: Int
        let protocolNumber: UInt8
        let sourceRange: Range<Int>
        let destinationRange: Range<Int>

        /// IPv4: 20바이트 이상, IHL 5 이상, IHL ≤ 선언 길이 ≤ 버퍼. MF나 오프셋이 있으면 조각이다.
        init(ipv4 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 20 else { throw .malformed }
            let headerLength = Int(bytes[0] & 0x0F) * 4
            let totalLength = Int(IPPacket.uint16(bytes, at: 2))
            guard headerLength >= 20, headerLength <= totalLength, totalLength <= bytes.count else { throw .malformed }
            // 6:2의 MF 비트(0x2000)와 13비트 조각 오프셋. 첫 조각(MF만 켜짐)도 조각이다.
            let flagsAndOffset = IPPacket.uint16(bytes, at: 6)
            guard flagsAndOffset & 0x3FFF == 0 else { throw .fragment }

            isIPv4 = true
            length = headerLength
            self.totalLength = totalLength
            protocolNumber = bytes[9]
            sourceRange = 12..<16
            destinationRange = 16..<20
        }

        /// IPv6: 40바이트 이상, 40 + payload length ≤ 버퍼. next-header 44는 조각, 확장 헤더는 거절한다.
        init(ipv6 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 40 else { throw .malformed }
            let totalLength = 40 + Int(IPPacket.uint16(bytes, at: 4))
            guard totalLength <= bytes.count else { throw .malformed }
            let nextHeader = bytes[6]
            guard nextHeader != 44 else { throw .fragment }
            // hop-by-hop(0), routing(43), ESP(50), AH(51), destination options(60), mobility(135),
            // HIP(139), shim6(140). 체인을 따라가 안쪽 전송 머리를 읽지 않는다.
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
