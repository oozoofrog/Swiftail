import SwiftailBase

/// 응답 패킷의 인터넷 체크섬(RFC 1071). IPv4 머리, UDP·TCP·ICMPv6(의사 머리 포함), ICMPv4가 같은 합을 쓴다.
///
/// 합과 의사 머리 계산은 `SwiftailBase`의 `InternetChecksum`이 한다(netstack과 같은 계산을 쓴다).
///
/// 프로토콜마다 다른 것은 체크섬 필드의 위치, 의사 머리를 합에 넣는지, 계산 결과 0을 어떻게 쓰는지뿐이다. 필드의
/// 값은 계산 전에 0이어야 한다.
///
/// RFC 1071(합), RFC 768(UDP, 의사 머리 IPv4), RFC 9293 3.1(TCP), RFC 8200 8.1(IPv6 의사 머리), RFC 4443 2.3(ICMPv6),
/// RFC 792(ICMPv4).
struct TransportChecksum: Sendable {
    /// 전송 계층 조각 안의 체크섬 필드 위치.
    let offset: Int
    /// 합에 IP 의사 머리를 넣는다. ICMPv4만 넣지 않는다.
    let usesPseudoHeader: Bool
    /// 계산 결과가 0이면 0xFFFF로 쓴다. UDP에서 0은 "체크섬 없음"이라서다.
    let zeroBecomesAllOnes: Bool

    static let udp = TransportChecksum(offset: 6, usesPseudoHeader: true, zeroBecomesAllOnes: true)
    static let tcp = TransportChecksum(offset: 16, usesPseudoHeader: true, zeroBecomesAllOnes: false)
    static let icmpv4 = TransportChecksum(offset: 2, usesPseudoHeader: false, zeroBecomesAllOnes: false)
    static let icmpv6 = TransportChecksum(offset: 2, usesPseudoHeader: true, zeroBecomesAllOnes: false)

    /// 체크섬 필드가 0인 전송 계층 조각 `transport`의 체크섬.
    ///
    /// - Parameters:
    ///   - source: 응답 패킷의 출발 주소(4 또는 16바이트).
    ///   - destination: 응답 패킷의 목적 주소. `source`와 같은 길이다.
    ///   - protocolNumber: IPv4 protocol 또는 IPv6 next header.
    func compute(over transport: [UInt8], source: [UInt8], destination: [UInt8], protocolNumber: UInt8) -> UInt16 {
        var checksum = InternetChecksum()
        if usesPseudoHeader {
            checksum.addPseudoHeader(
                source: source, destination: destination, protocolNumber: protocolNumber, length: transport.count)
        }
        checksum.add(transport)
        let sum = checksum.value
        return sum == 0 && zeroBecomesAllOnes ? 0xFFFF : sum
    }

    /// 바이트 하나의 인터넷 체크섬. 합 계산은 `SwiftailBase`의 `InternetChecksum`이다.
    static func internetChecksum(of bytes: [UInt8]) -> UInt16 {
        InternetChecksum.checksum(of: bytes)
    }
}
