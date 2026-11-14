// 응답 머리는 Go 구현을 따라 옮겼다: TTL·hop limit 64, 조각·DF 없음, IP 식별자(IPv6는 flow label)는 요청 값의 비트를
// 뒤집은 것, 주소·포트 맞바꿈, ICMP echo reply의 type·code.
// 출처: tailscale.com v1.104.6 `net/packet/ip4.go` (`Marshal`, `ToResponse`), `net/packet/ip6.go`,
// `net/packet/udp4.go`, `net/packet/icmp4.go`·`icmp6.go` (`ToResponse`), `net/tstun/wrap.go` (echo reply 주입).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 서비스 IP(`100.100.100.100`, `fd7a:115c:a1e0::53`)로 온 패킷에 노드가 직접 답하는 IP 패킷 만들기.
///
/// 입출력이 없는 순수 함수다. 받은 패킷은 이미 `IPPacket`으로 해석한 것이고, 답은 되돌려 보낼 IP 패킷 바이트다.
/// 출발·목적 주소와 포트를 맞바꾸고, IPv4 머리 체크섬과 UDP·TCP·ICMPv6의 의사 머리 체크섬, ICMPv4 체크섬을
/// 정확히 채운다(IPv6의 UDP 체크섬은 필수, RFC 8200 8.1). 응답할 수 없는 입력은 `nil`이다.
///
/// 어떤 패킷에 답할지(서비스 IP인지, UDP 53인지)는 부르는 쪽이 정한다. 여기서는 만들 수 있는지만 본다. 계약 동작 L2가
/// 정한 범위는 UDP 53에 DNS 응답, ICMP echo에 reply, TCP에 RST이고, 나머지는 버린다(응답도 ICMP unreachable도 없다).
///
/// shortcut: 요청의 IPv4 옵션·IPv6 traffic class는 답에 옮기지 않는다(Go도 옮기지 않는다). 요청의 체크섬은 검사하지
/// 않는다(`IPPacket`이 검사하지 않고, 필터 앞의 Go 래퍼도 검사하지 않는다).
///
/// `docs/contracts/SwiftailTunnel.md` 동작 L2, `docs/protocol-notes/dns-state-node.md` 4.3.
enum ServiceIPReply {
    /// 응답 IP 패킷의 TTL·hop limit. Go `net/packet/ip4.go`, `ip6.go`와 같다.
    static let hopLimit: UInt8 = 64

    /// 요청 UDP 데이터그램에 `payload`를 실어 되돌리는 UDP 패킷. 요청이 UDP가 아니거나 패킷 하나에 들어가지 않으면 `nil`.
    ///
    /// UDP 체크섬은 IPv4·IPv6 모두 계산한다. 계산 결과가 0이면 0xFFFF로 쓴다("체크섬 없음"과 구별, RFC 768).
    static func udp(payload: [UInt8], inReplyTo datagram: IPPacket) -> [UInt8]? {
        guard datagram.transportProtocol == .udp else { return nil }
        let length = 8 + payload.count
        guard length <= Int(UInt16.max) else { return nil }
        // 체크섬 자리(6~7)는 0으로 두고 `reply`가 채운다.
        let transport = Self.bytes(datagram.destinationPort) + Self.bytes(datagram.sourcePort)
            + Self.bytes(UInt16(length)) + [0, 0] + payload
        return reply(to: datagram, protocolNumber: 17, transport: transport, checksum: .udp)
    }

    /// ICMP echo request에 대한 echo reply. identifier·sequence·payload를 그대로 돌려준다.
    /// ICMPv4 type 8, ICMPv6 type 128이고 code가 0인 요청만 받는다(Go `Parsed.IsEchoRequest`). 아니면 `nil`.
    static func icmpEchoReply(inReplyTo request: IPPacket) -> [UInt8]? {
        guard let (type, code) = request.icmpTypeAndCode, code == 0 else { return nil }
        let isIPv4 = request.transportProtocol == .icmpv4
        guard type == (isIPv4 ? 8 : 128) else { return nil }
        // 머리 4바이트(type, code, checksum) 뒤의 identifier·sequence·payload를 옮긴다. 해석 단계가 8바이트를 확인했다.
        let rest = request.bytes[(request.transportOffset + 4)...]
        let transport: [UInt8] = [isIPv4 ? 0 : 129, 0, 0, 0] + rest
        return reply(to: request, protocolNumber: isIPv4 ? 1 : 58, transport: transport, checksum: isIPv4 ? .icmpv4 : .icmpv6)
    }

    // MARK: - IP 계층

    /// 전송 계층 조각(체크섬 자리는 0)에 체크섬을 채우고 IP 머리를 붙인다. 패킷 하나에 들어가지 않으면 `nil`.
    /// `ServiceIPReply+TCPReset.swift`가 같은 길로 RST를 낸다.
    static func reply(to request: IPPacket, protocolNumber: UInt8, transport: [UInt8], checksum: TransportChecksum) -> [UInt8]? {
        let isIPv4 = request.source.isIPv4
        guard transport.count <= Int(UInt16.max) - (isIPv4 ? 20 : 0) else { return nil }
        // 응답의 출발지는 요청의 목적지다.
        let source = request.destination.bytes
        let destination = request.source.bytes

        var transport = transport
        let sum = checksum.compute(
            over: transport, source: source, destination: destination, protocolNumber: protocolNumber)
        transport.replaceSubrange(checksum.offset..<checksum.offset + 2, with: Self.bytes(sum))

        let header: [UInt8]
        if isIPv4 {
            // 식별자: 요청과 구별되게 비트를 뒤집는다(Go `IP4Header.ToResponse`). 플래그·조각 오프셋은 0이다.
            let identification = ~(UInt16(request.bytes[4]) << 8 | UInt16(request.bytes[5]))
            var ipv4: [UInt8] = [0x45, 0] + Self.bytes(UInt16(20 + transport.count)) + Self.bytes(identification)
                + [0, 0, hopLimit, protocolNumber, 0, 0] + source + destination
            ipv4.replaceSubrange(10..<12, with: Self.bytes(TransportChecksum.internetChecksum(of: ipv4)))
            header = ipv4
        } else {
            // flow label 20비트를 뒤집는다(Go `IP6Header.ToResponse`). traffic class는 0이다.
            let flow = ~(UInt32(request.bytes[1] & 0x0F) << 16 | UInt32(request.bytes[2]) << 8 | UInt32(request.bytes[3])) & 0xF_FFFF
            header = [0x60, UInt8(flow >> 16), UInt8(truncatingIfNeeded: flow >> 8), UInt8(truncatingIfNeeded: flow)]
                + Self.bytes(UInt16(transport.count)) + [protocolNumber, hopLimit] + source + destination
        }
        return header + transport
    }

    /// 네트워크 바이트 순서(빅엔디언) 두 바이트.
    static func bytes(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }
}
