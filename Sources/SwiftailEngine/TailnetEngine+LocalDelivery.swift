import SwiftailBase

/// 장치에서 읽은 패킷 가운데 WireGuard로 보내지 않고 엔진이 직접 처리하는 것: 서비스 IP, TSMP, 자기 주소.
///
/// 서비스 IP(`100.100.100.100`, `fd7a:115c:a1e0::53`)는 터널 밖에 있는 호스트가 아니라 노드 자신이다. UDP 53은
/// MagicDNS 응답기가, ICMP echo는 echo reply로, TCP는 RST로 답하고, 그 밖의 것은 응답 없이 버린다(Go와 같다).
/// 서비스 IP로 간 패킷은 어떤 경우에도 `.datagram`을 내지 않는다. 자기 tailnet 주소로 가는 패킷은 필터 없이 같은
/// 바이트로 장치에 되돌린다(Network Extension은 터널 주소로 가는 패킷을 커널에서 되돌리지 않고 터널로 보낸다).
///
/// `docs/contracts/SwiftailTunnel.md` 동작 L, `docs/protocol-notes/dns-state-node.md` 4.3.
/// Go `net/tstun/wrap.go`(`filterPacketOutboundToWireGuard`), `wgengine/userspace.go`(`handleLocalPackets`).
extension TailnetEngine {
    /// 로컬에서 끝나는 패킷이면 그 출력을, 아니면 `nil`(피어로 보낸다).
    ///
    /// 순서는 서비스 IP → TSMP → 자기 주소다. Go도 TSMP를 자기 주소 확인보다 먼저 버린다(계약은 자기 주소를 먼저
    /// 적었지만 자기 주소로 가는 TSMP는 되돌리지 않는다).
    mutating func deliverLocally(_ packet: IPPacket, at now: ContinuousClock.Instant) -> Output? {
        if ServiceIP.contains(packet.destination) {
            return answerServiceIP(packet, at: now)
        }
        if packet.transportProtocol == .tsmp {
            return .dropped(.consumedControlPacket)
        }
        if localAddresses.contains(packet.destination) {
            return .ipPacket(packet.bytes)
        }
        return nil
    }

    /// 서비스 IP로 온 패킷에 대한 응답 패킷 또는 버림.
    private func answerServiceIP(_ packet: IPPacket, at now: ContinuousClock.Instant) -> Output {
        let reply: [UInt8]?
        switch packet.transportProtocol {
        case .udp where packet.destinationPort == Self.dnsPort:
            guard let query = udpPayload(of: packet) else { return .dropped(.serviceIPPacket) }
            reply = ServiceIPReply.udp(payload: resolver.response(to: query, at: wallClock(at: now)), inReplyTo: packet)
        case .icmpv4, .icmpv6:
            reply = ServiceIPReply.icmpEchoReply(inReplyTo: packet)
        case .tcp:
            reply = ServiceIPReply.tcpReset(inReplyTo: packet)
        default:
            reply = nil
        }
        return reply.map(Output.ipPacket) ?? .dropped(.serviceIPPacket)
    }

    private static let dnsPort: UInt16 = 53

    /// UDP 헤더의 길이 필드가 가리키는 payload. 길이 필드가 8보다 작거나 IP 패킷보다 길면 `nil`.
    private func udpPayload(of packet: IPPacket) -> [UInt8]? {
        let start = packet.transportOffset
        let length = Int(packet.bytes[start + 4]) << 8 | Int(packet.bytes[start + 5])
        guard length >= 8, start + length <= packet.bytes.count else { return nil }
        return Array(packet.bytes[(start + 8)..<(start + length)])
    }
}
