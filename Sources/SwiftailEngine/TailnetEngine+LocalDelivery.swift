import SwiftailBase

/// The engine handles packets read from the device locally for the service IP, TSMP, and local addresses, without sending them through WireGuard.
///
/// The service IP (`100.100.100.100`, `fd7a:115c:a1e0::53`) belongs to the node itself, with no host outside the tunnel. The MagicDNS responder
/// answers UDP 53, ICMP echo gets an echo reply, and TCP gets an RST. Discards everything else without replying (as in Go).
/// Packets sent to the service IP never emit `.datagram`. Packets sent to a local tailnet address return to the device with the same
/// bytes and without filtering (Network Extension sends packets to the tunnel address through the tunnel without looping them back in the kernel).
///
/// `docs/contracts/SwiftailTunnel.md` behavior L and `docs/protocol-notes/dns-state-node.md` 4.3.
/// Go `net/tstun/wrap.go`(`filterPacketOutboundToWireGuard`), `wgengine/userspace.go`(`handleLocalPackets`).
extension TailnetEngine {
    /// Returns the output for a packet that terminates locally, or `nil` if it goes to a peer.
    ///
    /// The order is service IP → TSMP → local address. Go also discards TSMP before checking local addresses (the contract lists local addresses first,
    /// but TSMP addressed to a local address is never looped back).
    func deliverLocally(_ packet: IPPacket, at now: ContinuousClock.Instant) -> Output? {
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

    /// A reply packet or discard for a packet sent to the service IP.
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

    /// The payload indicated by the UDP header's length field. Returns `nil` if the UDP length is below 8 or extends past the end of the IP packet.
    private func udpPayload(of packet: IPPacket) -> [UInt8]? {
        let start = packet.transportOffset
        let length = Int(packet.bytes[start + 4]) << 8 | Int(packet.bytes[start + 5])
        guard length >= 8, start + length <= packet.bytes.count else { return nil }
        return Array(packet.bytes[(start + 8)..<(start + length)])
    }
}
