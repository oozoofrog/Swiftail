// RST seq and ack rules and the window of 0 match the RST gVisor sends for a closed port.
// Origin: gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259 `pkg/tcpip/transport/tcp/protocol.go` (`replyWithReset`),
// RFC 9293 3.10.7.1.
// Copyright 2018 The gVisor Authors. Apache-2.0.

extension ServiceIPReply {
    /// An RST for a TCP segment. The service IP has no TCP stack, so it answers any segment to any port with an RST (decision D4).
    /// Returns `nil` if the request is not TCP or is an RST (RSTs receive no reply, RFC 9293 3.10.7.1).
    ///
    /// The following rules apply to segments arriving on a closed connection (RFC 9293 3.10.7.1).
    /// - If ACK is set, `seq = SEG.ACK` and only RST is set. `ack` is 0.
    /// - Otherwise, `seq = 0`, `ack = SEG.SEQ + SEG.LEN`, and both RST and ACK are set. `SEG.LEN` is the payload byte count
    ///   plus 1 each for SYN and FIN. Overflow past `UInt32` wraps in the sequence number space.
    ///
    /// The header is 20 bytes with no options, a window of 0, and an urgent pointer of 0.
    static func tcpReset(inReplyTo segment: IPPacket) -> [UInt8]? {
        guard segment.transportProtocol == .tcp else { return nil }
        let bytes = segment.bytes
        let offset = segment.transportOffset
        let flags = bytes[offset + 13]
        let reset: UInt8 = 0x04
        let syn: UInt8 = 0x02
        let fin: UInt8 = 0x01
        let ack: UInt8 = 0x10
        guard flags & reset == 0 else { return nil }

        let sequence: UInt32
        let acknowledgement: UInt32
        let replyFlags: UInt8
        if flags & ack != 0 {
            sequence = Self.uint32(bytes, at: offset + 8)
            acknowledgement = 0
            replyFlags = reset
        } else {
            // Parsing verified that the TCP header length (data offset) fits within the packet.
            let headerLength = Int(bytes[offset + 12] >> 4) * 4
            let payloadLength = bytes.count - offset - headerLength
            let flagLength = (flags & syn != 0 ? 1 : 0) + (flags & fin != 0 ? 1 : 0)
            sequence = 0
            acknowledgement = Self.uint32(bytes, at: offset + 4) &+ UInt32(truncatingIfNeeded: payloadLength + flagLength)
            replyFlags = reset | ack
        }

        // Swapped ports, seq, ack, data offset 5, flags, window 0, checksum field, and urgent 0.
        let transport = Self.bytes(segment.destinationPort) + Self.bytes(segment.sourcePort)
            + Self.bytes(sequence) + Self.bytes(acknowledgement)
            + [0x50, replyFlags, 0, 0, 0, 0, 0, 0]
        return reply(to: segment, protocolNumber: 6, transport: transport, checksum: .tcp)
    }

    private static func uint32(_ bytes: [UInt8], at index: Int) -> UInt32 {
        bytes[index..<index + 4].reduce(0) { $0 << 8 | UInt32($1) }
    }

    private static func bytes(_ value: UInt32) -> [UInt8] {
        bytes(UInt16(truncatingIfNeeded: value >> 16)) + bytes(UInt16(truncatingIfNeeded: value))
    }
}
