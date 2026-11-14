// RST의 seq·ack 규칙과 창 0은 gVisor가 닫힌 포트에 보내는 RST와 같다.
// 출처: gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259 `pkg/tcpip/transport/tcp/protocol.go` (`replyWithReset`),
// RFC 9293 3.10.7.1.
// Copyright 2018 The gVisor Authors. Apache-2.0.

extension ServiceIPReply {
    /// TCP 세그먼트에 대한 RST. 서비스 IP에는 TCP 스택이 없으므로 어떤 포트의 어떤 세그먼트에도 RST로 답한다(결정 D4).
    /// 요청이 TCP가 아니거나 RST면 `nil`이다(RST에는 답하지 않는다, RFC 9293 3.10.7.1).
    ///
    /// 닫힌 연결에 오는 세그먼트에 대한 규칙(RFC 9293 3.10.7.1):
    /// - ACK가 켜져 있으면 `seq = SEG.ACK`이고 RST만 켠다. `ack`는 0이다.
    /// - 아니면 `seq = 0`, `ack = SEG.SEQ + SEG.LEN`이고 RST와 ACK를 켠다. `SEG.LEN`은 payload 바이트 수에
    ///   SYN과 FIN을 1씩 더한 것이다. `UInt32`를 넘치면 순환한다(시퀀스 번호 공간).
    ///
    /// 머리는 옵션 없는 20바이트이고, 창은 0, urgent 포인터는 0이다.
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
            // 해석 단계가 TCP 머리 길이(data offset)를 패킷 안에서 확인했다.
            let headerLength = Int(bytes[offset + 12] >> 4) * 4
            let payloadLength = bytes.count - offset - headerLength
            let flagLength = (flags & syn != 0 ? 1 : 0) + (flags & fin != 0 ? 1 : 0)
            sequence = 0
            acknowledgement = Self.uint32(bytes, at: offset + 4) &+ UInt32(truncatingIfNeeded: payloadLength + flagLength)
            replyFlags = reset | ack
        }

        // 포트 맞바꿈, seq, ack, data offset 5, 플래그, 창 0, 체크섬 자리, urgent 0.
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
