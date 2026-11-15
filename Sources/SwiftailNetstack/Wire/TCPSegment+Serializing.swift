import SwiftailBase

extension TCPSegment {
    /// 세그먼트를 IP 패킷 바이트로 만든다. 두 체크섬(IPv4 머리, TCP)을 채운다.
    ///
    /// - 머리 20바이트 + 옵션 + 데이터. SYN이 켜진 세그먼트에는 MSS(4바이트), NOP 둘과 SACK-Permitted(2바이트), NOP와
    ///   Window Scale(3바이트)를 이 순서로 싣는다(gVisor `makeSynOptions`가 따르는 Linux의 순서). SYN이 꺼진 세그먼트에는
    ///   SACK 블록이 있을 때만 NOP 둘과 SACK(`2 + 8n`바이트)을 싣는다(gVisor `makeOptions`와 같다). 어느 조합이든 4바이트
    ///   경계에 맞아 채움이 필요 없다.
    /// - IPv4는 IHL 5, DF 켬, 식별자 0, TTL `hopLimit`. IPv6는 traffic class와 flow label 0, hop limit `hopLimit`.
    ///   기본값 64는 Go·gVisor와 같다(터널 계약 동작 L2).
    /// - urgent pointer와 CWR·ECE는 0이다.
    ///
    /// - Parameter hopLimit: IPv4 TTL 또는 IPv6 hop limit.
    /// - Returns: IP 패킷. 출발·목적 주소의 계열이 다르거나, SACK 블록이 4개를 넘어 옵션이 TCP 머리(40바이트)에 들어가지
    ///   않거나, IP 패킷 하나(65,535바이트)에 들어가지 않으면 `nil`. 상태 기계가 만드는 세그먼트에서는 일어나지 않는다.
    package func ipPacket(hopLimit: UInt8 = 64) -> [UInt8]? {
        let isIPv4 = source.address.isIPv4
        guard destination.address.isIPv4 == isIPv4 else { return nil }

        let isSynchronize = flags.contains(.syn)
        guard isSynchronize || sackBlocks.count <= Self.maximumSACKBlockCount else { return nil }
        let optionsLength = isSynchronize
            ? (maximumSegmentSize == nil ? 0 : 4) + (sackPermitted ? 4 : 0) + (windowScale == nil ? 0 : 4)
            : Self.sackOptionLength(blockCount: sackBlocks.count)
        let segmentLength = 20 + optionsLength + payload.count
        let ipHeaderLength = isIPv4 ? 20 : 40
        // IPv4의 total length는 머리를 포함하고, IPv6의 payload length는 머리를 포함하지 않는다.
        guard segmentLength <= Int(UInt16.max) - (isIPv4 ? ipHeaderLength : 0) else { return nil }

        var packet: [UInt8] = []
        packet.reserveCapacity(ipHeaderLength + segmentLength)
        if isIPv4 {
            packet.append(0x45)  // 버전 4, IHL 5
            packet.append(0)  // DSCP·ECN
            packet.appendUInt16(UInt16(ipHeaderLength + segmentLength))
            packet.appendUInt16(0)  // 식별자
            packet.appendUInt16(0x4000)  // DF, 조각 없음
            packet.append(hopLimit)
            packet.append(6)
            packet.appendUInt16(0)  // 머리 체크섬 자리
        } else {
            packet.append(contentsOf: [0x60, 0, 0, 0])  // 버전 6, traffic class 0, flow label 0
            packet.appendUInt16(UInt16(segmentLength))
            packet.append(6)
            packet.append(hopLimit)
        }
        packet.append(contentsOf: source.address.bytes)
        packet.append(contentsOf: destination.address.bytes)

        packet.appendUInt16(source.port)
        packet.appendUInt16(destination.port)
        packet.appendUInt32(sequenceNumber.rawValue)
        packet.appendUInt32(acknowledgmentNumber.rawValue)
        packet.append(UInt8((20 + optionsLength) / 4) << 4)
        packet.append(flags.rawValue)
        packet.appendUInt16(window)
        packet.appendUInt16(0)  // 체크섬 자리
        packet.appendUInt16(0)  // urgent pointer
        if isSynchronize {
            if let maximumSegmentSize {
                packet.append(contentsOf: [2, 4])
                packet.appendUInt16(maximumSegmentSize)
            }
            if sackPermitted {
                packet.append(contentsOf: [1, 1, 4, 2])
            }
            if let windowScale {
                packet.append(contentsOf: [1, 3, 3, windowScale])
            }
        } else if !sackBlocks.isEmpty {
            packet.append(contentsOf: [1, 1, 5, UInt8(2 + 8 * sackBlocks.count)])
            for block in sackBlocks {
                packet.appendUInt32(block.leftEdge.rawValue)
                packet.appendUInt32(block.rightEdge.rawValue)
            }
        }
        packet.append(contentsOf: payload)

        var checksum = InternetChecksum()
        checksum.addPseudoHeader(
            source: source.address.bytes, destination: destination.address.bytes, protocolNumber: 6, length: segmentLength)
        checksum.add(packet[ipHeaderLength...])
        packet.replaceUInt16(checksum.value, at: ipHeaderLength + 16)
        if isIPv4 {
            var headerChecksum = InternetChecksum()
            headerChecksum.add(packet[..<ipHeaderLength])
            packet.replaceUInt16(headerChecksum.value, at: 10)
        }
        return packet
    }
}

extension TCPSegment {
    /// SYN이 아닌 세그먼트에 SACK 블록 `blockCount`개를 실을 때의 옵션 길이: NOP 둘 + `2 + 8n`. 블록이 없으면 0.
    /// 보내는 데이터의 상한은 이만큼 줄어든다(RFC 9293 3.7.1: Eff.snd.MSS는 옵션을 포함한 TCP 머리를 뺀 값이다).
    package static func sackOptionLength(blockCount: Int) -> Int {
        blockCount == 0 ? 0 : 4 + 8 * blockCount
    }
}

extension [UInt8] {
    fileprivate mutating func appendUInt16(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    fileprivate mutating func appendUInt32(_ value: UInt32) {
        appendUInt16(UInt16(truncatingIfNeeded: value >> 16))
        appendUInt16(UInt16(truncatingIfNeeded: value))
    }

    /// 이미 채운 두 바이트를 덮어쓴다. 자리가 있음을 만든 쪽이 안다.
    fileprivate mutating func replaceUInt16(_ value: UInt16, at offset: Int) {
        self[offset] = UInt8(truncatingIfNeeded: value >> 8)
        self[offset + 1] = UInt8(truncatingIfNeeded: value)
    }
}
