import SwiftailBase

extension TCPSegment {
    /// Serializes the segment to an IP packet. Writes the TCP checksum and, for IPv4, the IP header checksum.
    ///
    /// - A 20-byte header + options + data. On a segment with SYN set, the order of the options is MSS (4 bytes),
    ///   two NOPs and SACK-Permitted (2 bytes), then one NOP and Window Scale (3 bytes). This is the Linux order followed by gVisor's
    ///   `makeSynOptions`. Segments with SYN clear carry two NOPs and SACK (`2 + 8n` bytes) only if there are SACK
    ///   blocks (as in gVisor's `makeOptions`). Every combination aligns to a 4-byte boundary without padding.
    /// - IPv4 uses IHL 5, DF set, identifier 0, and TTL `hopLimit`. IPv6 uses traffic class and flow label 0, and hop
    ///   limit `hopLimit`. The default of 64 matches Go and gVisor (tunnel contract behavior L2).
    /// - The urgent pointer, CWR, and ECE are 0.
    ///
    /// - Parameter hopLimit: The IPv4 TTL or IPv6 hop limit.
    /// - Returns: The IP packet. Returns `nil` if the source and destination address families differ, more than 4 SACK
    ///   blocks would exceed the TCP option space (40 bytes) on a non-SYN segment, or the encoded length exceeds
    ///   65,535 bytes (total packet length for IPv4, payload length for IPv6). These cases do not occur with segments
    ///   produced by the state machine.
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
        // IPv4 total length includes the header. IPv6 payload length excludes the header.
        guard segmentLength <= Int(UInt16.max) - (isIPv4 ? ipHeaderLength : 0) else { return nil }

        var packet: [UInt8] = []
        packet.reserveCapacity(ipHeaderLength + segmentLength)
        if isIPv4 {
            packet.append(0x45)  // Version 4, IHL 5
            packet.append(0)  // DSCP·ECN
            packet.appendUInt16(UInt16(ipHeaderLength + segmentLength))
            packet.appendUInt16(0)  // Identifier
            packet.appendUInt16(0x4000)  // DF, no fragments
            packet.append(hopLimit)
            packet.append(6)
            packet.appendUInt16(0)  // Header checksum placeholder
        } else {
            packet.append(contentsOf: [0x60, 0, 0, 0])  // Version 6, traffic class 0, flow label 0
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
        packet.appendUInt16(0)  // Checksum placeholder
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
    /// The option length for `blockCount` SACK blocks on a non-SYN segment is two NOPs + `2 + 8n`. Returns 0 if there
    /// are no blocks. This reduces the maximum sendable data by the same amount (RFC 9293 §3.7.1 accounts for the TCP header, including
    /// options, when calculating Eff.snd.MSS).
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

    /// Overwrites two previously filled bytes. The code that constructed the packet knows the space exists.
    fileprivate mutating func replaceUInt16(_ value: UInt16, at offset: Int) {
        self[offset] = UInt8(truncatingIfNeeded: value >> 8)
        self[offset + 1] = UInt8(truncatingIfNeeded: value)
    }
}
