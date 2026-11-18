import SwiftailBase

extension TCPSegment {
    /// Validates IP packet bytes and converts them to a segment. This is the boundary for untrusted input.
    ///
    /// Reads addresses and lengths from IPv4 headers (including options) and IPv6 headers (without extension headers).
    /// Discards bytes after the declared length, such as link-layer padding. Runs the following checks in order and
    /// stops at the first failure.
    ///
    /// 1. Throws `malformed` for an invalid packet length, IP version, or IP header length.
    /// 2. Throws `notTCP` if the protocol (IPv4 protocol or IPv6 next header) is other than 6.
    /// 3. Throws `malformed` for IPv4 fragments (MF set or a nonzero fragment offset). Without reassembly,
    ///    the fragment's TCP header cannot be trusted.
    /// 4. Throws `badChecksum` for an incorrect IPv4 header checksum.
    /// 5. Throws `malformed` if the segment is shorter than 20 bytes or the TCP data offset is below 5 or
    ///    past the end of the segment.
    /// 6. Throws `badChecksum` for an incorrect TCP checksum, including the pseudo-header.
    /// 7. Throws `malformed` for an invalid option length.
    ///
    /// Stops parsing options at EOL and skips NOP. Records MSS (kind 2, length 4), Window Scale (kind 3, length 3), and
    /// SACK-Permitted (kind 4, length 2) only in segments with SYN set, and SACK (kind 5, length `2 + 8n`, n ≥ 1) only
    /// in segments with SYN clear (RFC 2018 §2 sends SACK-Permitted only on SYN). Skips unknown options and any of
    /// these four with lengths that differ from the specification, using their lengths. An option shorter than 2 or
    /// extending beyond the header yields `malformed`. SACK whose blocks exceed the option space (40 bytes, n ≥ 5) also
    /// extends beyond the header and is handled here (the precaution in RFC 9293 §3.2 MUST-7, with the connection kept
    /// open). Reads MSS 0 as 536 for IPv4 and 1220 for IPv6. The RFC does not define a value for 0 (536 and 1220 in RFC
    /// 9293 §3.7.1 apply when the option is **absent**), so contract behavior W2 chose those values. Reads shifts above
    /// 14 as 14 (RFC 7323 §2.3). When an option appears more than once, keeps the last one.
    ///
    /// Ignores the urgent pointer and CWR, ECE, and URG on receipt.
    package init(parsingIPPacket bytes: [UInt8]) throws(ParseError) {
        guard let first = bytes.first else { throw .malformed }
        let ip: IPHeader
        switch first >> 4 {
        case 4: ip = try IPHeader(ipv4: bytes)
        case 6: ip = try IPHeader(ipv6: bytes)
        default: throw .malformed
        }
        guard ip.protocolNumber == 6 else { throw .notTCP }
        if ip.isIPv4 {
            // A fragment is unusable because only the first fragment contains the TCP header and the checksum covers the entire segment.
            guard bytes.uint16(at: 6) & 0x3FFF == 0 else { throw .malformed }
            var headerChecksum = InternetChecksum()
            headerChecksum.add(bytes[..<ip.headerLength])
            // The complemented sum, including the checksum field, must be 0 (RFC 1071 §1).
            guard headerChecksum.value == 0 else { throw .badChecksum }
        }

        let segment = bytes[ip.headerLength..<ip.totalLength]
        guard segment.count >= 20 else { throw .malformed }
        let headerLength = Int(segment.byte(at: 12) >> 4) * 4
        guard headerLength >= 20, headerLength <= segment.count else { throw .malformed }

        let sourceAddress = ip.sourceAddress
        let destinationAddress = ip.destinationAddress
        var checksum = InternetChecksum()
        checksum.addPseudoHeader(
            source: sourceAddress.bytes, destination: destinationAddress.bytes, protocolNumber: 6, length: segment.count)
        checksum.add(segment)
        guard checksum.value == 0 else { throw .badChecksum }

        let flags = Flags(rawValue: segment.byte(at: 13) & 0x1F)
        var maximumSegmentSize: UInt16?
        var windowScale: UInt8?
        var sackPermitted = false
        var sackBlocks: [SACKBlock] = []
        let options = try Options(
            parsing: segment[(segment.startIndex + 20)..<(segment.startIndex + headerLength)])
        if flags.contains(.syn) {
            let defaultMSS: UInt16 = ip.isIPv4 ? 536 : 1220
            maximumSegmentSize = options.maximumSegmentSize.map { $0 == 0 ? defaultMSS : $0 }
            windowScale = options.windowScale.map { min($0, 14) }
            sackPermitted = options.sackPermitted
        } else {
            sackBlocks = options.sackBlocks
        }

        self.init(
            source: IPEndpoint(address: sourceAddress, port: segment.uint16(at: 0)),
            destination: IPEndpoint(address: destinationAddress, port: segment.uint16(at: 2)),
            sequenceNumber: SequenceNumber(segment.uint32(at: 4)),
            acknowledgmentNumber: SequenceNumber(segment.uint32(at: 8)),
            flags: flags,
            window: segment.uint16(at: 14),
            maximumSegmentSize: maximumSegmentSize,
            windowScale: windowScale,
            sackPermitted: sackPermitted,
            sackBlocks: sackBlocks,
            payload: Array(segment[(segment.startIndex + headerLength)...])
        )
    }

    /// A parsed IP header. Validates that all ranges are inside the buffer on creation.
    private struct IPHeader {
        let isIPv4: Bool
        /// The length of the IP header, including IPv4 options. This is where the TCP segment begins.
        let headerLength: Int
        /// The declared total packet length, at least `headerLength` and no greater than the buffer length.
        let totalLength: Int
        let protocolNumber: UInt8
        let sourceAddress: IPAddress
        let destinationAddress: IPAddress

        /// IPv4 requires at least 20 bytes, an IHL of at least 5 words, and `IHL × 4 ≤ declared length ≤ buffer length`.
        init(ipv4 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 20 else { throw .malformed }
            let headerLength = Int(bytes[0] & 0x0F) * 4
            let totalLength = Int(bytes.uint16(at: 2))
            guard headerLength >= 20, headerLength <= totalLength, totalLength <= bytes.count,
                  let source = IPAddress(bytes: bytes[12..<16]),
                  let destination = IPAddress(bytes: bytes[16..<20])
            else { throw .malformed }
            isIPv4 = true
            self.headerLength = headerLength
            self.totalLength = totalLength
            protocolNumber = bytes[9]
            sourceAddress = source
            destinationAddress = destination
        }

        /// IPv6 requires at least 40 bytes and 40 + payload length ≤ buffer. It does not follow extension headers, so a
        /// next header other than 6 is not TCP.
        init(ipv6 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 40 else { throw .malformed }
            let totalLength = 40 + Int(bytes.uint16(at: 4))
            guard totalLength <= bytes.count,
                  let source = IPAddress(bytes: bytes[8..<24]),
                  let destination = IPAddress(bytes: bytes[24..<40])
            else { throw .malformed }
            isIPv4 = false
            headerLength = 40
            self.totalLength = totalLength
            protocolNumber = bytes[6]
            sourceAddress = source
            destinationAddress = destination
        }
    }

    /// Values read from the TCP header's option area (RFC 9293 §3.2).
    private struct Options {
        var maximumSegmentSize: UInt16?
        var windowScale: UInt8?
        var sackPermitted = false
        var sackBlocks: [SACKBlock] = []

        /// Scans the option area once. Each step advances by at least one byte, so the number of iterations cannot exceed the area's length.
        init(parsing region: ArraySlice<UInt8>) throws(ParseError) {
            var index = region.startIndex
            walk: while index < region.endIndex {
                switch region[index] {
                case 0:
                    break walk
                case 1:
                    index += 1
                case let kind:
                    // Other than EOL and NOP, options have a kind, a length including the two header bytes, and a value.
                    guard index + 1 < region.endIndex else { throw .malformed }
                    let length = Int(region[index + 1])
                    guard length >= 2, length <= region.endIndex - index else { throw .malformed }
                    if kind == 2, length == 4 {
                        maximumSegmentSize = UInt16(region[index + 2]) << 8 | UInt16(region[index + 3])
                    } else if kind == 3, length == 3 {
                        windowScale = region[index + 2]
                    } else if kind == 4, length == 2 {
                        sackPermitted = true
                    } else if kind == 5, length > 2, (length - 2) % 8 == 0 {
                        // A block consists of two 32-bit values, its left and right edges. The length was checked above
                        // against the option area.
                        sackBlocks = stride(from: index + 2, to: index + length, by: 8).map { offset in
                            SACKBlock(
                                leftEdge: SequenceNumber(region.uint32(atIndex: offset)),
                                rightEdge: SequenceNumber(region.uint32(atIndex: offset + 4)))
                        }
                    }
                    index += length
                }
            }
        }
    }
}

extension ArraySlice<UInt8> {
    /// The byte `offset` from the start of the slice. Call only after checking the length.
    fileprivate func byte(at offset: Int) -> UInt8 {
        self[startIndex + offset]
    }

    fileprivate func uint16(at offset: Int) -> UInt16 {
        UInt16(byte(at: offset)) << 8 | UInt16(byte(at: offset + 1))
    }

    fileprivate func uint32(at offset: Int) -> UInt32 {
        UInt32(uint16(at: offset)) << 16 | UInt32(uint16(at: offset + 2))
    }

    /// The big-endian 32-bit value starting at the slice's `index`. Call only after checking the length.
    fileprivate func uint32(atIndex index: Int) -> UInt32 {
        uint32(at: index - startIndex)
    }
}

extension [UInt8] {
    /// Call only after checking the length.
    fileprivate func uint16(at offset: Int) -> UInt16 {
        UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }
}
