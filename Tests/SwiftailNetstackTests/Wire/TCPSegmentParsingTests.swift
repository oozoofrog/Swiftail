import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// Segment parsing (behaviors W 1·2·4, X1). `RawPacket` builds input bytes independently of the implementation.
@Suite("TCP segment parsing")
struct TCPSegmentParsingTests {
    private func parse(_ bytes: [UInt8]) throws(TCPSegment.ParseError) -> TCPSegment {
        try TCPSegment(parsingIPPacket: bytes)
    }

    private func parseError(_ bytes: [UInt8]) -> TCPSegment.ParseError? {
        do {
            _ = try TCPSegment(parsingIPPacket: bytes)
            return nil
        } catch {
            return error
        }
    }

    // MARK: - Valid inputs

    @Test("IPv4 SYN: addresses, ports, numbers, flags, window, MSS, and Window Scale")
    func ipv4SYN() throws {
        let segment = RawPacket.segment(
            sourcePort: 51_000, destinationPort: 443, sequence: 0xFFFF_FFF0, acknowledgment: 0,
            flags: 0x02, window: 65_535, options: [2, 4, 0x04, 0xD8, 1, 3, 3, 7])
        let parsed = try parse(RawPacket.ipv4(segment: segment))
        #expect(parsed.source == WireHosts.endpoint(WireHosts.v4a, 51_000))
        #expect(parsed.destination == WireHosts.endpoint(WireHosts.v4b, 443))
        #expect(parsed.sequenceNumber == SequenceNumber(0xFFFF_FFF0))
        #expect(parsed.acknowledgmentNumber == SequenceNumber(0))
        #expect(parsed.flags == [.syn])
        #expect(parsed.window == 65_535)
        #expect(parsed.maximumSegmentSize == 1240)
        #expect(parsed.windowScale == 7)
        #expect(parsed.payload.isEmpty)
        #expect(parsed.sequenceLength == 1)
    }

    @Test("IPv6 data segment")
    func ipv6Data() throws {
        let payload = Array("hello".utf8)
        let segment = RawPacket.segment(
            sequence: 100, acknowledgment: 200, flags: 0x18, window: 512, payload: payload)
        let parsed = try parse(RawPacket.ipv6(segment: segment))
        #expect(parsed.source == WireHosts.endpoint(WireHosts.v6a, 40_000))
        #expect(parsed.destination == WireHosts.endpoint(WireHosts.v6b, 443))
        #expect(parsed.sequenceNumber == SequenceNumber(100))
        #expect(parsed.acknowledgmentNumber == SequenceNumber(200))
        #expect(parsed.flags == [.ack, .psh])
        #expect(parsed.window == 512)
        #expect(parsed.maximumSegmentSize == nil)
        #expect(parsed.windowScale == nil)
        #expect(parsed.payload == payload)
        #expect(parsed.sequenceLength == 5)
    }

    @Test("Packets with IPv4 options (IHL 6, 8)")
    func ipv4Options() throws {
        let segment = RawPacket.segment(flags: 0x10, payload: [1, 2, 3])
        for ipOptions in [[UInt8](repeating: 1, count: 4), [UInt8](repeating: 1, count: 12)] {
            let parsed = try parse(RawPacket.ipv4(segment: segment, ipOptions: ipOptions))
            #expect(parsed.payload == [1, 2, 3], "\(ipOptions.count) bytes of IP options")
            #expect(parsed.source.port == 40_000)
        }
        // Maximum header with IHL 15 (60 bytes).
        let maximum = try parse(RawPacket.ipv4(segment: segment, ipOptions: [UInt8](repeating: 0, count: 40)))
        #expect(maximum.payload == [1, 2, 3])
    }

    @Test("Discards bytes after the declared length (link-layer padding)")
    func trailingPaddingIgnored() throws {
        let segment = RawPacket.segment(payload: [9, 8, 7])
        for packet in [RawPacket.ipv4(segment: segment), RawPacket.ipv6(segment: segment)] {
            let exact = try parse(packet)
            let padded = try parse(packet + [0xAA, 0xBB, 0xCC])
            #expect(padded == exact)
            #expect(padded.payload == [9, 8, 7])
        }
    }

    @Test("Checksum for odd-length data")
    func oddLengthPayload() throws {
        for count in [1, 3, 1239] {
            let payload = [UInt8](repeating: 0xA5, count: count)
            let segment = RawPacket.segment(payload: payload)
            #expect(try parse(RawPacket.ipv4(segment: segment)).payload == payload)
            #expect(try parse(RawPacket.ipv6(segment: segment)).payload == payload)
        }
    }

    @Test("Acknowledgment and sequence numbers retain values at the 2³² boundary")
    func sequenceNumbersAtTheEdge() throws {
        let segment = RawPacket.segment(sequence: 0xFFFF_FFFF, acknowledgment: 0x8000_0000, flags: 0x11)
        let parsed = try parse(RawPacket.ipv4(segment: segment))
        #expect(parsed.sequenceNumber == SequenceNumber(0xFFFF_FFFF))
        #expect(parsed.acknowledgmentNumber == SequenceNumber(0x8000_0000))
        #expect(parsed.flags == [.fin, .ack])
        #expect(parsed.sequenceLength == 1)
    }

    @Test("Ignores URG, CWR, ECE, and the urgent pointer")
    func ignoredFields() throws {
        let segment = RawPacket.segment(flags: 0xF0 | 0x08, urgent: 0xBEEF)
        let parsed = try parse(RawPacket.ipv4(segment: segment))
        #expect(parsed.flags == [.ack, .psh])
    }

    // MARK: - Truncation and header length

    @Test("Fails to parse regardless of where truncation occurs", arguments: [4, 6])
    func truncated(version: Int) throws {
        let segment = RawPacket.segment(flags: 0x02, options: [2, 4, 0x04, 0xD8], payload: [1, 2, 3, 4, 5])
        let packet = version == 4 ? RawPacket.ipv4(segment: segment) : RawPacket.ipv6(segment: segment)
        _ = try parse(packet)
        for length in 0..<packet.count {
            let error = parseError(Array(packet[..<length]))
            #expect(error == .malformed, "Length \(length)")
        }
    }

    @Test("Invalid IP header: version, IHL 4, IHL beyond the declared length, and declared length beyond the buffer")
    func badIPHeader() {
        let segment = RawPacket.segment()
        let good = RawPacket.ipv4(segment: segment)
        #expect(parseError([]) == .malformed)
        #expect(parseError([UInt8](repeating: 0, count: 40)) == .malformed)  // Version 0
        var version5 = good
        version5[0] = 0x55
        #expect(parseError(version5) == .malformed)
        var ihl4 = good
        ihl4[0] = 0x44
        #expect(parseError(ihl4) == .malformed)
        var ihlBeyond = good
        ihlBeyond[0] = 0x4F  // The header is 60 bytes, but the declared length is 40
        ihlBeyond[2] = 0
        ihlBeyond[3] = 40
        #expect(parseError(ihlBeyond) == .malformed)
        var tooLong = good
        tooLong[3] &+= 1  // The declared length is 1 greater than the actual length
        #expect(parseError(tooLong) == .malformed)
        // IPv6: payload length exceeds the buffer.
        var v6 = RawPacket.ipv6(segment: segment)
        v6[5] &+= 1
        #expect(parseError(v6) == .malformed)
    }

    @Test("Does not parse IPv4 fragments (MF, fragment offset)")
    func fragments() {
        let segment = RawPacket.segment()
        for flagsAndOffset: UInt16 in [0x2000, 0x0001, 0x2001, 0x1FFF] {
            let packet = RawPacket.ipv4(segment: segment, flagsAndOffset: flagsAndOffset)
            #expect(parseError(packet) == .malformed, "Flags and offset \(flagsAndOffset)")
        }
        // DF and the reserved bit do not indicate fragmentation.
        #expect(parseError(RawPacket.ipv4(segment: segment, flagsAndOffset: 0x4000)) == nil)
    }

    @Test("TCP header shorter than 20 bytes")
    func shortTCPHeader() {
        for length in [0, 1, 12, 19] {
            let segment = Array(RawPacket.segment()[..<length])
            // Set the IPv4 header checksum correctly because it is checked before the TCP header. The TCP checksum is not filled for segments shorter than 20 bytes.
            #expect(parseError(RawPacket.ipv4(segment: segment)) == .malformed, "Length \(length)")
            #expect(parseError(RawPacket.ipv6(segment: segment)) == .malformed, "Length \(length)")
        }
    }

    @Test("data offset ranges from 5 through 15 and is rejected if it points beyond the segment")
    func dataOffsetBoundaries() throws {
        // 4 is below the minimum header length (20).
        let offset4 = RawPacket.segment(dataOffset: 4, payload: [1, 2, 3, 4])
        #expect(parseError(RawPacket.ipv4(segment: offset4)) == .malformed)
        // 5: no options.
        #expect(try parse(RawPacket.ipv4(segment: RawPacket.segment(dataOffset: 5, payload: [1]))).payload == [1])
        // 15: all 40 bytes of option space are filled. Data comes after them.
        let options = [UInt8](repeating: 1, count: 40)  // 40 NOPs
        let offset15 = RawPacket.segment(options: options, payload: [7, 7])
        #expect(try parse(RawPacket.ipv4(segment: offset15)).payload == [7, 7])
        // Beyond the header: the segment is 23 bytes but data offset is 15 (60 bytes). At 4 bits it cannot represent 16.
        let beyond = RawPacket.segment(dataOffset: 15, payload: [1, 2, 3])
        #expect(parseError(RawPacket.ipv4(segment: beyond)) == .malformed)
        // A header ending exactly at the end of the segment (0 bytes of data) is valid.
        let exact = RawPacket.segment(options: [UInt8](repeating: 1, count: 8))
        #expect(try parse(RawPacket.ipv6(segment: exact)).payload.isEmpty)
        // One byte short.
        let short = Array(RawPacket.segment(options: [UInt8](repeating: 1, count: 8)).dropLast(4))
        #expect(parseError(RawPacket.ipv6(segment: short)) == .malformed)
    }

    // MARK: - Protocol

    @Test("Non-TCP yields notTCP: UDP, ICMP, IPv6 extension and fragment headers, and unknown numbers")
    func notTCP() {
        let segment = RawPacket.segment()
        for number: UInt8 in [1, 17, 58, 99, 132, 255] {
            #expect(parseError(RawPacket.ipv4(segment: segment, protocolNumber: number)) == .notTCP, "IPv4 \(number)")
            #expect(parseError(RawPacket.ipv6(segment: segment, nextHeader: number)) == .notTCP, "IPv6 \(number)")
        }
        // Does not follow the chain of extension headers (0 hop-by-hop, 43 routing, 44 fragment, 60 destination options).
        for number: UInt8 in [0, 43, 44, 60] {
            #expect(parseError(RawPacket.ipv6(segment: segment, nextHeader: number)) == .notTCP, "IPv6 \(number)")
        }
        // Protocol is checked first even without a TCP header (a UDP packet with no checksum filled in).
        #expect(parseError(RawPacket.ipv4(segment: [1, 2, 3], protocolNumber: 17, fixChecksums: false)) == .notTCP)
    }

    // MARK: - Checksum

    @Test("A wrong TCP checksum yields badChecksum: data, header, checksum field, and pseudo-header address")
    func badTCPChecksum() {
        for version in [4, 6] {
            let packet = version == 4
                ? RawPacket.ipv4(segment: RawPacket.segment(payload: [1, 2, 3]))
                : RawPacket.ipv6(segment: RawPacket.segment(payload: [1, 2, 3]))
            let ipLength = version == 4 ? 20 : 40
            #expect(parseError(packet) == nil)
            for (name, index) in [("Data", packet.count - 1), ("Sequence", ipLength + 4), ("Checksum", ipLength + 17), ("Window", ipLength + 14)] {
                var changed = packet
                changed[index] ^= 0x01
                #expect(parseError(changed) == .badChecksum, "IPv\(version) \(name)")
            }
            // Changing an address invalidates the checksum through the pseudo-header (IPv4 also gets a wrong header checksum, so both yield badChecksum).
            var address = packet
            address[version == 4 ? 15 : 23] ^= 0x01
            #expect(parseError(address) == .badChecksum, "IPv\(version) address")
        }
    }

    @Test("IPv4: Even with a correct header checksum, a TCP checksum calculated with a different address yields badChecksum (pseudo-header)")
    func pseudoHeaderCoversTheAddresses() {
        var packet = RawPacket.ipv4(segment: RawPacket.segment(payload: [1, 2, 3]))
        #expect(parseError(packet) == nil)
        // Change the destination address and recompute only the IPv4 header checksum.
        packet.replaceSubrange(16..<20, with: [100, 64, 0, 3])
        packet.replaceSubrange(10..<12, with: [0, 0])
        packet.replaceSubrange(10..<12, with: RawPacket.be16(Int(RawPacket.checksum(Array(packet[..<20])))))
        #expect(parseError(packet) == .badChecksum)
    }

    @Test("A wrong IPv4 header checksum yields badChecksum")
    func badIPv4HeaderChecksum() {
        var packet = RawPacket.ipv4(segment: RawPacket.segment())
        packet[10] ^= 0x80
        #expect(parseError(packet) == .badChecksum)
        // Changing TTL also invalidates the header checksum. The TCP checksum does not include TTL.
        var ttl = RawPacket.ipv4(segment: RawPacket.segment())
        ttl[8] &-= 1
        #expect(parseError(ttl) == .badChecksum)
    }

    @Test("Rejects a TCP segment with a checksum field of 0")
    func zeroChecksumRejected() {
        let segment = RawPacket.segment(payload: [1, 2, 3])
        // 20-byte IPv4 header + offset of the TCP checksum field (16).
        #expect(parseError(RawPacket.ipv4(segment: segment).zeroing(at: 36, count: 2)) == .badChecksum)
    }

    // MARK: - Options

    private func synPacket(options: [UInt8], flags: UInt8 = 0x02, ipv6: Bool = false) -> [UInt8] {
        let segment = RawPacket.segment(flags: flags, options: options)
        return ipv6 ? RawPacket.ipv6(segment: segment) : RawPacket.ipv4(segment: segment)
    }

    @Test("MSS and Window Scale with misalignment from NOPs")
    func mssAndWindowScaleWithNOPs() throws {
        let layouts: [[UInt8]] = [
            [2, 4, 0x05, 0xB4, 1, 3, 3, 8],  // MSS, NOP, WS
            [1, 3, 3, 2, 2, 4, 0x02, 0x18],  // NOP, WS, MSS
            [1, 1, 1, 2, 4, 0x05, 0xB4, 1, 1, 3, 3, 5],  // Several NOPs cause misalignment
            [3, 3, 9, 2, 4, 0x05, 0xB4],  // WS first, no alignment (EOL padding at the end)
        ]
        let expected: [(UInt16, UInt8)] = [(1460, 8), (536, 2), (1460, 5), (1460, 9)]
        for (options, (mss, shift)) in zip(layouts, expected) {
            let parsed = try parse(synPacket(options: options))
            #expect(parsed.maximumSegmentSize == mss, "\(options)")
            #expect(parsed.windowScale == shift, "\(options)")
        }
    }

    @Test("Stops at EOL without reading later bytes, even if they are invalid options")
    func endOfOptionList() throws {
        // MSS, EOL, and an "option" of length 0 followed by Window Scale.
        let parsed = try parse(synPacket(options: [2, 4, 0x05, 0xB4, 0, 9, 0, 3, 3, 7]))
        #expect(parsed.maximumSegmentSize == 1460)
        #expect(parsed.windowScale == nil)
        // The option area starts with EOL.
        let first = try parse(synPacket(options: [0, 2, 4, 0x05, 0xB4]))
        #expect(first.maximumSegmentSize == nil)
    }

    @Test("Skips unknown options by length")
    func unknownOptionsSkipped() throws {
        // SACK-permitted (4, 2), timestamp (8, 10), unknown kind 77 (length 5), then MSS.
        let options: [UInt8] = [4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 77, 5, 9, 9, 9, 2, 4, 0x05, 0x00]
        let parsed = try parse(synPacket(options: options))
        #expect(parsed.maximumSegmentSize == 1280)
        #expect(parsed.windowScale == nil)
    }

    @Test("Invalid option length yields malformed: 0, 1, past the header, and missing length byte")
    func malformedOptions() {
        let cases: [(name: String, options: [UInt8])] = [
            ("Length 0", [77, 0, 1, 1]),
            ("Length 1", [77, 1, 1, 1]),
            ("MSS with length 0", [2, 0, 0, 0]),
            ("Length beyond the header", [77, 8, 0, 0]),
            ("MSS extends past the end of the header", [1, 1, 2, 4]),
            ("Window Scale extends past the end of the header", [1, 1, 1, 1, 1, 1, 3, 3]),
            ("The last byte is kind, so there is no length byte", [1, 1, 1, 77]),
        ]
        for (name, options) in cases {
            #expect(parseError(synPacket(options: options)) == .malformed, "\(name)")
            #expect(parseError(synPacket(options: options, ipv6: true)) == .malformed, "IPv6 \(name)")
        }
    }

    @Test("Ignores MSS and Window Scale on non-SYN segments but still checks their lengths")
    func optionsIgnoredWithoutSYN() throws {
        for flags: UInt8 in [0x10, 0x18, 0x01, 0x04, 0x14, 0x11] {
            let parsed = try parse(synPacket(options: [2, 4, 0x05, 0xB4, 1, 3, 3, 7], flags: flags))
            #expect(parsed.maximumSegmentSize == nil, "Flags \(flags)")
            #expect(parsed.windowScale == nil, "Flags \(flags)")
        }
        #expect(parseError(synPacket(options: [77, 1, 0, 0], flags: 0x10)) == .malformed)
        // SYN-ACK is a SYN.
        let synAck = try parse(synPacket(options: [2, 4, 0x05, 0xB4, 1, 3, 3, 7], flags: 0x12))
        #expect(synAck.maximumSegmentSize == 1460)
        #expect(synAck.windowScale == 7)
    }

    @Test("MSS 0 uses the default (IPv4 536, IPv6 1220). Keeps other values unchanged (including 1 and 65535)")
    func mssZeroAndExtremes() throws {
        #expect(try parse(synPacket(options: [2, 4, 0, 0])).maximumSegmentSize == 536)
        #expect(try parse(synPacket(options: [2, 4, 0, 0], ipv6: true)).maximumSegmentSize == 1220)
        #expect(try parse(synPacket(options: [2, 4, 0, 1])).maximumSegmentSize == 1)
        #expect(try parse(synPacket(options: [2, 4, 0xFF, 0xFF], ipv6: true)).maximumSegmentSize == 65_535)
    }

    @Test("Window Scale shift is capped at 14")
    func windowScaleClamped() throws {
        let expected: [(UInt8, UInt8)] = [(0, 0), (1, 1), (14, 14), (15, 14), (255, 14)]
        for (given, shift) in expected {
            #expect(try parse(synPacket(options: [3, 3, given])).windowScale == shift, "shift \(given)")
        }
    }

    @Test("Skips MSS and Window Scale with nonstandard lengths by length and does not read their values")
    func wrongSizedKnownOptions() throws {
        // MSS of length 3 (one value byte), then Window Scale of length 4.
        let parsed = try parse(synPacket(options: [2, 3, 0x05, 3, 4, 7, 7, 1]))
        #expect(parsed.maximumSegmentSize == nil)
        #expect(parsed.windowScale == nil)
    }

    @Test("The last instance of a repeated option wins")
    func duplicateOptions() throws {
        let parsed = try parse(synPacket(options: [2, 4, 0x02, 0x00, 2, 4, 0x04, 0x00, 3, 3, 2, 3, 3, 6, 1, 1]))
        #expect(parsed.maximumSegmentSize == 1024)
        #expect(parsed.windowScale == 6)
    }

    @Test("Finishes even when all 40 option bytes are filled or length-2 options go on without end")
    func maximumOptionRegion() throws {
        // Kind 77, length 2, repeated 20 times (40 bytes).
        let options = [UInt8](Array(repeating: [77, 2], count: 20).joined())
        let parsed = try parse(synPacket(options: options))
        #expect(parsed.maximumSegmentSize == nil)
        // 40 NOPs.
        let nops = try parse(synPacket(options: [UInt8](repeating: 1, count: 40)))
        #expect(nops.windowScale == nil)
    }
}

extension [UInt8] {
    /// Returns a copy with `count` bytes zeroed starting at `index`.
    fileprivate func zeroing(at index: Int, count: Int) -> [UInt8] {
        var copy = self
        for offset in index..<index + count { copy[offset] = 0 }
        return copy
    }
}
