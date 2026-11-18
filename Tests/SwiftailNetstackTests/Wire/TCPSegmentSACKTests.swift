import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// Parsing and serializing SACK-Permitted and SACK options (RFC 2018 2·3, contract behaviors W2·W3, X1). `RawPacket` builds input bytes independently of the implementation.
@Suite("TCP segment SACK options")
struct TCPSegmentSACKTests {
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

    /// SACK option bytes: kind 5, length, and the left and right edges of each block.
    private func sackOption(_ blocks: [(UInt32, UInt32)]) -> [UInt8] {
        [5, UInt8(2 + 8 * blocks.count)] + blocks.flatMap { RawPacket.be32($0.0) + RawPacket.be32($0.1) }
    }

    private func block(_ left: UInt32, _ right: UInt32) -> TCPSegment.SACKBlock {
        TCPSegment.SACKBlock(leftEdge: SequenceNumber(left), rightEdge: SequenceNumber(right))
    }

    // MARK: - Parsing SACK-Permitted

    @Test("Reads SACK-Permitted (kind 4, length 2) on SYN and reads the surrounding MSS and Window Scale options")
    func sackPermittedOnSYN() throws {
        let options: [UInt8] = [2, 4, 0x04, 0xD8, 1, 1, 4, 2, 1, 3, 3, 7]
        for packet in [
            RawPacket.ipv4(segment: RawPacket.segment(flags: 0x02, options: options)),
            RawPacket.ipv6(segment: RawPacket.segment(flags: 0x12, options: options)),
        ] {
            let parsed = try parse(packet)
            #expect(parsed.sackPermitted)
            #expect(parsed.maximumSegmentSize == 1240)
            #expect(parsed.windowScale == 7)
            #expect(parsed.sackBlocks.isEmpty)
        }
        let without = try parse(RawPacket.ipv4(segment: RawPacket.segment(flags: 0x02, options: [2, 4, 0x04, 0xD8])))
        #expect(!without.sackPermitted)
    }

    @Test("Discards SACK-Permitted on non-SYN segments (RFC 2018 2: send only on SYN)")
    func sackPermittedOnNonSYNIgnored() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: [1, 1, 4, 2])))
        #expect(!parsed.sackPermitted)
    }

    @Test("Skips SACK-Permitted by length without reading its value if length is not 2 (reads subsequent options)")
    func sackPermittedWrongLength() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(
            flags: 0x02, options: [4, 3, 0, 2, 4, 0x04, 0xD8, 1])))
        #expect(!parsed.sackPermitted)
        #expect(parsed.maximumSegmentSize == 1240)
    }

    // MARK: - Parsing SACK blocks

    @Test("Reads 1~4 SACK blocks in option order and preserves a block that wraps at the 32-bit boundary", arguments: 1...4)
    func sackBlocks(count: Int) throws {
        let all: [(UInt32, UInt32)] = [(5_500, 6_000), (0xFFFF_FFF0, 0x10), (8_000, 8_500), (7_000, 7_500)]
        let blocks = Array(all.prefix(count))
        let packet = RawPacket.ipv4(segment: RawPacket.segment(
            acknowledgment: 5_000, flags: 0x10, options: [1, 1] + sackOption(blocks)))
        let parsed = try parse(packet)
        #expect(parsed.sackBlocks == blocks.map { block($0.0, $0.1) })
        #expect(!parsed.sackPermitted)
        #expect(parsed.maximumSegmentSize == nil)
    }

    @Test("Also reads SACK blocks on data-bearing segments, with data starting after the options (IPv6)")
    func sackBlocksWithPayload() throws {
        let payload: [UInt8] = [1, 2, 3, 4, 5]
        let parsed = try parse(RawPacket.ipv6(segment: RawPacket.segment(
            flags: 0x18, options: [1, 1] + sackOption([(100, 200), (300, 400)]), payload: payload)))
        #expect(parsed.sackBlocks == [block(100, 200), block(300, 400)])
        #expect(parsed.payload == payload)
    }

    @Test("Discards SACK blocks on SYN (just as MSS and Window Scale are kept only on SYN)")
    func sackBlocksOnSYNIgnored() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(
            flags: 0x12, options: [2, 4, 0x04, 0xD8, 1, 1] + sackOption([(1, 2)]))))
        #expect(parsed.sackBlocks.isEmpty)
        #expect(parsed.maximumSegmentSize == 1240)
    }

    @Test("Skips a SACK by length without reading values when its length is not 2 + 8n (n ≥ 1)", arguments: [2, 3, 9, 17, 33])
    func sackWrongLengthSkipped(length: Int) throws {
        var option: [UInt8] = [5, UInt8(length)] + [UInt8](repeating: 0xAB, count: length - 2)
        // Put Window Scale after it to check that parsing skips by exactly the length (as this is not a SYN, it does not retain the value, so check that there is no error).
        option += [1, 1, 1, 1]
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: option)))
        #expect(parsed.sackBlocks.isEmpty)
    }

    @Test("When a segment has two SACK options, the last one wins")
    func duplicateSACKLastWins() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(
            flags: 0x10, options: [1, 1] + sackOption([(1, 2)]) + [1, 1] + sackOption([(3, 4), (5, 6)]))))
        #expect(parsed.sackBlocks == [block(3, 4), block(5, 6)])
    }

    @Test("A SACK extending past the header, a SACK with blocks exceeding the option space (40 bytes), and a SACK with a truncated length field are malformed")
    func malformedSACK() {
        // Declares one block (length 10), but the option area contains only 8 bytes.
        let outside = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: [1, 1, 5, 10, 0, 0, 0, 1]))
        #expect(parseError(outside) == .malformed)
        // Five blocks give length 42. They do not fit even with all 40 bytes of option space.
        let fiveBlocks = [5, 42] + [UInt8](repeating: 0, count: 38)
        let tooMany = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: fiveBlocks))
        #expect(parseError(tooMany) == .malformed)
        // The area's last byte is kind 5 with no length field.
        let truncated = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: [1, 1, 1, 5]))
        #expect(parseError(truncated) == .malformed)
    }

    // MARK: - Serialization

    @Test("SYN: 12 bytes in the order MSS, two NOPs and SACK-Permitted, then NOP and Window Scale (as in gVisor makeSynOptions)")
    func serializeSYNWithSACKPermitted() throws {
        let segment = TCPSegment(
            source: WireHosts.endpoint(WireHosts.v4a, 40_000), destination: WireHosts.endpoint(WireHosts.v4b, 443),
            sequenceNumber: SequenceNumber(1), flags: [.syn], window: 65_535,
            maximumSegmentSize: 1240, windowScale: 3, sackPermitted: true)
        let packet = try #require(segment.ipPacket())
        let expected = RawPacket.ipv4(segment: RawPacket.segment(
            sequence: 1, flags: 0x02, window: 65_535, options: [2, 4, 0x04, 0xD8, 1, 1, 4, 2, 1, 3, 3, 3]))
        #expect(packet == expected)
        #expect(try parse(packet) == segment)

        var withoutScale = segment
        withoutScale.windowScale = nil
        let shorter = try #require(withoutScale.ipPacket())
        #expect(shorter == RawPacket.ipv4(segment: RawPacket.segment(
            sequence: 1, flags: 0x02, window: 65_535, options: [2, 4, 0x04, 0xD8, 1, 1, 4, 2])))
    }

    @Test("Non-SYN segments omit SACK-Permitted, and SYN segments omit SACK blocks")
    func optionsOnlyWhereAllowed() throws {
        let ack = TCPSegment(
            source: WireHosts.endpoint(WireHosts.v4a, 40_000), destination: WireHosts.endpoint(WireHosts.v4b, 443),
            sequenceNumber: SequenceNumber(1), flags: [.ack], sackPermitted: true)
        let ackPacket = try #require(ack.ipPacket())
        #expect(ackPacket.count == 40)
        #expect(try !parse(ackPacket).sackPermitted)

        let syn = TCPSegment(
            source: WireHosts.endpoint(WireHosts.v4a, 40_000), destination: WireHosts.endpoint(WireHosts.v4b, 443),
            sequenceNumber: SequenceNumber(1), flags: [.syn], sackBlocks: [block(1, 2)])
        let synPacket = try #require(syn.ipPacket())
        #expect(synPacket.count == 40)
    }

    @Test("ACK with 1~4 SACK blocks: two NOPs + kind 5 + length + blocks. Parsing yields the same values (IPv4 and IPv6)", arguments: 1...4)
    func serializeSACKBlocks(count: Int) throws {
        let edges: [(UInt32, UInt32)] = [(6_000, 6_500), (0xFFFF_FF00, 0x100), (8_000, 8_500), (9_000, 9_500)]
        let blocks = Array(edges.prefix(count))
        for (source, destination) in [(WireHosts.v4a, WireHosts.v4b), (WireHosts.v6a, WireHosts.v6b)] {
            let segment = TCPSegment(
                source: WireHosts.endpoint(source, 40_000), destination: WireHosts.endpoint(destination, 443),
                sequenceNumber: SequenceNumber(7), acknowledgmentNumber: SequenceNumber(5_500), flags: [.ack],
                window: 4_096, sackBlocks: blocks.map { block($0.0, $0.1) }, payload: [9, 8, 7])
            let packet = try #require(segment.ipPacket())
            let raw = RawPacket.segment(
                sequence: 7, acknowledgment: 5_500, flags: 0x10, window: 4_096, options: [1, 1] + sackOption(blocks),
                payload: [9, 8, 7])
            let expected = source.isIPv4
                ? RawPacket.ipv4(source: source, destination: destination, segment: raw)
                : RawPacket.ipv6(source: source, destination: destination, segment: raw)
            #expect(packet == expected)
            #expect(try parse(packet) == segment)
        }
        #expect(TCPSegment.sackOptionLength(blockCount: count) == 4 + 8 * count)
    }

    @Test("Five SACK blocks do not fit in the TCP header, so the result is nil")
    func tooManySACKBlocksDoNotSerialize() {
        let segment = TCPSegment(
            source: WireHosts.endpoint(WireHosts.v4a, 40_000), destination: WireHosts.endpoint(WireHosts.v4b, 443),
            sequenceNumber: SequenceNumber(1), flags: [.ack],
            sackBlocks: (0..<5).map { block(UInt32($0) * 10, UInt32($0) * 10 + 5) })
        #expect(segment.ipPacket() == nil)
        #expect(TCPSegment.sackOptionLength(blockCount: 0) == 0)
    }
}
