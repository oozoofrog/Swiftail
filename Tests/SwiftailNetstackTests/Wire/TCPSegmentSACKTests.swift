import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// SACK-Permitted와 SACK 옵션의 해석·만들기(RFC 2018 2·3, 계약 동작 W2·W3, X1). 입력 바이트는 `RawPacket`이 구현과 따로 짠다.
@Suite("TCP 세그먼트 SACK 옵션")
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

    /// SACK 옵션의 바이트: kind 5, 길이, 블록마다 왼쪽·오른쪽 끝.
    private func sackOption(_ blocks: [(UInt32, UInt32)]) -> [UInt8] {
        [5, UInt8(2 + 8 * blocks.count)] + blocks.flatMap { RawPacket.be32($0.0) + RawPacket.be32($0.1) }
    }

    private func block(_ left: UInt32, _ right: UInt32) -> TCPSegment.SACKBlock {
        TCPSegment.SACKBlock(leftEdge: SequenceNumber(left), rightEdge: SequenceNumber(right))
    }

    // MARK: - 해석: SACK-Permitted

    @Test("SYN의 SACK-Permitted(kind 4, 길이 2)를 읽는다. 앞뒤의 MSS·Window Scale도 읽힌다")
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

    @Test("SYN이 아닌 세그먼트의 SACK-Permitted는 버린다(RFC 2018 2: SYN에만 보낸다)")
    func sackPermittedOnNonSYNIgnored() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: [1, 1, 4, 2])))
        #expect(!parsed.sackPermitted)
    }

    @Test("길이가 2가 아닌 SACK-Permitted는 값을 읽지 않고 길이로 건너뛴다(뒤의 옵션은 읽는다)")
    func sackPermittedWrongLength() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(
            flags: 0x02, options: [4, 3, 0, 2, 4, 0x04, 0xD8, 1])))
        #expect(!parsed.sackPermitted)
        #expect(parsed.maximumSegmentSize == 1240)
    }

    // MARK: - 해석: SACK 블록

    @Test("SACK 블록 1~4개를 옵션의 순서대로 읽는다. 32비트 끝을 순환하는 블록도 그대로다", arguments: 1...4)
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

    @Test("데이터가 실린 세그먼트의 SACK 블록도 읽고 데이터는 옵션 뒤에서 시작한다(IPv6)")
    func sackBlocksWithPayload() throws {
        let payload: [UInt8] = [1, 2, 3, 4, 5]
        let parsed = try parse(RawPacket.ipv6(segment: RawPacket.segment(
            flags: 0x18, options: [1, 1] + sackOption([(100, 200), (300, 400)]), payload: payload)))
        #expect(parsed.sackBlocks == [block(100, 200), block(300, 400)])
        #expect(parsed.payload == payload)
    }

    @Test("SYN의 SACK 블록은 버린다(MSS·Window Scale을 SYN에서만 담는 것과 같은 규칙)")
    func sackBlocksOnSYNIgnored() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(
            flags: 0x12, options: [2, 4, 0x04, 0xD8, 1, 1] + sackOption([(1, 2)]))))
        #expect(parsed.sackBlocks.isEmpty)
        #expect(parsed.maximumSegmentSize == 1240)
    }

    @Test("길이가 2 + 8n(n ≥ 1)이 아닌 SACK은 값을 읽지 않고 길이로 건너뛴다", arguments: [2, 3, 9, 17, 33])
    func sackWrongLengthSkipped(length: Int) throws {
        var option: [UInt8] = [5, UInt8(length)] + [UInt8](repeating: 0xAB, count: length - 2)
        // 뒤에 Window Scale을 두어 길이로 정확히 건너뛰었는지 본다(SYN이 아니라 값은 담지 않으므로 오류가 없음으로 본다).
        option += [1, 1, 1, 1]
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: option)))
        #expect(parsed.sackBlocks.isEmpty)
    }

    @Test("같은 세그먼트에 SACK이 둘이면 뒤의 것이 남는다")
    func duplicateSACKLastWins() throws {
        let parsed = try parse(RawPacket.ipv4(segment: RawPacket.segment(
            flags: 0x10, options: [1, 1] + sackOption([(1, 2)]) + [1, 1] + sackOption([(3, 4), (5, 6)]))))
        #expect(parsed.sackBlocks == [block(3, 4), block(5, 6)])
    }

    @Test("머리 밖으로 나가는 SACK, 블록이 옵션 공간(40바이트)을 넘는 SACK, 길이 필드가 잘린 SACK은 malformed")
    func malformedSACK() {
        // 블록 하나(길이 10)를 선언했지만 옵션 영역에는 8바이트뿐이다.
        let outside = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: [1, 1, 5, 10, 0, 0, 0, 1]))
        #expect(parseError(outside) == .malformed)
        // 블록 5개는 길이 42다. 옵션 영역 40바이트를 꽉 채워도 들어가지 않는다.
        let fiveBlocks = [5, 42] + [UInt8](repeating: 0, count: 38)
        let tooMany = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: fiveBlocks))
        #expect(parseError(tooMany) == .malformed)
        // 영역의 마지막 바이트가 kind 5이고 길이 필드가 없다.
        let truncated = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10, options: [1, 1, 1, 5]))
        #expect(parseError(truncated) == .malformed)
    }

    // MARK: - 만들기

    @Test("SYN: MSS, NOP 둘과 SACK-Permitted, NOP와 Window Scale 순서의 12바이트(gVisor makeSynOptions와 같다)")
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

    @Test("SYN이 아니면 SACK-Permitted를 싣지 않고, SYN이면 SACK 블록을 싣지 않는다")
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

    @Test("ACK의 SACK 블록 1~4개: NOP 둘 + kind 5 + 길이 + 블록. 해석하면 같은 값이다(IPv4·IPv6)", arguments: 1...4)
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

    @Test("SACK 블록이 5개면 TCP 머리에 들어가지 않아 nil이다")
    func tooManySACKBlocksDoNotSerialize() {
        let segment = TCPSegment(
            source: WireHosts.endpoint(WireHosts.v4a, 40_000), destination: WireHosts.endpoint(WireHosts.v4b, 443),
            sequenceNumber: SequenceNumber(1), flags: [.ack],
            sackBlocks: (0..<5).map { block(UInt32($0) * 10, UInt32($0) * 10 + 5) })
        #expect(segment.ipPacket() == nil)
        #expect(TCPSegment.sackOptionLength(blockCount: 0) == 0)
    }
}
