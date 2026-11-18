import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// Segment serialization (behaviors W 3·4) and the serialize → parse round trip. `RawPacket` builds expected bytes independently of the implementation.
@Suite("TCP segment serialization")
struct TCPSegmentSerializingTests {
    private func segment(
        _ source: IPAddress, _ destination: IPAddress,
        sequence: UInt32 = 1, acknowledgment: UInt32 = 0, flags: TCPSegment.Flags, window: UInt16 = 1000,
        mss: UInt16? = nil, windowScale: UInt8? = nil, payload: [UInt8] = []
    ) -> TCPSegment {
        TCPSegment(
            source: WireHosts.endpoint(source, 40_000), destination: WireHosts.endpoint(destination, 443),
            sequenceNumber: SequenceNumber(sequence), acknowledgmentNumber: SequenceNumber(acknowledgment),
            flags: flags, window: window, maximumSegmentSize: mss, windowScale: windowScale, payload: payload)
    }

    // MARK: - Bytes

    @Test("IPv4 SYN: matches independently constructed bytes (MSS 1240, NOP, Window Scale 3)")
    func ipv4SYNBytes() throws {
        let made = try #require(
            segment(WireHosts.v4a, WireHosts.v4b, sequence: 0x0102_0304, flags: .syn, window: 65_535, mss: 1240, windowScale: 3)
                .ipPacket())
        let expected = RawPacket.ipv4(
            segment: RawPacket.segment(
                sequence: 0x0102_0304, flags: 0x02, window: 65_535, options: [2, 4, 0x04, 0xD8, 1, 3, 3, 3]))
        #expect(made == expected)
        #expect(made.count == 20 + 28)
    }

    @Test("IPv6 data segment: matches independently constructed bytes")
    func ipv6DataBytes() throws {
        let payload = Array("tailnet".utf8)
        let made = try #require(
            segment(WireHosts.v6a, WireHosts.v6b, sequence: 7, acknowledgment: 9, flags: [.ack, .psh], payload: payload)
                .ipPacket())
        let expected = RawPacket.ipv6(
            segment: RawPacket.segment(sequence: 7, acknowledgment: 9, flags: 0x18, payload: payload))
        #expect(made == expected)
    }

    @Test("Option combinations: MSS only, Window Scale only, both, and neither. The header is aligned to a 4-byte boundary")
    func optionLayouts() throws {
        let layouts: [(mss: UInt16?, scale: UInt8?, options: [UInt8])] = [
            (nil, nil, []),
            (1220, nil, [2, 4, 0x04, 0xC4]),
            (nil, 7, [1, 3, 3, 7]),
            (1460, 14, [2, 4, 0x05, 0xB4, 1, 3, 3, 14]),
        ]
        for layout in layouts {
            for (from, to) in [(WireHosts.v4a, WireHosts.v4b), (WireHosts.v6a, WireHosts.v6b)] {
                let made = try #require(
                    segment(from, to, flags: [.syn, .ack], mss: layout.mss, windowScale: layout.scale).ipPacket())
                let raw = RawPacket.segment(flags: 0x12, options: layout.options)
                let expected = from.isIPv4 ? RawPacket.ipv4(segment: raw) : RawPacket.ipv6(segment: raw)
                #expect(made == expected, "\(layout)")
            }
        }
    }

    @Test("Omits options on non-SYN segments")
    func noOptionsWithoutSYN() throws {
        let made = try #require(segment(WireHosts.v4a, WireHosts.v4b, flags: .ack, mss: 1240, windowScale: 3).ipPacket())
        #expect(made == RawPacket.ipv4(segment: RawPacket.segment(flags: 0x10)))
    }

    @Test("Serialized IPv4 header fields: IHL 5, DF, identifier 0, TTL 64, protocol 6, and checksum")
    func ipv4HeaderFields() throws {
        let payload = [UInt8](repeating: 0x42, count: 100)
        let made = try #require(segment(WireHosts.v4a, WireHosts.v4b, flags: .ack, payload: payload).ipPacket())
        #expect(made[0] == 0x45)
        #expect(made[1] == 0)
        #expect(Int(made[2]) << 8 | Int(made[3]) == made.count)
        #expect(made.count == 20 + 20 + 100)
        #expect(made[4] == 0 && made[5] == 0)
        #expect(made[6] == 0x40 && made[7] == 0)  // DF only
        #expect(made[8] == 64)
        #expect(made[9] == 6)
        #expect(Array(made[12..<16]) == WireHosts.v4a.bytes)
        #expect(Array(made[16..<20]) == WireHosts.v4b.bytes)
        // The complement is 0 when the field is included in the sum.
        #expect(RawPacket.checksum(Array(made[..<20])) == 0)
        // Data begins at the end of the TCP header.
        #expect(Array(made[40...]) == payload)
    }

    @Test("Serialized IPv6 header fields: version 6, traffic class and flow label 0, hop limit 64, and next header 6")
    func ipv6HeaderFields() throws {
        let made = try #require(segment(WireHosts.v6a, WireHosts.v6b, flags: .ack, payload: [1, 2, 3]).ipPacket())
        #expect(Array(made[0..<4]) == [0x60, 0, 0, 0])
        #expect(Int(made[4]) << 8 | Int(made[5]) == 20 + 3)
        #expect(made[6] == 6)
        #expect(made[7] == 64)
        #expect(Array(made[8..<24]) == WireHosts.v6a.bytes)
        #expect(Array(made[24..<40]) == WireHosts.v6b.bytes)
        #expect(made.count == 40 + 23)
    }

    @Test("The hopLimit argument sets TTL and hop limit")
    func hopLimitArgument() throws {
        let v4 = try #require(segment(WireHosts.v4a, WireHosts.v4b, flags: .ack).ipPacket(hopLimit: 7))
        #expect(v4[8] == 7)
        #expect(RawPacket.checksum(Array(v4[..<20])) == 0)  // The header checksum covers TTL
        let v6 = try #require(segment(WireHosts.v6a, WireHosts.v6b, flags: .ack).ipPacket(hopLimit: 7))
        #expect(v6[7] == 7)
        #expect(try TCPSegment(parsingIPPacket: v4).source.port == 40_000)
    }

    @Test("TCP checksum of the serialized packet: urgent pointer, CWR, and ECE are 0")
    func tcpHeaderTail() throws {
        for (from, to) in [(WireHosts.v4a, WireHosts.v4b), (WireHosts.v6a, WireHosts.v6b)] {
            let made = try #require(segment(from, to, flags: [.fin, .ack], window: 0x1234, payload: [1]).ipPacket())
            let ip = from.isIPv4 ? 20 : 40
            #expect(made[ip + 13] == 0x11)  // FIN | ACK. No CWR, ECE, or URG
            #expect(made[ip + 12] == 0x50)  // data offset 5, reserved 0
            #expect(made[ip + 14] == 0x12 && made[ip + 15] == 0x34)
            #expect(made[ip + 18] == 0 && made[ip + 19] == 0)  // urgent pointer
            #expect(made == (from.isIPv4
                ? RawPacket.ipv4(segment: RawPacket.segment(flags: 0x11, window: 0x1234, payload: [1]))
                : RawPacket.ipv6(segment: RawPacket.segment(flags: 0x11, window: 0x1234, payload: [1]))))
        }
    }

    // MARK: - Size and rejection

    @Test("Maximum payload in one IP packet: 65,495 bytes for IPv4 and 65,515 bytes for IPv6")
    func largestPayloads() throws {
        let v4Limit = 65_535 - 20 - 20
        let v6Limit = 65_535 - 20
        let fitsV4 = try #require(segment(WireHosts.v4a, WireHosts.v4b, flags: .ack, payload: [UInt8](repeating: 1, count: v4Limit)).ipPacket())
        #expect(fitsV4.count == 65_535)
        #expect(try TCPSegment(parsingIPPacket: fitsV4).payload.count == v4Limit)
        let fitsV6 = try #require(segment(WireHosts.v6a, WireHosts.v6b, flags: .ack, payload: [UInt8](repeating: 1, count: v6Limit)).ipPacket())
        #expect(fitsV6.count == 40 + 65_535)
        #expect(try TCPSegment(parsingIPPacket: fitsV6).payload.count == v6Limit)

        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: .ack, payload: [UInt8](repeating: 1, count: v4Limit + 1)).ipPacket() == nil)
        #expect(segment(WireHosts.v6a, WireHosts.v6b, flags: .ack, payload: [UInt8](repeating: 1, count: v6Limit + 1)).ipPacket() == nil)
    }

    @Test("Does not serialize when the source and destination address families differ")
    func mixedFamilies() {
        #expect(segment(WireHosts.v4a, WireHosts.v6b, flags: .ack).ipPacket() == nil)
        #expect(segment(WireHosts.v6a, WireHosts.v4b, flags: .ack).ipPacket() == nil)
    }

    // MARK: - Round trip

    @Test("Serialize → parse round-trips across family × flags × options × payload length")
    func roundTrip() throws {
        let flagSets: [TCPSegment.Flags] = [
            .syn, [.syn, .ack], .ack, [.ack, .psh], [.fin, .ack], .rst, [.rst, .ack], [.fin, .ack, .psh],
        ]
        let payloadLengths = [0, 1, 2, 3, 536, 1199, 1240]
        for (from, to) in [(WireHosts.v4a, WireHosts.v4b), (WireHosts.v6a, WireHosts.v6b)] {
            for flags in flagSets {
                for length in payloadLengths {
                    let isSYN = flags.contains(.syn)
                    var random = WireFuzzRandom(seed: UInt64(length) << 8 | UInt64(flags.rawValue))
                    let original = segment(
                        from, to, sequence: 0xFFFF_FF00, acknowledgment: 0x0000_0100, flags: flags, window: 0xFFFF,
                        mss: isSYN ? 1220 : nil, windowScale: isSYN ? 14 : nil, payload: random.bytes(length))
                    let bytes = try #require(original.ipPacket())
                    #expect(try TCPSegment(parsingIPPacket: bytes) == original, "\(from) \(flags.rawValue) length \(length)")
                }
            }
        }
    }

    @Test("Parse → serialize also round-trips (rebuilds the received packet with the same bytes)")
    func reserializing() throws {
        let packets = [
            RawPacket.ipv4(segment: RawPacket.segment(flags: 0x02, options: [2, 4, 0x04, 0xD8, 1, 3, 3, 3])),
            RawPacket.ipv6(segment: RawPacket.segment(flags: 0x12, options: [2, 4, 0x04, 0xC4, 1, 3, 3, 3])),
            RawPacket.ipv4(segment: RawPacket.segment(flags: 0x18, payload: Array("abc".utf8))),
            RawPacket.ipv6(segment: RawPacket.segment(flags: 0x11)),
        ]
        for packet in packets {
            #expect(try TCPSegment(parsingIPPacket: packet).ipPacket() == packet)
        }
    }

    @Test("MSS 0 on SYN parses as the default, and serializing again carries the default")
    func mssZeroNormalized() throws {
        let packet = RawPacket.ipv4(segment: RawPacket.segment(flags: 0x02, options: [2, 4, 0, 0]))
        let parsed = try TCPSegment(parsingIPPacket: packet)
        #expect(parsed.maximumSegmentSize == 536)
        let rebuilt = try #require(parsed.ipPacket())
        #expect(rebuilt == RawPacket.ipv4(segment: RawPacket.segment(flags: 0x02, options: [2, 4, 0x02, 0x18])))
    }

    @Test("sequenceLength: adds 1 each for SYN and FIN to the data length")
    func sequenceLength() {
        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: .ack).sequenceLength == 0)
        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: .syn).sequenceLength == 1)
        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: [.syn, .ack]).sequenceLength == 1)
        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: [.fin, .ack], payload: [1, 2, 3]).sequenceLength == 4)
        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: [.syn, .fin], payload: [1]).sequenceLength == 3)
        #expect(segment(WireHosts.v4a, WireHosts.v4b, flags: .rst).sequenceLength == 0)
    }
}
