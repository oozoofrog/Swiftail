// Contract behavior 1. IP packet parsing. Fixed packets, trimming to the declared length, short headers, IHL 4, fragments, extension headers, and random input.

import Testing

import SwiftailBase
import SwiftailEngine

@Suite("IP packet parsing")
struct IPPacketTests {
    @Test("Read IPv4 UDP addresses and ports")
    func ipv4UDP() throws {
        let packet = try IPPacket(parsing: TestPacket.udp(from: "100.64.0.2", 40000, to: "100.64.0.1", 7))
        #expect(packet.source == IPAddress("100.64.0.2"))
        #expect(packet.destination == IPAddress("100.64.0.1"))
        #expect(packet.transportProtocol == .udp)
        #expect(packet.sourcePort == 40000)
        #expect(packet.destinationPort == 7)
        #expect(!packet.isTCPSYN)
    }

    @Test("Read IPv6 UDP addresses and ports")
    func ipv6UDP() throws {
        let packet = try IPPacket(parsing: TestPacket.udp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 65535))
        #expect(packet.source == IPAddress("fd7a:115c:a1e0::2"))
        #expect(packet.destination == IPAddress("fd7a:115c:a1e0::1"))
        #expect(packet.transportProtocol == .udp)
        #expect(packet.sourcePort == 1)
        #expect(packet.destinationPort == 65535)
    }

    @Test("A TCP segment with only SYN set is a new connection", arguments: ["100.64.0.2", "fd7a:115c:a1e0::2"])
    func tcpFlags(source: String) throws {
        let destination = source.contains(":") ? "fd7a:115c:a1e0::1" : "100.64.0.1"
        let flags: [(UInt8, Bool)] = [(0x02, true), (0x12, false), (0x10, false), (0x04, false), (0x03, true), (0x00, false)]
        for (flag, isSYN) in flags {
            let packet = try IPPacket(parsing: TestPacket.tcp(from: source, 50000, to: destination, 22, flags: flag))
            #expect(packet.transportProtocol == .tcp)
            #expect(packet.sourcePort == 50000)
            #expect(packet.destinationPort == 22)
            #expect(packet.isTCPSYN == isSYN, "flags \(flag)")
        }
    }

    @Test("Treat only the number for the IP family as ICMP. Ports are 0")
    func icmp() throws {
        let v4 = try IPPacket(parsing: TestPacket.icmp(from: "100.64.0.2", to: "100.64.0.1", type: 8))
        #expect(v4.transportProtocol == .icmpv4)
        #expect(v4.sourcePort == 0 && v4.destinationPort == 0)
        let v6 = try IPPacket(parsing: TestPacket.icmp(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", type: 128))
        #expect(v6.transportProtocol == .icmpv6)

        // Go also treats 58 in IPv4 and 1 in IPv6 as protocols other than ICMP.
        let crossed4 = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 58, transport: [128, 0, 0, 0])
        #expect(try IPPacket(parsing: crossed4).transportProtocol == .other(58))
        let crossed6 = TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 1, transport: [8, 0, 0, 0])
        #expect(try IPPacket(parsing: crossed6).transportProtocol == .other(1))
    }

    @Test("Read SCTP ports at the same offsets as UDP ports")
    func sctp() throws {
        let v4 = try IPPacket(parsing: TestPacket.sctp(from: "100.64.0.2", 40000, to: "100.64.0.1", 9))
        #expect(v4.transportProtocol == .sctp)
        #expect(v4.sourcePort == 40000 && v4.destinationPort == 9)
        let v6 = try IPPacket(parsing: TestPacket.sctp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 2))
        #expect(v6.transportProtocol == .sctp)
        #expect(v6.destinationPort == 2)
    }

    @Test("TSMP and other protocols")
    func otherProtocols() throws {
        let tsmp = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 99, transport: Array("p12345678".utf8))
        #expect(try IPPacket(parsing: tsmp).transportProtocol == .tsmp)
        let gre = TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 47, transport: [])
        let parsed = try IPPacket(parsing: gre)
        #expect(parsed.transportProtocol == .other(47))
        #expect(parsed.sourcePort == 0)
    }

    @Test("Read the transport header after any IPv4 options")
    func ipv4Options() throws {
        let udp = [0x9C, 0x40, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00] as [UInt8]
        let bytes = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 17, transport: udp, options: [1, 1, 1, 0])
        let packet = try IPPacket(parsing: bytes)
        #expect(packet.sourcePort == 40000)
        #expect(packet.destinationPort == 7)
    }

    @Test("Trim bytes after the declared length")
    func truncatesToDeclaredLength() throws {
        let v4 = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 2)
        #expect(try IPPacket(parsing: v4 + [0, 0, 0, 0]).bytes == v4)
        let v6 = TestPacket.udp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 2)
        #expect(try IPPacket(parsing: v6 + [9, 9]).bytes == v6)
    }

    @Test("Packets that are too short or have an inconsistent length are malformed")
    func malformed() {
        let udp = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 2)
        let tcp = TestPacket.tcp(from: "100.64.0.2", 1, to: "100.64.0.1", 2, flags: 0x02)
        let udp6 = TestPacket.udp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 2)

        var ihl4 = udp
        ihl4[0] = 0x44
        var longerThanBuffer = udp
        longerThanBuffer[3] += 1
        var shorterThanHeader = udp
        shorterThanHeader[2] = 0
        shorterThanHeader[3] = 19
        var ihlBeyondTotal = udp
        ihlBeyondTotal[0] = 0x4F
        var payloadBeyondBuffer6 = udp6
        payloadBeyondBuffer6[5] += 1
        var tcpDataOffsetTooSmall = tcp
        tcpDataOffsetTooSmall[20 + 12] = 0x40
        var tcpDataOffsetBeyondPacket = tcp
        tcpDataOffsetBeyondPacket[20 + 12] = 0x60

        let cases: [[UInt8]] = [
            [],
            [0x45],
            Array(udp.prefix(19)),
            Array(udp6.prefix(39)),
            [0x50] + Array(udp.dropFirst()),  // Version 5
            ihl4,
            longerThanBuffer,
            shorterThanHeader,
            ihlBeyondTotal,
            payloadBeyondBuffer6,
            // The transport header is shorter than the minimum length.
            TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 17, transport: [0, 1, 0, 2, 0, 7, 0]),
            TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 6, transport: [UInt8](repeating: 0, count: 19)),
            TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 1, transport: [0, 0, 0, 0, 0, 0, 0]),
            TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 58, transport: [129, 0, 0, 0]),
            TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 132, transport: [UInt8](repeating: 0, count: 11)),
            // Go drops protocol numbers 0 and 255 as Unknown.
            TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 0, transport: [0, 0, 0, 0]),
            TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 255, transport: [0, 0, 0, 0]),
            TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 255, transport: [0, 0, 0, 0]),
            tcpDataOffsetTooSmall,
            tcpDataOffsetBeyondPacket,
        ]
        for bytes in cases {
            #expect(throws: IPPacket.ParseError.malformed, "\(bytes.count) bytes") { try IPPacket(parsing: bytes) }
        }
    }

    @Test("Fragments with IPv4 MF or offset, or IPv6 next-header 44", arguments: [UInt16(0x2000), 0x0001, 0x2001, 0x1FFF])
    func fragments(flagsAndOffset: UInt16) {
        let udp = [0, 1, 0, 2, 0, 8, 0, 0] as [UInt8]
        let bytes = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 17, transport: udp, flagsAndOffset: flagsAndOffset)
        #expect(throws: IPPacket.ParseError.fragment) { try IPPacket(parsing: bytes) }
    }

    @Test("IPv4 with only the DF bit set is unfragmented")
    func dontFragment() throws {
        let udp = [0, 1, 0, 2, 0, 8, 0, 0] as [UInt8]
        let bytes = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 17, transport: udp, flagsAndOffset: 0x4000)
        #expect(try IPPacket(parsing: bytes).transportProtocol == .udp)
    }

    @Test("An IPv6 fragment header (44) yields fragment")
    func ipv6Fragment() {
        let bytes = TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 44, transport: [17, 0, 0, 0, 0, 0, 0, 1])
        #expect(throws: IPPacket.ParseError.fragment) { try IPPacket(parsing: bytes) }
    }

    @Test("IPv6 extension headers yield extensionHeader", arguments: [UInt8(0), 43, 50, 51, 60, 135, 139, 140])
    func extensionHeaders(nextHeader: UInt8) {
        let bytes = TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: nextHeader, transport: [17, 0, 0, 0, 0, 0, 0, 0])
        #expect(throws: IPPacket.ParseError.extensionHeader) { try IPPacket(parsing: bytes) }
    }

    @Test("Random byte sequences and truncated or modified packets do not crash the parser")
    func fuzz() {
        var random = FuzzRandom(seed: 0x5EED)
        let seeds = [
            TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 2),
            TestPacket.tcp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 2, flags: 0x02),
            TestPacket.icmp(from: "100.64.0.2", to: "100.64.0.1", type: 8),
        ]
        for _ in 0..<20_000 {
            var bytes: [UInt8]
            if Bool.random(using: &random), let seed = seeds.randomElement(using: &random) {
                bytes = Array(seed.prefix(Int.random(in: 0...seed.count, using: &random)))
                for _ in 0..<Int.random(in: 0...3, using: &random) where !bytes.isEmpty {
                    bytes[Int.random(in: 0..<bytes.count, using: &random)] = UInt8.random(in: .min ... .max, using: &random)
                }
            } else {
                bytes = random.bytes(Int.random(in: 0...80, using: &random))
                if !bytes.isEmpty, Bool.random(using: &random) {
                    bytes[0] = Bool.random(using: &random) ? 0x45 : 0x60
                }
            }
            if let packet = try? IPPacket(parsing: bytes) {
                #expect(packet.bytes.count <= bytes.count)
            }
        }
    }
}
