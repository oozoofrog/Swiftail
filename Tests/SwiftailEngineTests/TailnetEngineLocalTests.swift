// Contract `docs/contracts/SwiftailTunnel.md` behavior L (local handling) and behavior D7, item 4 in the test list.
// Verify that the engine handles packets read from the device that go to the service IP, to a local address, or to TSMP without WireGuard.
// Verify reply checksums independently of the code that generated the reply by checking whether the ones' complement sum is 0xFFFF.
// alice uses 100.64.0.1 and fd7a:115c:a1e0::1 (local), bob uses 100.64.0.2 and fd7a:115c:a1e0::2 (peer), and DNS enables MagicDNS.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine

// MARK: - Test helpers

private let service4 = "100.100.100.100"
private let service6 = "fd7a:115c:a1e0::53"
private let client4 = "100.64.0.1"
private let client6 = "fd7a:115c:a1e0::1"

/// alice's netmap. bob is the only peer, and `DNSConfig` enables MagicDNS. The names are `node1` (local) and `node2` (bob).
private func localNetmap(
    bobAddress: String = "100.64.0.2/32", selfExtra: String = "", dnsConfig: String = #"{"Proxied":true}"#
) throws -> Netmap {
    let selfNode = makeNodeJSON(
        id: 1, key: makeNodeKey(byte: 1), addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], extra: selfExtra)
    let bob = makeNodeJSON(
        id: 2, key: makeNodeKey(byte: 2), addresses: [bobAddress, "fd7a:115c:a1e0::2/128"],
        extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#)
    let json = #"{"Node":\#(selfNode),"Peers":[\#(bob)],"DNSConfig":\#(dnsConfig),"PacketFilter":[]}"#
    let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
    var session = MapSession()
    return try #require(try session.apply(response, receivedAt: wallClockStart).netmap)
}

/// An engine with the netmap applied.
private func makeEngine(applying netmap: Netmap? = nil) throws -> TailnetEngine {
    var engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: clockStart, wallClock: wallClockStart)
    _ = engine.apply(try netmap ?? localNetmap(), at: clockStart, wallClock: wallClockStart)
    return engine
}

/// Extracts one engine output as IP packet bytes. Fails the test if the output is different.
private func reply(_ outputs: [TailnetEngine.Output]) throws -> [UInt8] {
    #expect(outputs.count == 1)
    guard case let .ipPacket(bytes)? = outputs.first else {
        Issue.record("Expected an IP packet, got \(outputs)")
        throw ReplyMissing()
    }
    return bytes
}

private struct ReplyMissing: Error {}

private func isDatagram(_ output: TailnetEngine.Output) -> Bool {
    if case .datagram = output { true } else { false }
}

/// The reply IP packet as parsed directly by the test without `IPPacket`.
private struct ReplyView {
    let version: Int
    let source: [UInt8]
    let destination: [UInt8]
    let protocolNumber: UInt8
    let hopLimit: UInt8
    let headerLength: Int
    let bytes: [UInt8]

    var transport: [UInt8] { Array(bytes[headerLength...]) }

    init(_ bytes: [UInt8]) throws {
        self.bytes = bytes
        version = Int(bytes[0] >> 4)
        if version == 4 {
            headerLength = 20
            protocolNumber = bytes[9]
            hopLimit = bytes[8]
            source = Array(bytes[12..<16])
            destination = Array(bytes[16..<20])
            // The length field equals the byte count, and the sum including the header checksum is 0xFFFF. DF, MF, and offset are 0.
            #expect(Int(bytes[2]) << 8 | Int(bytes[3]) == bytes.count)
            #expect(onesComplementSum(Array(bytes[0..<20])) == 0xFFFF)
            #expect(bytes[6] == 0 && bytes[7] == 0)
        } else {
            headerLength = 40
            protocolNumber = bytes[6]
            hopLimit = bytes[7]
            source = Array(bytes[8..<24])
            destination = Array(bytes[24..<40])
            #expect(Int(bytes[4]) << 8 | Int(bytes[5]) == bytes.count - 40)
        }
    }

    /// Whether the transport checksum is valid, including the pseudo-header. Only ICMPv4 has no pseudo-header.
    var transportChecksumIsValid: Bool {
        let segment = transport
        var message = segment
        if !(version == 4 && protocolNumber == 1) {
            if version == 4 {
                message = source + destination + [0, protocolNumber] + [UInt8(segment.count >> 8), UInt8(segment.count & 0xFF)] + segment
            } else {
                let length = segment.count
                message = source + destination + [0, 0, UInt8(length >> 8), UInt8(length & 0xFF)] + [0, 0, 0, protocolNumber] + segment
            }
        }
        return onesComplementSum(message) == 0xFFFF
    }
}

/// The ones' complement sum of 16-bit big-endian words. A valid message including the checksum field yields 0xFFFF.
private func onesComplementSum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var index = 0
    while index + 1 < bytes.count {
        sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
        index += 2
    }
    if index < bytes.count { sum += UInt32(bytes[index]) << 8 }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
    return UInt16(sum)
}

private func octets(_ text: String) -> [UInt8] {
    TestPacket.address(text)
}

/// Builds a TCP segment for tests with a 20-byte header.
private func tcpSegment(
    from source: String, _ sourcePort: UInt16, to destination: String, _ destinationPort: UInt16,
    sequence: UInt32, acknowledgement: UInt32 = 0, flags: UInt8, payload: [UInt8] = []
) -> [UInt8] {
    func word(_ value: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: value >> (24 - 8 * UInt32($0))) } }
    let header = TestPacket.bigEndian(sourcePort) + TestPacket.bigEndian(destinationPort)
        + word(sequence) + word(acknowledgement) + [0x50, flags, 0xFF, 0xFF, 0, 0, 0, 0]
    return TestPacket.ip(from: source, to: destination, protocolNumber: 6, transport: header + payload)
}

private func uint32(_ bytes: [UInt8], at index: Int) -> UInt32 {
    bytes[index..<index + 4].reduce(0) { $0 << 8 | UInt32($1) }
}

/// Builds a DNS query packet addressed to the service IP.
private func dnsQuery(_ name: String, type: UInt16, from client: String, to service: String, port: UInt16 = 40000, id: UInt16 = 0xBEEF) -> [UInt8] {
    TestPacket.udp(from: client, port, to: service, 53, payload: DNSWire.query(name, type: type, id: id))
}

/// Extracts the UDP payload from a reply packet and parses it as a DNS response.
private func decodeDNS(_ packet: [UInt8]) throws -> DecodedResponse {
    let view = try ReplyView(packet)
    return try DecodedResponse(Array(view.transport[8...]))
}

/// Reads the 32-bit SERIAL from the SOA record data after two names (MNAME, RNAME).
private func soaSerial(_ record: DecodedResponse.Record) -> UInt32 {
    var offset = 0
    for _ in 0..<2 {
        while record.data[offset] != 0 { offset += Int(record.data[offset]) + 1 }
        offset += 1
    }
    return uint32(record.data, at: offset)
}

// MARK: - Service IP over UDP 53

@Suite("Service IP constants")
struct ServiceIPConstantTests {
    @Test("Both service IPs parse and match the DNS servers and routes in the computed settings")
    func constants() throws {
        #expect(ServiceIP.ipv4?.bytes == [100, 100, 100, 100])
        #expect(ServiceIP.ipv6?.bytes == [0xFD, 0x7A, 0x11, 0x5C, 0xA1, 0xE0] + [UInt8](repeating: 0, count: 9) + [0x53])
        let first = try #require(IPAddress(service4))
        let second = try #require(IPAddress(service6))
        let other = try #require(IPAddress("100.100.100.101"))
        #expect(ServiceIP.contains(first) && ServiceIP.contains(second) && !ServiceIP.contains(other))
        let settings = try #require(TunnelNetworkSettings(netmap: try localNetmap(), mtu: 1280, at: wallClockStart))
        #expect(settings.dnsServers == [try #require(ServiceIP.ipv4), try #require(ServiceIP.ipv6)])
        #expect(settings.routes.suffix(2) == [try #require(IPPrefix("\(service4)/32")), try #require(IPPrefix("\(service6)/128"))])
    }
}

@Suite("TailnetEngine local handling of DNS at the service IP")
struct ServiceIPDNSTests {
    @Test("Answer UDP 53 queries with a reply packet that swaps addresses and ports and has a valid checksum", arguments: [false, true])
    func answersQuery(ipv6: Bool) throws {
        // Answer peer AAAA queries for peers that also have IPv4 only when the local node has `magicdns-aaaa` (behavior D3).
        var engine = try makeEngine(applying: localNetmap(selfExtra: #","CapMap":{"magicdns-aaaa":null}"#))
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        let request = dnsQuery("node2.tail0001.ts.net.", type: ipv6 ? 28 : 1, from: client, to: service)

        let packet = try reply(engine.send(request, at: clockStart))
        let view = try ReplyView(packet)
        #expect(view.version == (ipv6 ? 6 : 4))
        #expect(view.source == octets(service))
        #expect(view.destination == octets(client))
        #expect(view.protocolNumber == 17)
        #expect(view.hopLimit == 64)
        let udp = view.transport
        #expect(Array(udp[0..<2]) == TestPacket.bigEndian(53))
        #expect(Array(udp[2..<4]) == TestPacket.bigEndian(40000))
        #expect(Int(udp[4]) << 8 | Int(udp[5]) == udp.count)
        // IPv6 requires a UDP checksum, so compute a nonzero value for IPv4 as well.
        #expect(udp[6] != 0 || udp[7] != 0)
        #expect(view.transportChecksumIsValid)

        let response = try decodeDNS(packet)
        #expect(response.id == 0xBEEF)
        #expect(response.has(0x8000))
        #expect(response.responseCode == 0)
        #expect(response.answer?.data == octets(ipv6 ? "fd7a:115c:a1e0::2" : "100.64.0.2"))
    }

    @Test("Answer queries for the local name and PTR queries for the service IP")
    func answersSelfAndReverse() throws {
        var engine = try makeEngine()
        let selfName = try decodeDNS(try reply(engine.send(dnsQuery("node1.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(selfName.answer?.data == [100, 64, 0, 1])
        let reverse = try decodeDNS(try reply(engine.send(dnsQuery("100.100.100.100.in-addr.arpa.", type: 12, from: client4, to: service4), at: clockStart)))
        #expect(reverse.responseCode == 0)
        #expect(reverse.answer?.type == 12)
    }

    @Test("Names outside the zone get SERVFAIL. Unknown names inside it get NXDOMAIN + SOA. The SOA SERIAL is the engine's wall-clock time")
    func negativeAnswers() throws {
        var engine = try makeEngine()
        let outside = try decodeDNS(try reply(engine.send(dnsQuery("example.com.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(outside.responseCode == 2)

        // The netmap was applied at wallClockStart (1_800_000_000), and 90 seconds have elapsed on the monotonic clock.
        let inside = try decodeDNS(try reply(engine.send(dnsQuery("nobody.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart + .seconds(90))))
        #expect(inside.responseCode == 3)
        #expect(try soaSerial(#require(inside.authority)) == 1_800_000_090)

        // Applying a new netmap moves the reference point.
        _ = engine.apply(try localNetmap(), at: clockStart + .seconds(100), wallClock: wallClockStart + 1_000)
        let later = try decodeDNS(try reply(engine.send(dnsQuery("nobody.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart + .seconds(105))))
        #expect(try soaSerial(#require(later.authority)) == 1_800_001_005)
    }

    @Test("Before the first netmap, node names yield SERVFAIL and only the fixed names for the service IP get answers")
    func beforeNetmap() throws {
        var engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: clockStart, wallClock: wallClockStart)
        let name = try decodeDNS(try reply(engine.send(dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(name.responseCode == 2)
        let fixed = try decodeDNS(try reply(engine.send(dnsQuery("magicdns.localhost-tailscale-daemon.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(fixed.responseCode == 0)
        #expect(fixed.answer?.data == [100, 100, 100, 100])
    }

    @Test("Replies follow the new netmap when it changes")
    func followsNewNetmap() throws {
        var engine = try makeEngine()
        let query = dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart))).answer?.data == [100, 64, 0, 2])

        _ = engine.apply(try localNetmap(bobAddress: "100.64.0.9/32"), at: clockStart, wallClock: wallClockStart)
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart))).answer?.data == [100, 64, 0, 9])

        // Disabling MagicDNS empties the zones, changing unknown names that were inside a zone from NXDOMAIN to SERVFAIL.
        let unknown = dnsQuery("nobody.tail0001.ts.net.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(unknown, at: clockStart))).responseCode == 3)
        _ = engine.apply(try localNetmap(dnsConfig: #"{"Proxied":false}"#), at: clockStart, wallClock: wallClockStart)
        #expect(try decodeDNS(try reply(engine.send(unknown, at: clockStart))).responseCode == 2)
    }

    @Test("Local key expiration makes all names yield SERVFAIL even without a new netmap")
    func selfKeyExpiry() throws {
        // The local key expires at wallClockStart + 60 seconds.
        var engine = try makeEngine(applying: localNetmap(selfExtra: #","KeyExpiry":"2027-01-15T08:01:00Z""#))
        let query = dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart + .seconds(59)))).responseCode == 0)

        // `nextDeadline` includes the expiry time. Calling advance then shuts down the responder.
        #expect(engine.nextDeadline == clockStart + .seconds(60))
        _ = engine.advance(to: clockStart + .seconds(60))
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart + .seconds(60)))).responseCode == 2)
        // The fixed names for the service IP still get answers.
        let fixed = dnsQuery("magicdns.localhost-tailscale-daemon.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(fixed, at: clockStart + .seconds(60)))).responseCode == 0)
    }

    @Test("A netmap with an already expired local node or an expiry marker shuts down the responder immediately")
    func expiredSelfOnApply() throws {
        let query = dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4)
        for extra in [#","KeyExpiry":"2027-01-15T07:59:00Z""#, #","Expired":true"#] {
            var engine = try makeEngine(applying: localNetmap(selfExtra: extra))
            #expect(try decodeDNS(try reply(engine.send(query, at: clockStart))).responseCode == 2, "\(extra)")
        }
    }

    @Test("Drop UDP 53 packets with an invalid length without replying, and answer empty queries with FORMERR")
    func malformedUDP() throws {
        var engine = try makeEngine()
        // The UDP length field exceeds the IP packet length or is less than 8.
        for length: UInt16 in [100, 7, 0] {
            var packet = TestPacket.udp(from: client4, 40000, to: service4, 53, payload: DNSWire.query("a.", type: 1))
            packet[24] = UInt8(length >> 8)
            packet[25] = UInt8(length & 0xFF)
            #expect(engine.send(packet, at: clockStart) == [.dropped(.serviceIPPacket)], "Length \(length)")
        }
        // With no payload there is no 12-byte header, so the reply is FORMERR with ID 0.
        let empty = try reply(engine.send(TestPacket.udp(from: client4, 40000, to: service4, 53, payload: []), at: clockStart))
        let response = try decodeDNS(empty)
        #expect(response.id == 0 && response.responseCode == 1)
        // If the UDP length field is shorter than the IP packet, the trailing bytes are outside the payload.
        var trailing = TestPacket.udp(from: client4, 40000, to: service4, 53, payload: DNSWire.query("node2.tail0001.ts.net.", type: 1) + [1, 2, 3])
        let udpLength = trailing.count - 20 - 3
        trailing[24] = UInt8(udpLength >> 8)
        trailing[25] = UInt8(udpLength & 0xFF)
        #expect(try decodeDNS(try reply(engine.send(trailing, at: clockStart))).answer?.data == [100, 64, 0, 2])
    }
}

// MARK: - Service IP handling of ICMP echo, TCP, and other traffic

@Suite("TailnetEngine local handling of ICMP, TCP, and other traffic at the service IP")
struct ServiceIPOtherTests {
    @Test("Answer ICMP and ICMPv6 echo requests with echo replies", arguments: [false, true])
    func echoReply(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        let body: [UInt8] = [0x12, 0x34, 0x00, 0x07] + Array("ping!".utf8)
        let request = TestPacket.ip(from: client, to: service, protocolNumber: ipv6 ? 58 : 1, transport: [ipv6 ? 128 : 8, 0, 0, 0] + body)

        let packet = try reply(engine.send(request, at: clockStart))
        let view = try ReplyView(packet)
        #expect(view.source == octets(service) && view.destination == octets(client))
        #expect(view.protocolNumber == (ipv6 ? 58 : 1))
        #expect(view.hopLimit == 64)
        #expect(Array(view.transport[0..<2]) == [ipv6 ? 129 : 0, 0])
        #expect(Array(view.transport[4...]) == body)
        #expect(view.transportChecksumIsValid)
    }

    @Test("Drop ICMP traffic other than echo requests without replying")
    func nonEchoICMP() throws {
        var engine = try makeEngine()
        for (client, service, type, code) in [(client4, service4, UInt8(0), UInt8(0)), (client4, service4, 3, 1), (client4, service4, 8, 1), (client6, service6, 129, 0), (client6, service6, 1, 0), (client6, service6, 128, 5)] {
            let packet = TestPacket.icmp(from: client, to: service, type: type, code: code)
            #expect(engine.send(packet, at: clockStart) == [.dropped(.serviceIPPacket)], "type \(type) code \(code)")
        }
    }

    @Test("Answer segments without ACK with RST+ACK, seq 0, and ack = SEQ + LEN (SYN and FIN each count as 1)", arguments: [false, true])
    func resetWithoutACK(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        // (seq, flags, payload byte count, expected ack)
        let cases: [(UInt32, UInt8, Int, UInt32)] = [
            (1000, 0x02, 0, 1001),                  // SYN
            (1000, 0x00, 5, 1005),                  // Data only
            (1000, 0x03, 4, 1006),                  // SYN+FIN+data
            (0xFFFF_FFFF, 0x02, 0, 0),              // SYN: wraps at the end of the sequence number space
            (0xFFFF_FFFE, 0x02, 4, 3),              // Data 4 + SYN 1: 0xFFFFFFFE + 5 = 3
            (0xFFFF_FFF0, 0x01, 0, 0xFFFF_FFF1),    // FIN
        ]
        for (sequence, flags, length, expected) in cases {
            let payload = [UInt8](repeating: 0x5A, count: length)
            let segment = tcpSegment(from: client, 50000, to: service, 8080, sequence: sequence, acknowledgement: 0xAAAA_AAAA, flags: flags, payload: payload)
            // This rule applies only when the ACK bit is unset (ignore the acknowledgement field).
            let view = try ReplyView(try reply(engine.send(segment, at: clockStart)))
            let tcp = view.transport
            #expect(view.source == octets(service) && view.destination == octets(client))
            #expect(view.protocolNumber == 6 && view.hopLimit == 64)
            #expect(Array(tcp[0..<2]) == TestPacket.bigEndian(8080) && Array(tcp[2..<4]) == TestPacket.bigEndian(50000))
            #expect(uint32(tcp, at: 4) == 0, "seq, SYN seq \(sequence)")
            #expect(uint32(tcp, at: 8) == expected, "ack, seq \(sequence) flags \(flags) len \(length)")
            #expect(tcp[12] == 0x50 && tcp[13] == 0x14)  // RST+ACK
            #expect(Array(tcp[14..<16]) == [0, 0] && Array(tcp[18..<20]) == [0, 0])  // Window 0, urgent 0
            #expect(tcp.count == 20)
            #expect(view.transportChecksumIsValid)
        }
    }

    @Test("Answer segments with ACK with only RST and seq = SEG.ACK", arguments: [false, true])
    func resetWithACK(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        for flags: UInt8 in [0x10, 0x12, 0x18, 0x11] {
            let segment = tcpSegment(from: client, 50000, to: service, 22, sequence: 7, acknowledgement: 0xFFFF_FFFF, flags: flags, payload: [1, 2, 3])
            let view = try ReplyView(try reply(engine.send(segment, at: clockStart)))
            let tcp = view.transport
            #expect(uint32(tcp, at: 4) == 0xFFFF_FFFF)
            #expect(uint32(tcp, at: 8) == 0)
            #expect(tcp[13] == 0x04, "flags \(flags)")
            #expect(view.transportChecksumIsValid)
        }
    }

    @Test("RST gets no reply")
    func noResetForReset() throws {
        var engine = try makeEngine()
        for flags: UInt8 in [0x04, 0x14] {
            let segment = tcpSegment(from: client4, 50000, to: service4, 22, sequence: 1, flags: flags)
            #expect(engine.send(segment, at: clockStart) == [.dropped(.serviceIPPacket)])
        }
    }

    @Test("Drop traffic to other UDP ports and traffic using other protocols without replying", arguments: [false, true])
    func otherPacketsAreDropped(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        let packets: [[UInt8]] = [
            TestPacket.udp(from: client, 40000, to: service, 80),
            TestPacket.udp(from: client, 40000, to: service, 5353),
            TestPacket.sctp(from: client, 1, to: service, 2),
            TestPacket.ip(from: client, to: service, protocolNumber: 99, transport: Array("p12345678".utf8)),
            TestPacket.ip(from: client, to: service, protocolNumber: 47, transport: [0, 0, 0, 0]),
            // ICMP numbers for the wrong family, such as 58 in IPv4 and 1 in IPv6, count as other protocols.
            TestPacket.ip(from: client, to: service, protocolNumber: ipv6 ? 1 : 58, transport: [8, 0, 0, 0, 0, 1, 0, 1]),
        ]
        for packet in packets {
            #expect(engine.send(packet, at: clockStart) == [.dropped(.serviceIPPacket)])
        }
    }

    @Test("No packet to the service IP emits a .datagram, even when there is a peer")
    func neverSendsDatagrams() throws {
        var engine = try makeEngine()
        // Service IP traffic stays out of WireGuard even when a peer session exists.
        _ = engine.send(TestPacket.udp(from: client4, 1, to: "100.64.0.2", 7), at: clockStart)
        var random = FuzzRandom(seed: 0x5E7_71CE)
        let protocols: [UInt8] = [1, 6, 17, 58, 99, 132, 47, 4, 2]
        for step in 0..<3_000 {
            let service = step % 2 == 0 ? service4 : service6
            let client = step % 2 == 0 ? client4 : client6
            let transport = random.bytes(Int.random(in: 0...80, using: &random))
            var packet = TestPacket.ip(from: client, to: service, protocolNumber: protocols[step % protocols.count], transport: transport)
            // Build some packets for UDP 53 so they reach the responder.
            if step % 3 == 0, packet[step % 2 == 0 ? 9 : 6] == 17, packet.count >= (step % 2 == 0 ? 24 : 44) {
                let at = step % 2 == 0 ? 22 : 42
                packet[at] = 0
                packet[at + 1] = 53
            }
            for output in engine.send(packet, at: clockStart + .milliseconds(step)) {
                #expect(!isDatagram(output))
            }
            // Truncated packets also cause no throws.
            for output in engine.send(Array(packet.prefix(step % 45)), at: clockStart + .milliseconds(step)) {
                #expect(!isDatagram(output))
            }
        }
    }
}

// MARK: - Local addresses and TSMP

@Suite("TailnetEngine local handling of local addresses and TSMP")
struct SelfAddressTests {
    @Test("Packets to a local address bypass the filter and return with the same bytes", arguments: [false, true])
    func reflectsToSelf(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (source, destination) = ipv6 ? ("fd7a:115c:a1e0::2", client6) : ("100.64.0.2", client4)
        // With no filter rules, these packets would have been blocked as inbound traffic.
        let packets = [
            TestPacket.udp(from: client(ipv6), 1, to: destination, 7),
            tcpSegment(from: client(ipv6), 1, to: destination, 22, sequence: 1, flags: 0x02),
            TestPacket.icmp(from: client(ipv6), to: destination, type: ipv6 ? 128 : 8),
            TestPacket.udp(from: source, 1, to: destination, 7),
        ]
        for packet in packets {
            #expect(engine.send(packet, at: clockStart) == [.ipPacket(packet)])
        }
    }

    private func client(_ ipv6: Bool) -> String { ipv6 ? client6 : client4 }

    @Test("Strip trailing link-layer padding before returning packets sent to a local address")
    func reflectsDeclaredLength() throws {
        var engine = try makeEngine()
        let packet = TestPacket.udp(from: client4, 1, to: client4, 7)
        #expect(engine.send(packet + [0, 0, 0], at: clockStart) == [.ipPacket(packet)])
    }

    @Test("Local addresses are unknown before the netmap. They follow address changes in the netmap")
    func followsNetmap() throws {
        var engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: clockStart, wallClock: wallClockStart)
        let packet = TestPacket.udp(from: client4, 1, to: client4, 7)
        #expect(engine.send(packet, at: clockStart) == [.dropped(.noPeerForDestination)])
        _ = engine.apply(try localNetmap(), at: clockStart, wallClock: wallClockStart)
        #expect(engine.send(packet, at: clockStart) == [.ipPacket(packet)])
        // A netmap without local addresses disables loopback for these packets.
        let moved = makeNodeJSON(id: 1, key: makeNodeKey(byte: 1), addresses: ["100.64.0.77/32"])
        _ = engine.apply(try makeNetmap(selfNode: moved, peers: []), at: clockStart, wallClock: wallClockStart)
        #expect(engine.send(packet, at: clockStart) == [.dropped(.noPeerForDestination)])
    }

    @Test("Drop TSMP from the device regardless of destination, including TSMP sent to a local address")
    func dropsTSMPFromDevice() throws {
        var engine = try makeEngine()
        for destination in ["100.64.0.2", client4, "100.64.0.3"] {
            let tsmp = TestPacket.ip(from: client4, to: destination, protocolNumber: 99, transport: Array("p12345678".utf8))
            #expect(engine.send(tsmp, at: clockStart) == [.dropped(.consumedControlPacket)], "\(destination)")
        }
        let v6 = TestPacket.ip(from: client6, to: "fd7a:115c:a1e0::2", protocolNumber: 99, transport: Array("p12345678".utf8))
        #expect(engine.send(v6, at: clockStart) == [.dropped(.consumedControlPacket)])
    }

    @Test("Packets to a peer still go through WireGuard")
    func peerTrafficUnchanged() throws {
        var engine = try makeEngine()
        let outputs = engine.send(TestPacket.udp(from: client4, 1, to: "100.64.0.2", 7), at: clockStart)
        #expect(outputs.count == 1 && outputs.allSatisfy(isDatagram))
    }

    @Test("Truncated packets to local addresses or the service IP and random bytes cause no crash")
    func fuzz() throws {
        var engine = try makeEngine()
        var random = FuzzRandom(seed: 0x10CA1)
        let destinations = [client4, client6, service4, service6]
        for step in 0..<3_000 {
            let destination = destinations[step % destinations.count]
            let source = destination.contains(":") ? client6 : client4
            var packet = TestPacket.ip(from: source, to: destination, protocolNumber: UInt8.random(in: 0...255, using: &random), transport: random.bytes(Int.random(in: 0...64, using: &random)))
            if step % 5 == 0, !packet.isEmpty { packet[0] = UInt8.random(in: 0...255, using: &random) }
            _ = engine.send(Array(packet.prefix(Int.random(in: 0...packet.count, using: &random))), at: clockStart + .milliseconds(step))
        }
    }
}
