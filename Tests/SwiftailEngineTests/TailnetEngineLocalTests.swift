// 계약 `docs/contracts/SwiftailTunnel.md` 동작 L(로컬 처리)과 동작 D7, 시험 목록 4번.
// 장치에서 읽은 패킷 가운데 서비스 IP·자기 주소·TSMP로 가는 것을 엔진이 WireGuard 없이 처리하는지 본다.
// 응답 패킷의 체크섬은 응답을 만든 코드를 쓰지 않고 시험에서 따로 검증한다(1의 보수 합이 0xFFFF가 되는지).
// alice는 100.64.0.1·fd7a:115c:a1e0::1(자기), bob은 100.64.0.2·fd7a:115c:a1e0::2(피어)이고 DNS는 MagicDNS를 켠다.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine

// MARK: - 시험 도우미

private let service4 = "100.100.100.100"
private let service6 = "fd7a:115c:a1e0::53"
private let client4 = "100.64.0.1"
private let client6 = "fd7a:115c:a1e0::1"

/// alice의 netmap. 피어는 bob 하나이고 `DNSConfig`는 MagicDNS를 켠다. 이름은 `node1`(자기), `node2`(bob)이다.
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

/// netmap을 적용한 엔진.
private func makeEngine(applying netmap: Netmap? = nil) throws -> TailnetEngine {
    var engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), now: clockStart, wallClock: wallClockStart)
    _ = engine.apply(try netmap ?? localNetmap(), at: clockStart, wallClock: wallClockStart)
    return engine
}

/// 엔진이 돌려준 출력 하나를 IP 패킷 바이트로 꺼낸다. 아니면 시험 실패.
private func reply(_ outputs: [TailnetEngine.Output]) throws -> [UInt8] {
    #expect(outputs.count == 1)
    guard case let .ipPacket(bytes)? = outputs.first else {
        Issue.record("IP 패킷이 아니다: \(outputs)")
        throw ReplyMissing()
    }
    return bytes
}

private struct ReplyMissing: Error {}

private func isDatagram(_ output: TailnetEngine.Output) -> Bool {
    if case .datagram = output { true } else { false }
}

/// 응답 IP 패킷을 시험이 직접 읽은 모습. `IPPacket`을 쓰지 않는다.
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
            // 길이 필드가 바이트 수와 같고, 머리 체크섬을 포함한 합이 0xFFFF다. DF·MF·오프셋은 0이다.
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

    /// 전송 계층의 체크섬이 맞다(의사 머리 포함. ICMPv4만 의사 머리가 없다).
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

/// 16비트 빅엔디언 낱말의 1의 보수 합. 체크섬 필드를 포함한 올바른 메시지는 0xFFFF가 된다.
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

/// 시험용 TCP 세그먼트(머리 20바이트).
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

/// 서비스 IP로 보내는 DNS 질의 패킷.
private func dnsQuery(_ name: String, type: UInt16, from client: String, to service: String, port: UInt16 = 40000, id: UInt16 = 0xBEEF) -> [UInt8] {
    TestPacket.udp(from: client, port, to: service, 53, payload: DNSWire.query(name, type: type, id: id))
}

/// 응답 패킷에서 UDP payload를 꺼내 DNS 응답으로 읽는다.
private func decodeDNS(_ packet: [UInt8]) throws -> DecodedResponse {
    let view = try ReplyView(packet)
    return try DecodedResponse(Array(view.transport[8...]))
}

/// SOA 레코드 데이터의 SERIAL: 이름 둘(MNAME, RNAME) 다음의 32비트.
private func soaSerial(_ record: DecodedResponse.Record) -> UInt32 {
    var offset = 0
    for _ in 0..<2 {
        while record.data[offset] != 0 { offset += Int(record.data[offset]) + 1 }
        offset += 1
    }
    return uint32(record.data, at: offset)
}

// MARK: - 서비스 IP: UDP 53

@Suite("서비스 IP 상수")
struct ServiceIPConstantTests {
    @Test("두 서비스 IP는 해석되고, 설정 산출의 DNS 서버·경로와 같은 값이다")
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

@Suite("TailnetEngine 로컬 처리: 서비스 IP의 DNS")
struct ServiceIPDNSTests {
    @Test("UDP 53 질의에 응답 패킷으로 답한다: 주소·포트를 맞바꾸고 체크섬이 맞다", arguments: [false, true])
    func answersQuery(ipv6: Bool) throws {
        // 피어 AAAA는 자기 노드에 `magicdns-aaaa`가 있을 때만 IPv4가 있는 피어에게도 답한다(동작 D3).
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
        // IPv6의 UDP 체크섬은 필수이므로 IPv4도 0이 아닌 값을 계산한다.
        #expect(udp[6] != 0 || udp[7] != 0)
        #expect(view.transportChecksumIsValid)

        let response = try decodeDNS(packet)
        #expect(response.id == 0xBEEF)
        #expect(response.has(0x8000))
        #expect(response.responseCode == 0)
        #expect(response.answer?.data == octets(ipv6 ? "fd7a:115c:a1e0::2" : "100.64.0.2"))
    }

    @Test("자기 이름과 서비스 IP의 PTR에 답한다")
    func answersSelfAndReverse() throws {
        var engine = try makeEngine()
        let selfName = try decodeDNS(try reply(engine.send(dnsQuery("node1.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(selfName.answer?.data == [100, 64, 0, 1])
        let reverse = try decodeDNS(try reply(engine.send(dnsQuery("100.100.100.100.in-addr.arpa.", type: 12, from: client4, to: service4), at: clockStart)))
        #expect(reverse.responseCode == 0)
        #expect(reverse.answer?.type == 12)
    }

    @Test("영역 밖의 이름은 SERVFAIL, 영역 안의 모르는 이름은 NXDOMAIN + SOA. SOA SERIAL은 엔진의 벽시계다")
    func negativeAnswers() throws {
        var engine = try makeEngine()
        let outside = try decodeDNS(try reply(engine.send(dnsQuery("example.com.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(outside.responseCode == 2)

        // wallClockStart(1_800_000_000) 시점에 적용했고, 단조 시각이 90초 지났다.
        let inside = try decodeDNS(try reply(engine.send(dnsQuery("nobody.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart + .seconds(90))))
        #expect(inside.responseCode == 3)
        #expect(try soaSerial(#require(inside.authority)) == 1_800_000_090)

        // 새 netmap을 적용하면 기준점이 옮겨 간다.
        _ = engine.apply(try localNetmap(), at: clockStart + .seconds(100), wallClock: wallClockStart + 1_000)
        let later = try decodeDNS(try reply(engine.send(dnsQuery("nobody.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart + .seconds(105))))
        #expect(try soaSerial(#require(later.authority)) == 1_800_001_005)
    }

    @Test("netmap이 아직 없으면 노드 이름은 SERVFAIL이고 서비스 IP의 고정 이름만 답한다")
    func beforeNetmap() throws {
        var engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), now: clockStart, wallClock: wallClockStart)
        let name = try decodeDNS(try reply(engine.send(dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(name.responseCode == 2)
        let fixed = try decodeDNS(try reply(engine.send(dnsQuery("magicdns.localhost-tailscale-daemon.", type: 1, from: client4, to: service4), at: clockStart)))
        #expect(fixed.responseCode == 0)
        #expect(fixed.answer?.data == [100, 100, 100, 100])
    }

    @Test("netmap이 바뀌면 응답이 새 netmap을 따른다")
    func followsNewNetmap() throws {
        var engine = try makeEngine()
        let query = dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart))).answer?.data == [100, 64, 0, 2])

        _ = engine.apply(try localNetmap(bobAddress: "100.64.0.9/32"), at: clockStart, wallClock: wallClockStart)
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart))).answer?.data == [100, 64, 0, 9])

        // MagicDNS를 끄면 영역이 비어, 영역 안이었던 모르는 이름이 NXDOMAIN에서 SERVFAIL로 바뀐다.
        let unknown = dnsQuery("nobody.tail0001.ts.net.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(unknown, at: clockStart))).responseCode == 3)
        _ = engine.apply(try localNetmap(dnsConfig: #"{"Proxied":false}"#), at: clockStart, wallClock: wallClockStart)
        #expect(try decodeDNS(try reply(engine.send(unknown, at: clockStart))).responseCode == 2)
    }

    @Test("자기 키가 만료되면 새 netmap이 없어도 모든 이름이 SERVFAIL이다")
    func selfKeyExpiry() throws {
        // 자기 키가 wallClockStart + 60초에 만료된다.
        var engine = try makeEngine(applying: localNetmap(selfExtra: #","KeyExpiry":"2027-01-15T08:01:00Z""#))
        let query = dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart + .seconds(59)))).responseCode == 0)

        // 만료 시각이 `nextDeadline`에 들어 있다. 그때 advance를 부르면 응답기가 닫힌다.
        #expect(engine.nextDeadline == clockStart + .seconds(60))
        _ = engine.advance(to: clockStart + .seconds(60))
        #expect(try decodeDNS(try reply(engine.send(query, at: clockStart + .seconds(60)))).responseCode == 2)
        // 서비스 IP의 고정 이름은 계속 답한다.
        let fixed = dnsQuery("magicdns.localhost-tailscale-daemon.", type: 1, from: client4, to: service4)
        #expect(try decodeDNS(try reply(engine.send(fixed, at: clockStart + .seconds(60)))).responseCode == 0)
    }

    @Test("이미 만료된 자기 노드나 만료 표지가 있는 netmap을 받으면 바로 닫힌다")
    func expiredSelfOnApply() throws {
        let query = dnsQuery("node2.tail0001.ts.net.", type: 1, from: client4, to: service4)
        for extra in [#","KeyExpiry":"2027-01-15T07:59:00Z""#, #","Expired":true"#] {
            var engine = try makeEngine(applying: localNetmap(selfExtra: extra))
            #expect(try decodeDNS(try reply(engine.send(query, at: clockStart))).responseCode == 2, "\(extra)")
        }
    }

    @Test("UDP 53의 길이가 맞지 않으면 응답 없이 버리고, 빈 질의에는 FORMERR로 답한다")
    func malformedUDP() throws {
        var engine = try makeEngine()
        // UDP 길이 필드가 IP 패킷보다 길다 / 8보다 짧다.
        for length: UInt16 in [100, 7, 0] {
            var packet = TestPacket.udp(from: client4, 40000, to: service4, 53, payload: DNSWire.query("a.", type: 1))
            packet[24] = UInt8(length >> 8)
            packet[25] = UInt8(length & 0xFF)
            #expect(engine.send(packet, at: clockStart) == [.dropped(.serviceIPPacket)], "길이 \(length)")
        }
        // payload가 없으면 12바이트 머리가 없으므로 ID 0의 FORMERR다.
        let empty = try reply(engine.send(TestPacket.udp(from: client4, 40000, to: service4, 53, payload: []), at: clockStart))
        let response = try decodeDNS(empty)
        #expect(response.id == 0 && response.responseCode == 1)
        // UDP 길이 필드가 IP 패킷보다 짧으면 남는 바이트는 payload가 아니다.
        var trailing = TestPacket.udp(from: client4, 40000, to: service4, 53, payload: DNSWire.query("node2.tail0001.ts.net.", type: 1) + [1, 2, 3])
        let udpLength = trailing.count - 20 - 3
        trailing[24] = UInt8(udpLength >> 8)
        trailing[25] = UInt8(udpLength & 0xFF)
        #expect(try decodeDNS(try reply(engine.send(trailing, at: clockStart))).answer?.data == [100, 64, 0, 2])
    }
}

// MARK: - 서비스 IP: ICMP echo, TCP, 그 밖

@Suite("TailnetEngine 로컬 처리: 서비스 IP의 ICMP·TCP·그 밖")
struct ServiceIPOtherTests {
    @Test("ICMP·ICMPv6 echo request에 echo reply로 답한다", arguments: [false, true])
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

    @Test("echo request가 아닌 ICMP는 응답 없이 버린다")
    func nonEchoICMP() throws {
        var engine = try makeEngine()
        for (client, service, type, code) in [(client4, service4, UInt8(0), UInt8(0)), (client4, service4, 3, 1), (client4, service4, 8, 1), (client6, service6, 129, 0), (client6, service6, 1, 0), (client6, service6, 128, 5)] {
            let packet = TestPacket.icmp(from: client, to: service, type: type, code: code)
            #expect(engine.send(packet, at: clockStart) == [.dropped(.serviceIPPacket)], "type \(type) code \(code)")
        }
    }

    @Test("ACK가 없는 세그먼트에는 seq 0, ack = SEQ + LEN인 RST+ACK로 답한다(SYN·FIN은 1씩)", arguments: [false, true])
    func resetWithoutACK(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        // (seq, flags, payload 바이트 수, 기대 ack)
        let cases: [(UInt32, UInt8, Int, UInt32)] = [
            (1000, 0x02, 0, 1001),                  // SYN
            (1000, 0x00, 5, 1005),                  // 데이터만
            (1000, 0x03, 4, 1006),                  // SYN+FIN+데이터
            (0xFFFF_FFFF, 0x02, 0, 0),              // SYN: 시퀀스 번호 공간을 넘어 순환
            (0xFFFF_FFFE, 0x02, 4, 3),              // 데이터 4 + SYN 1: 0xFFFFFFFE + 5 = 3
            (0xFFFF_FFF0, 0x01, 0, 0xFFFF_FFF1),    // FIN
        ]
        for (sequence, flags, length, expected) in cases {
            let payload = [UInt8](repeating: 0x5A, count: length)
            let segment = tcpSegment(from: client, 50000, to: service, 8080, sequence: sequence, acknowledgement: 0xAAAA_AAAA, flags: flags, payload: payload)
            // ACK 비트가 없는 경우만 이 규칙이다(acknowledgement 필드는 무시된다).
            let view = try ReplyView(try reply(engine.send(segment, at: clockStart)))
            let tcp = view.transport
            #expect(view.source == octets(service) && view.destination == octets(client))
            #expect(view.protocolNumber == 6 && view.hopLimit == 64)
            #expect(Array(tcp[0..<2]) == TestPacket.bigEndian(8080) && Array(tcp[2..<4]) == TestPacket.bigEndian(50000))
            #expect(uint32(tcp, at: 4) == 0, "seq, SYN seq \(sequence)")
            #expect(uint32(tcp, at: 8) == expected, "ack, seq \(sequence) flags \(flags) len \(length)")
            #expect(tcp[12] == 0x50 && tcp[13] == 0x14)  // RST+ACK
            #expect(Array(tcp[14..<16]) == [0, 0] && Array(tcp[18..<20]) == [0, 0])  // 창 0, urgent 0
            #expect(tcp.count == 20)
            #expect(view.transportChecksumIsValid)
        }
    }

    @Test("ACK가 있는 세그먼트에는 seq = SEG.ACK인 RST만으로 답한다", arguments: [false, true])
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

    @Test("RST에는 답하지 않는다")
    func noResetForReset() throws {
        var engine = try makeEngine()
        for flags: UInt8 in [0x04, 0x14] {
            let segment = tcpSegment(from: client4, 50000, to: service4, 22, sequence: 1, flags: flags)
            #expect(engine.send(segment, at: clockStart) == [.dropped(.serviceIPPacket)])
        }
    }

    @Test("다른 UDP 포트와 다른 프로토콜은 응답 없이 버린다", arguments: [false, true])
    func otherPacketsAreDropped(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (client, service) = ipv6 ? (client6, service6) : (client4, service4)
        let packets: [[UInt8]] = [
            TestPacket.udp(from: client, 40000, to: service, 80),
            TestPacket.udp(from: client, 40000, to: service, 5353),
            TestPacket.sctp(from: client, 1, to: service, 2),
            TestPacket.ip(from: client, to: service, protocolNumber: 99, transport: Array("p12345678".utf8)),
            TestPacket.ip(from: client, to: service, protocolNumber: 47, transport: [0, 0, 0, 0]),
            // IPv4 안의 58, IPv6 안의 1처럼 계열이 맞지 않는 ICMP 번호도 그 밖의 프로토콜이다.
            TestPacket.ip(from: client, to: service, protocolNumber: ipv6 ? 1 : 58, transport: [8, 0, 0, 0, 0, 1, 0, 1]),
        ]
        for packet in packets {
            #expect(engine.send(packet, at: clockStart) == [.dropped(.serviceIPPacket)])
        }
    }

    @Test("서비스 IP로 간 어떤 패킷도 .datagram을 내지 않는다(피어가 있어도)")
    func neverSendsDatagrams() throws {
        var engine = try makeEngine()
        // 피어와 세션이 있는 상태에서도 서비스 IP는 WireGuard로 가지 않는다.
        _ = engine.send(TestPacket.udp(from: client4, 1, to: "100.64.0.2", 7), at: clockStart)
        var random = FuzzRandom(seed: 0x5E7_71CE)
        let protocols: [UInt8] = [1, 6, 17, 58, 99, 132, 47, 4, 2]
        for step in 0..<3_000 {
            let service = step % 2 == 0 ? service4 : service6
            let client = step % 2 == 0 ? client4 : client6
            let transport = random.bytes(Int.random(in: 0...80, using: &random))
            var packet = TestPacket.ip(from: client, to: service, protocolNumber: protocols[step % protocols.count], transport: transport)
            // 일부는 UDP 53으로 만들어 응답기까지 간다.
            if step % 3 == 0, packet[step % 2 == 0 ? 9 : 6] == 17, packet.count >= (step % 2 == 0 ? 24 : 44) {
                let at = step % 2 == 0 ? 22 : 42
                packet[at] = 0
                packet[at + 1] = 53
            }
            for output in engine.send(packet, at: clockStart + .milliseconds(step)) {
                #expect(!isDatagram(output))
            }
            // 잘린 패킷도 던지지 않는다.
            for output in engine.send(Array(packet.prefix(step % 45)), at: clockStart + .milliseconds(step)) {
                #expect(!isDatagram(output))
            }
        }
    }
}

// MARK: - 자기 주소와 TSMP

@Suite("TailnetEngine 로컬 처리: 자기 주소와 TSMP")
struct SelfAddressTests {
    @Test("자기 주소로 가는 패킷은 필터를 거치지 않고 같은 바이트로 되돌아온다", arguments: [false, true])
    func reflectsToSelf(ipv6: Bool) throws {
        var engine = try makeEngine()
        let (source, destination) = ipv6 ? ("fd7a:115c:a1e0::2", client6) : ("100.64.0.2", client4)
        // 필터 규칙이 없으므로 받은 패킷이었다면 막혔을 것들이다.
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

    @Test("자기 주소 뒤에 붙은 링크 계층 패딩은 떼고 되돌린다")
    func reflectsDeclaredLength() throws {
        var engine = try makeEngine()
        let packet = TestPacket.udp(from: client4, 1, to: client4, 7)
        #expect(engine.send(packet + [0, 0, 0], at: clockStart) == [.ipPacket(packet)])
    }

    @Test("netmap 전에는 자기 주소를 모른다. netmap이 주소를 바꾸면 따라간다")
    func followsNetmap() throws {
        var engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), now: clockStart, wallClock: wallClockStart)
        let packet = TestPacket.udp(from: client4, 1, to: client4, 7)
        #expect(engine.send(packet, at: clockStart) == [.dropped(.noPeerForDestination)])
        _ = engine.apply(try localNetmap(), at: clockStart, wallClock: wallClockStart)
        #expect(engine.send(packet, at: clockStart) == [.ipPacket(packet)])
        // 자기 주소가 없는 netmap을 받으면 되돌리지 않는다.
        let moved = makeNodeJSON(id: 1, key: makeNodeKey(byte: 1), addresses: ["100.64.0.77/32"])
        _ = engine.apply(try makeNetmap(selfNode: moved, peers: []), at: clockStart, wallClock: wallClockStart)
        #expect(engine.send(packet, at: clockStart) == [.dropped(.noPeerForDestination)])
    }

    @Test("장치에서 온 TSMP는 어디로 가든 버린다. 자기 주소로 가는 것도 되돌리지 않는다")
    func dropsTSMPFromDevice() throws {
        var engine = try makeEngine()
        for destination in ["100.64.0.2", client4, "100.64.0.3"] {
            let tsmp = TestPacket.ip(from: client4, to: destination, protocolNumber: 99, transport: Array("p12345678".utf8))
            #expect(engine.send(tsmp, at: clockStart) == [.dropped(.consumedControlPacket)], "\(destination)")
        }
        let v6 = TestPacket.ip(from: client6, to: "fd7a:115c:a1e0::2", protocolNumber: 99, transport: Array("p12345678".utf8))
        #expect(engine.send(v6, at: clockStart) == [.dropped(.consumedControlPacket)])
    }

    @Test("피어로 가는 패킷은 이전처럼 WireGuard로 간다")
    func peerTrafficUnchanged() throws {
        var engine = try makeEngine()
        let outputs = engine.send(TestPacket.udp(from: client4, 1, to: "100.64.0.2", 7), at: clockStart)
        #expect(outputs.count == 1 && outputs.allSatisfy(isDatagram))
    }

    @Test("자기 주소·서비스 IP로 가는 잘린 패킷과 임의 바이트로 죽지 않는다")
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
