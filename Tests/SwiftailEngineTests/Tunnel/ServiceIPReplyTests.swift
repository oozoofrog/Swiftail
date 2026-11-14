// 서비스 IP 응답 패킷(계약 동작 L2, DNS 노트 4.3)의 시험.
//
// Go 기준값: 임시 Go 프로그램(저장소에 두지 않음)을 `Tools/interop` 모듈에서 `go run`으로 돌려 얻었다.
// - ICMP echo reply: `net/tstun/wrap.go`의 처리와 같다. `packet.Generate`로 만든 요청을 `packet.Parsed.Decode`로
//   읽고 `ICMP4Header()`/`ICMP6Header()` → `ToResponse()` → `packet.Generate(&header, p.Payload())`.
// - UDP 응답: 같은 `net/packet`의 `UDP4Header`/`UDP6Header` → `ToResponse()` → `packet.Generate`.
// - TCP RST: gVisor(`pkg/tcpip/header`)의 `TCP.Encode`와 `PseudoHeaderChecksum`·`CalculateChecksum`으로 만든 20바이트
//   TCP 세그먼트(`tcp.buildTCPHdr`의 방식). gVisor는 IP 머리를 스택의 식별자로 만들어 결정적이지 않으므로 TCP 세그먼트만 견준다.
//   RST의 seq·ack·플래그는 `tcp.replyWithReset`의 규칙을 입력에 적용해 정했다(창 0).
// 도구의 입력은 아래 요청 바이트이고, 요청 IP 식별자(IPv4 0x1234·0xBEEF, IPv6 flow 0x12345·0x54321)는 응답에서 뒤집힌다.

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailEngine

@Suite("서비스 IP 응답: Go 기준값")
struct ServiceIPReplyGoVectorTests {
    static let echo4Request = "450000211234000040013b9b64400005646464640800f8240007000370696e6721"
    static let echo4Reply = "45000021edcb0000400160036464646464400005000000250007000370696e6721"
    static let echo6Request = "60012345000c3a40fd7a115ca1e000000000000000000005fd7a115ca1e00000000000000000005380003f170007000370696e67"
    static let echo6Reply = "600edcba000c3a40fd7a115ca1e000000000000000000053fd7a115ca1e00000000000000000000581003e170007000370696e67"
    static let udp4Request = "45000031beef000040118ebf6440000564646464cfdb0035001dee02abcd01000001000000000000036162630000010001"
    static let udp4Answer = "abcd858000010001000000000361626300000100010378"
    static let udp4Reply = "450000334110000040110c9d64646464644000050035cfdb001ff179abcd858000010001000000000361626300000100010378"
    static let udp6Request = "60054321001d1140fd7a115ca1e000000000000000000005fd7a115ca1e000000000000000000053cfdb0035001d9e49abcd010000010000000000000361626300001c0001"
    static let udp6Answer = "abcd858000010001000000000361626300001c000103"
    static let udp6Reply = "600abcde001e1140fd7a115ca1e000000000000000000053fd7a115ca1e0000000000000000000050035cfdb001e19c3abcd858000010001000000000361626300001c000103"
    /// 서비스 IP(출발)에서 클라이언트(도착)로 가는 RST의 TCP 세그먼트.
    static let rst4Syn = "00509c40000000000000abce501400003a640000"
    static let rst6Syn = "00509c40000000000000abce5014000005ab0000"
    static let rst4Ack = "00509c40112233440000000050040000a1dc0000"
    static let rst6Ack = "00509c401122334400000000500400006d230000"

    @Test("ICMPv4 echo reply가 Go의 응답과 바이트까지 같다")
    func echo4() throws {
        let reply = try #require(ServiceIPReply.icmpEchoReply(inReplyTo: ReplyFixture.parse(ReplyFixture.bytes(hex: Self.echo4Request))))
        #expect(reply == ReplyFixture.bytes(hex: Self.echo4Reply))
    }

    @Test("ICMPv6 echo reply가 Go의 응답과 바이트까지 같다")
    func echo6() throws {
        let reply = try #require(ServiceIPReply.icmpEchoReply(inReplyTo: ReplyFixture.parse(ReplyFixture.bytes(hex: Self.echo6Request))))
        #expect(reply == ReplyFixture.bytes(hex: Self.echo6Reply))
    }

    @Test("IPv4 UDP 응답이 Go의 응답과 바이트까지 같다")
    func udp4() throws {
        let request = try ReplyFixture.parse(ReplyFixture.bytes(hex: Self.udp4Request))
        let reply = try #require(ServiceIPReply.udp(payload: ReplyFixture.bytes(hex: Self.udp4Answer), inReplyTo: request))
        #expect(reply == ReplyFixture.bytes(hex: Self.udp4Reply))
    }

    @Test("IPv6 UDP 응답이 Go의 응답과 바이트까지 같다")
    func udp6() throws {
        let request = try ReplyFixture.parse(ReplyFixture.bytes(hex: Self.udp6Request))
        let reply = try #require(ServiceIPReply.udp(payload: ReplyFixture.bytes(hex: Self.udp6Answer), inReplyTo: request))
        #expect(reply == ReplyFixture.bytes(hex: Self.udp6Reply))
    }

    @Test("TCP RST의 세그먼트가 gVisor가 만드는 것과 같다(SYN에 대한 RST+ACK, ACK에 대한 RST)")
    func tcpResetSegments() throws {
        let cases: [(client: String, service: String, name: String, request: [UInt8], expected: String)] = [
            ("100.64.0.5", "100.100.100.100", "IPv4 SYN",
             ReplyFixture.tcpRequest(from: "100.64.0.5", 40000, to: "100.100.100.100", 80, sequence: 0xABCD, flags: 0x02), Self.rst4Syn),
            ("fd7a:115c:a1e0::5", "fd7a:115c:a1e0::53", "IPv6 SYN",
             ReplyFixture.tcpRequest(from: "fd7a:115c:a1e0::5", 40000, to: "fd7a:115c:a1e0::53", 80, sequence: 0xABCD, flags: 0x02), Self.rst6Syn),
            ("100.64.0.5", "100.100.100.100", "IPv4 ACK",
             ReplyFixture.tcpRequest(from: "100.64.0.5", 40000, to: "100.100.100.100", 80, sequence: 7, acknowledgement: 0x1122_3344, flags: 0x10), Self.rst4Ack),
            ("fd7a:115c:a1e0::5", "fd7a:115c:a1e0::53", "IPv6 ACK",
             ReplyFixture.tcpRequest(from: "fd7a:115c:a1e0::5", 40000, to: "fd7a:115c:a1e0::53", 80, sequence: 7, acknowledgement: 0x1122_3344, flags: 0x10), Self.rst6Ack),
        ]
        for (client, service, name, request, expected) in cases {
            let reply = try #require(ServiceIPReply.tcpReset(inReplyTo: ReplyFixture.parse(request)), "\(name)")
            let decoded = try ReplyFixture.Decoded(reply)
            #expect(decoded.transport == ReplyFixture.bytes(hex: expected), "\(name)")
            // IP 머리의 주소는 요청의 맞바꿈이다.
            let serviceAddress = try ReplyFixture.ip(service).bytes
            let clientAddress = try ReplyFixture.ip(client).bytes
            #expect(decoded.source == serviceAddress && decoded.destination == clientAddress, "\(name)")
        }
    }
}

/// 두 주소 계열에서 같은 시험을 돌리는 입력.
private let families: [(name: String, client: String, service: String)] = [
    ("IPv4", "100.64.0.5", "100.100.100.100"),
    ("IPv6", "fd7a:115c:a1e0::5", "fd7a:115c:a1e0::53"),
]

@Suite("서비스 IP 응답: UDP")
struct ServiceIPReplyUDPTests {
    @Test("주소와 포트가 맞바뀌고 길이 필드와 체크섬이 맞다")
    func swapsEndpoints() throws {
        for (name, client, service) in families {
            let payload: [UInt8] = Array(0..<37)
            let request = try ReplyFixture.parse(TestPacket.udp(from: client, 53211, to: service, 53, payload: [1, 2, 3]))
            let reply = try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: payload, inReplyTo: request)))
            #expect(reply.protocolNumber == 17, "\(name)")
            let serviceBytes = try ReplyFixture.ip(service).bytes
            let clientBytes = try ReplyFixture.ip(client).bytes
            #expect(reply.source == serviceBytes && reply.destination == clientBytes, "\(name)")
            #expect(reply.hopLimit == 64, "\(name)")
            #expect(reply.word(0) == 53 && reply.word(2) == 53211, "\(name) 포트")
            #expect(Int(reply.word(4)) == reply.transport.count && reply.transport.count == 8 + payload.count, "\(name) 길이 필드")
            #expect(Array(reply.transport[8...]) == payload, "\(name)")
            #expect(reply.word(6) != 0 && reply.transportChecksumIsValid, "\(name) 체크섬")
        }
    }

    @Test("응답이 다시 IPPacket으로 해석되고 포트가 맞바뀌어 있다")
    func replyParses() throws {
        for (name, client, service) in families {
            let request = try ReplyFixture.parse(TestPacket.udp(from: client, 40001, to: service, 53))
            let reply = try ReplyFixture.parse(#require(ServiceIPReply.udp(payload: [9], inReplyTo: request)))
            #expect(reply.transportProtocol == .udp && reply.sourcePort == 53 && reply.destinationPort == 40001, "\(name)")
            #expect(reply.source == request.destination && reply.destination == request.source, "\(name)")
        }
    }

    @Test("IP 식별자·flow label은 요청 값의 비트를 뒤집고, 요청의 IPv4 옵션과 IPv6 traffic class는 옮기지 않는다")
    func identificationAndHeaderOptions() throws {
        // IPv4: 식별자 0 → 0xFFFF. 옵션(NOP 4개)이 있는 요청도 20바이트 머리의 응답을 받는다.
        let plain = try ReplyFixture.parse(TestPacket.udp(from: "100.64.0.5", 1, to: "100.100.100.100", 53))
        let v4 = try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: [], inReplyTo: plain)))
        #expect(v4.identification == 0xFFFF)
        let withOptions = try ReplyFixture.parse(TestPacket.ipv4(
            from: "100.64.0.5", to: "100.100.100.100", protocolNumber: 17,
            transport: [0, 1, 0, 53, 0, 8, 0, 0], options: [1, 1, 1, 1]))
        let optionReply = try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: [7], inReplyTo: withOptions)))
        #expect(optionReply.transport.count == 9 && optionReply.transportChecksumIsValid)

        // IPv6: flow label 0 → 0xFFFFF, traffic class 0xAB·flow 0x12345 → traffic class 0·flow 0xEDCBA.
        let flowZero = try ReplyFixture.parse(TestPacket.udp(from: "fd7a:115c:a1e0::5", 1, to: "fd7a:115c:a1e0::53", 53))
        #expect(try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: [], inReplyTo: flowZero))).identification == 0xFFFFF)
        var classed = TestPacket.udp(from: "fd7a:115c:a1e0::5", 1, to: "fd7a:115c:a1e0::53", 53)
        classed.replaceSubrange(0..<4, with: [0x6A, 0xB1, 0x23, 0x45])
        let classedReply = try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: [], inReplyTo: ReplyFixture.parse(classed))))
        #expect(classedReply.identification == 0xEDCBA)
    }

    @Test("빈 payload와 홀수·큰 payload의 체크섬")
    func payloadShapes() throws {
        for (name, client, service) in families {
            let request = try ReplyFixture.parse(TestPacket.udp(from: client, 1, to: service, 53))
            for count in [0, 1, 2, 511, 512, 1001, 1200] {
                let payload = (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) }
                let reply = try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: payload, inReplyTo: request)))
                #expect(reply.transport.count == 8 + count && reply.transportChecksumIsValid, "\(name) \(count)")
            }
        }
    }

    @Test("계산한 체크섬이 0이면 0xFFFF로 쓴다")
    func zeroChecksumBecomesAllOnes() throws {
        for (name, client, service) in families {
            let request = try ReplyFixture.parse(TestPacket.udp(from: client, 1000, to: service, 53))
            // 마지막 낱말을 정해 합이 0xFFFF(계산 결과 0)가 되게 한다: 나머지의 합을 S라 하면 낱말은 ~S다.
            var payload: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0, 0]
            let udp = TestPacket.bigEndian(53) + TestPacket.bigEndian(1000) + TestPacket.bigEndian(UInt16(8 + payload.count)) + [0, 0] + payload
            let pseudo = try ReplyFixture.pseudoHeader(
                source: ReplyFixture.ip(service).bytes, destination: ReplyFixture.ip(client).bytes, protocolNumber: 17, length: udp.count)
            let rest = ReplyFixture.onesComplementSum(pseudo + udp)
            payload.replaceSubrange(4..<6, with: TestPacket.bigEndian(~rest))

            let reply = try ReplyFixture.Decoded(#require(ServiceIPReply.udp(payload: payload, inReplyTo: request)))
            #expect(reply.word(6) == 0xFFFF, "\(name)")
            #expect(reply.transportChecksumIsValid, "\(name)")
        }
    }

    @Test("패킷 하나에 들어가지 않으면 nil: IPv4는 65,507바이트, IPv6는 65,527바이트까지")
    func sizeLimits() throws {
        let v4 = try ReplyFixture.parse(TestPacket.udp(from: "100.64.0.5", 1, to: "100.100.100.100", 53))
        let fits4 = try #require(ServiceIPReply.udp(payload: [UInt8](repeating: 0xA5, count: 65_507), inReplyTo: v4))
        #expect(fits4.count == 65_535)
        #expect(try ReplyFixture.Decoded(fits4).transportChecksumIsValid)
        #expect(ServiceIPReply.udp(payload: [UInt8](repeating: 0, count: 65_508), inReplyTo: v4) == nil)

        let v6 = try ReplyFixture.parse(TestPacket.udp(from: "fd7a:115c:a1e0::5", 1, to: "fd7a:115c:a1e0::53", 53))
        let fits6 = try #require(ServiceIPReply.udp(payload: [UInt8](repeating: 0xA5, count: 65_527), inReplyTo: v6))
        #expect(fits6.count == 40 + 65_535)
        #expect(try ReplyFixture.Decoded(fits6).transportChecksumIsValid)
        #expect(ServiceIPReply.udp(payload: [UInt8](repeating: 0, count: 65_528), inReplyTo: v6) == nil)
    }

    @Test("UDP가 아닌 요청에는 만들지 않는다")
    func rejectsNonUDP() throws {
        for (name, client, service) in families {
            let tcp = try ReplyFixture.parse(ReplyFixture.tcpRequest(from: client, 1, to: service, 53, sequence: 1, flags: 0x02))
            let echo = try ReplyFixture.parse(ReplyFixture.echoRequest(from: client, to: service, body: [0, 1, 0, 1]))
            #expect(ServiceIPReply.udp(payload: [1], inReplyTo: tcp) == nil, "\(name)")
            #expect(ServiceIPReply.udp(payload: [1], inReplyTo: echo) == nil, "\(name)")
        }
    }
}

@Suite("서비스 IP 응답: ICMP echo")
struct ServiceIPReplyEchoTests {
    @Test("echo reply는 identifier·sequence·payload를 그대로 돌려주고 주소를 맞바꾼다")
    func echoesPayload() throws {
        for (name, client, service) in families {
            let isIPv4 = client == "100.64.0.5"
            let body: [UInt8] = [0xBE, 0xEF, 0x01, 0x02] + (0..<31).map { UInt8($0) }
            let request = try ReplyFixture.parse(ReplyFixture.echoRequest(from: client, to: service, body: body))
            let reply = try ReplyFixture.Decoded(#require(ServiceIPReply.icmpEchoReply(inReplyTo: request)))
            #expect(reply.protocolNumber == (isIPv4 ? 1 : 58), "\(name)")
            let serviceBytes = try ReplyFixture.ip(service).bytes
            let clientBytes = try ReplyFixture.ip(client).bytes
            #expect(reply.source == serviceBytes && reply.destination == clientBytes, "\(name)")
            #expect(reply.hopLimit == 64, "\(name)")
            #expect(reply.transport[0] == (isIPv4 ? 0 : 129) && reply.transport[1] == 0, "\(name) type·code")
            #expect(Array(reply.transport[4...]) == body, "\(name) identifier·sequence·payload")
            #expect(reply.transportChecksumIsValid, "\(name)")
            // 식별자(flow label)는 요청의 0에서 뒤집힌다.
            #expect(reply.identification == (isIPv4 ? 0xFFFF : 0xFFFFF), "\(name)")
        }
    }

    @Test("payload 없는 echo(머리 8바이트)와 홀수·큰 payload")
    func shapes() throws {
        for (name, client, service) in families {
            for dataCount in [0, 1, 2, 56, 1001, 1400] {
                let body: [UInt8] = [0, 9, 0, 3] + (0..<dataCount).map { UInt8(truncatingIfNeeded: $0 &* 13) }
                let request = try ReplyFixture.parse(ReplyFixture.echoRequest(from: client, to: service, body: body))
                let reply = try ReplyFixture.Decoded(#require(ServiceIPReply.icmpEchoReply(inReplyTo: request)))
                #expect(Array(reply.transport[4...]) == body && reply.transportChecksumIsValid, "\(name) \(dataCount)")
            }
        }
    }

    @Test("패킷 길이 한도의 요청에도 넘침 없이 답한다")
    func maximumSize() throws {
        // IPv4: 머리 20 + ICMP 머리 4 + body 65,511 = 65,535. IPv6: ICMP 머리 4 + body 65,531 = payload 65,535.
        let body4 = [UInt8](repeating: 0xFF, count: 65_535 - 20 - 4)
        let reply4 = try #require(ServiceIPReply.icmpEchoReply(inReplyTo: ReplyFixture.parse(ReplyFixture.echoRequest(from: "100.64.0.5", to: "100.100.100.100", body: body4))))
        #expect(reply4.count == 65_535)
        #expect(try ReplyFixture.Decoded(reply4).transportChecksumIsValid)

        let body6 = [UInt8](repeating: 0xFF, count: 65_535 - 4)
        let reply6 = try #require(ServiceIPReply.icmpEchoReply(inReplyTo: ReplyFixture.parse(ReplyFixture.echoRequest(from: "fd7a:115c:a1e0::5", to: "fd7a:115c:a1e0::53", body: body6))))
        #expect(reply6.count == 40 + 65_535)
        #expect(try ReplyFixture.Decoded(reply6).transportChecksumIsValid)
    }

    @Test("echo request가 아닌 ICMP에는 답하지 않는다")
    func ignoresOtherICMP() throws {
        let body: [UInt8] = [0, 1, 0, 1]
        // IPv4: code가 0이 아닌 echo request, echo reply, unreachable, timestamp.
        for (type, code) in [(8, 1), (0, 0), (3, 1), (13, 0), (255, 0)] as [(UInt8, UInt8)] {
            let request = try ReplyFixture.parse(ReplyFixture.echoRequest(from: "100.64.0.5", to: "100.100.100.100", body: body, type: type, code: code))
            #expect(ServiceIPReply.icmpEchoReply(inReplyTo: request) == nil, "v4 type \(type) code \(code)")
        }
        // IPv6: code가 0이 아닌 echo request, echo reply, neighbor solicitation, router solicitation, unreachable.
        for (type, code) in [(128, 1), (129, 0), (135, 0), (133, 0), (1, 0)] as [(UInt8, UInt8)] {
            let request = try ReplyFixture.parse(ReplyFixture.echoRequest(from: "fd7a:115c:a1e0::5", to: "fd7a:115c:a1e0::53", body: body, type: type, code: code))
            #expect(ServiceIPReply.icmpEchoReply(inReplyTo: request) == nil, "v6 type \(type) code \(code)")
        }
        // IPv4에 실린 ICMPv6 번호(58)와 IPv6에 실린 ICMPv4 번호(1)는 ICMP로 보지 않는다.
        let crossed4 = try ReplyFixture.parse(TestPacket.ip(from: "100.64.0.5", to: "100.100.100.100", protocolNumber: 58, transport: [128, 0, 0, 0, 0, 1, 0, 1]))
        #expect(ServiceIPReply.icmpEchoReply(inReplyTo: crossed4) == nil)
        let crossed6 = try ReplyFixture.parse(TestPacket.ip(from: "fd7a:115c:a1e0::5", to: "fd7a:115c:a1e0::53", protocolNumber: 1, transport: [8, 0, 0, 0, 0, 1, 0, 1]))
        #expect(ServiceIPReply.icmpEchoReply(inReplyTo: crossed6) == nil)
    }

    @Test("ICMP가 아닌 요청에는 만들지 않는다")
    func rejectsNonICMP() throws {
        for (name, client, service) in families {
            let udp = try ReplyFixture.parse(TestPacket.udp(from: client, 1, to: service, 53))
            let tcp = try ReplyFixture.parse(ReplyFixture.tcpRequest(from: client, 1, to: service, 53, sequence: 1, flags: 0x02))
            #expect(ServiceIPReply.icmpEchoReply(inReplyTo: udp) == nil, "\(name)")
            #expect(ServiceIPReply.icmpEchoReply(inReplyTo: tcp) == nil, "\(name)")
        }
    }
}

@Suite("서비스 IP 응답: TCP RST")
struct ServiceIPReplyResetTests {
    private static let syn: UInt8 = 0x02, fin: UInt8 = 0x01, rst: UInt8 = 0x04, ack: UInt8 = 0x10

    /// 요청을 만들어 RST를 얻고, 시험 쪽에서 읽은 TCP 머리 필드를 돌려준다.
    private func reset(
        _ family: (name: String, client: String, service: String), sequence: UInt32, acknowledgement: UInt32 = 0, flags: UInt8,
        options: [UInt8] = [], payload: [UInt8] = [], ports: (UInt16, UInt16) = (40000, 80)
    ) throws -> (seq: UInt32, ack: UInt32, flags: UInt8) {
        let request = ReplyFixture.tcpRequest(
            from: family.client, ports.0, to: family.service, ports.1, sequence: sequence, acknowledgement: acknowledgement,
            flags: flags, options: options, payload: payload)
        let reply = try ReplyFixture.Decoded(#require(ServiceIPReply.tcpReset(inReplyTo: ReplyFixture.parse(request)), "\(family.name)"))
        #expect(reply.protocolNumber == 6 && reply.hopLimit == 64, "\(family.name)")
        let serviceBytes = try ReplyFixture.ip(family.service).bytes
        let clientBytes = try ReplyFixture.ip(family.client).bytes
        #expect(reply.source == serviceBytes && reply.destination == clientBytes, "\(family.name) 주소")
        #expect(reply.transport.count == 20, "\(family.name) 옵션 없는 머리, payload 없음")
        #expect(reply.word(0) == ports.1 && reply.word(2) == ports.0, "\(family.name) 포트")
        #expect(reply.transport[12] == 0x50, "\(family.name) data offset 5")
        #expect(reply.word(14) == 0 && reply.word(18) == 0, "\(family.name) 창 0, urgent 0")
        #expect(reply.transportChecksumIsValid, "\(family.name) 체크섬")
        return (reply.long(4), reply.long(8), reply.transport[13])
    }

    @Test("ACK가 없으면 seq 0, ack = SEG.SEQ + SEG.LEN(SYN은 1), RST+ACK")
    func withoutACK() throws {
        for family in families {
            let syn = try reset(family, sequence: 0x1000, flags: Self.syn)
            #expect(syn.seq == 0 && syn.ack == 0x1001 && syn.flags == Self.rst | Self.ack, "\(family.name) SYN")
            let data = try reset(family, sequence: 0x1000, flags: 0, payload: [UInt8](repeating: 1, count: 100))
            #expect(data.seq == 0 && data.ack == 0x1000 + 100 && data.flags == 0x14, "\(family.name) payload")
            let fin = try reset(family, sequence: 0x1000, flags: Self.fin)
            #expect(fin.ack == 0x1001, "\(family.name) FIN")
            let both = try reset(family, sequence: 0x1000, flags: Self.syn | Self.fin, payload: [1, 2, 3])
            #expect(both.ack == 0x1000 + 3 + 2, "\(family.name) SYN+FIN+payload")
            // 요청의 ack 필드는 ACK 플래그가 없으면 보지 않는다.
            let ignoredAck = try reset(family, sequence: 5, acknowledgement: 0xDEAD_BEEF, flags: Self.syn)
            #expect(ignoredAck.seq == 0 && ignoredAck.ack == 6, "\(family.name)")
        }
    }

    @Test("ACK가 있으면 seq = SEG.ACK, RST만, ack 0")
    func withACK() throws {
        for family in families {
            for (label, flags, payload) in [("ACK", Self.ack, []), ("SYN+ACK", Self.syn | Self.ack, []), ("FIN+ACK", Self.fin | Self.ack, []), ("데이터", Self.ack, [UInt8](repeating: 9, count: 40))] as [(String, UInt8, [UInt8])] {
                let result = try reset(family, sequence: 7, acknowledgement: 0x1122_3344, flags: flags, payload: payload)
                #expect(result.seq == 0x1122_3344 && result.ack == 0 && result.flags == Self.rst, "\(family.name) \(label)")
            }
            let zeroAck = try reset(family, sequence: 7, acknowledgement: 0, flags: Self.ack)
            #expect(zeroAck.seq == 0 && zeroAck.flags == Self.rst, "\(family.name) ACK 0")
            let maxAck = try reset(family, sequence: 7, acknowledgement: .max, flags: Self.ack)
            #expect(maxAck.seq == .max, "\(family.name) ACK 최대")
        }
    }

    @Test("SEG.SEQ + SEG.LEN이 UInt32를 넘치면 순환한다")
    func wrapsAround() throws {
        for family in families {
            #expect(try reset(family, sequence: 0xFFFF_FFFE, flags: 0, payload: [1, 2, 3]).ack == 1, "\(family.name) payload")
            #expect(try reset(family, sequence: 0xFFFF_FFFF, flags: Self.syn).ack == 0, "\(family.name) SYN")
            #expect(try reset(family, sequence: 0xFFFF_FFFB, flags: Self.syn | Self.fin, payload: [1, 2, 3]).ack == 0, "\(family.name) SYN+FIN+payload")
            #expect(try reset(family, sequence: .max, flags: 0).ack == .max, "\(family.name) 길이 0")
        }
    }

    @Test("TCP 옵션은 payload 길이에 들지 않는다")
    func optionsAreNotPayload() throws {
        // data offset 8(옵션 12바이트): NOP 열둘. payload는 5바이트다.
        for family in families {
            let result = try reset(family, sequence: 100, flags: 0, options: [UInt8](repeating: 1, count: 12), payload: [1, 2, 3, 4, 5])
            #expect(result.ack == 105, "\(family.name)")
            let syn = try reset(family, sequence: 100, flags: Self.syn, options: [2, 4, 5, 0xB4])
            #expect(syn.ack == 101, "\(family.name) MSS 옵션이 있는 SYN")
        }
    }

    @Test("어느 포트의 세그먼트에도 포트를 맞바꿔 답한다")
    func anyPort() throws {
        for family in families {
            for ports in [(1, 53), (50000, 53), (443, 8080), (0, 0), (65535, 65535)] as [(UInt16, UInt16)] {
                _ = try reset(family, sequence: 1, flags: Self.syn, ports: ports)
            }
        }
    }

    @Test("RST에는 답하지 않는다")
    func ignoresReset() throws {
        for (name, client, service) in families {
            for flags in [Self.rst, Self.rst | Self.ack, Self.rst | Self.syn, Self.rst | Self.fin | Self.ack] {
                let request = try ReplyFixture.parse(ReplyFixture.tcpRequest(from: client, 1, to: service, 80, sequence: 1, acknowledgement: 2, flags: flags))
                #expect(ServiceIPReply.tcpReset(inReplyTo: request) == nil, "\(name) flags \(flags)")
            }
        }
    }

    @Test("TCP가 아닌 요청에는 만들지 않는다")
    func rejectsNonTCP() throws {
        for (name, client, service) in families {
            let udp = try ReplyFixture.parse(TestPacket.udp(from: client, 1, to: service, 53))
            let echo = try ReplyFixture.parse(ReplyFixture.echoRequest(from: client, to: service, body: [0, 1, 0, 1]))
            let sctp = try ReplyFixture.parse(TestPacket.sctp(from: client, 1, to: service, 2))
            #expect(ServiceIPReply.tcpReset(inReplyTo: udp) == nil, "\(name)")
            #expect(ServiceIPReply.tcpReset(inReplyTo: echo) == nil, "\(name)")
            #expect(ServiceIPReply.tcpReset(inReplyTo: sctp) == nil, "\(name)")
        }
    }
}

@Suite("서비스 IP 응답: 체크섬 계산")
struct TransportChecksumTests {
    @Test("RFC 1071 3절의 고정 벡터와 홀수 길이")
    func knownVectors() {
        // RFC 1071 3절: 00 01 f2 03 f4 f5 f6 f7의 합은 0xddf2이고 보수는 0x220d다.
        #expect(TransportChecksum.internetChecksum(of: [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]) == 0x220D)
        // 홀수 길이는 마지막에 0을 덧붙여 센다.
        #expect(TransportChecksum.internetChecksum(of: [0x12, 0x34, 0x56]) == ~UInt16(0x1234 + 0x5600))
        #expect(TransportChecksum.internetChecksum(of: []) == 0xFFFF)
        // 올림이 여러 번 일어나는 입력: 0xFFFF가 많으면 합은 0xFFFF로 접힌다.
        #expect(TransportChecksum.internetChecksum(of: [UInt8](repeating: 0xFF, count: 70_000)) == 0)
    }

    @Test("독립 구현과 임의 입력에서 같다")
    func matchesIndependentSum() {
        var random = FuzzRandom(seed: 11)
        for length in [0, 1, 2, 3, 20, 63, 1500, 65_535] {
            let bytes = random.bytes(length)
            #expect(TransportChecksum.internetChecksum(of: bytes) == ~ReplyFixture.onesComplementSum(bytes), "길이 \(length)")
        }
    }
}
