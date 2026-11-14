// 계약 동작 6: 필터 규칙 변환과 판정. 노트(netmap-engine.md) 7절 3~6의 항목.
// 자기 주소는 100.64.0.1과 fd7a:115c:a1e0::1, 피어는 100.64.0.2와 fd7a:115c:a1e0::2다.

import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("패킷 필터")
struct PacketFilterTests {
    static let local = ["100.64.0.1", "fd7a:115c:a1e0::1"]
    static let peer4 = "100.64.0.2"
    static let peer6 = "fd7a:115c:a1e0::2"

    /// 규칙 JSON과 자기 주소로 만든 필터.
    private func filter(_ rulesJSON: String) throws -> PacketFilter {
        PacketFilter(rules: try decodeFilterRules(rulesJSON), localAddresses: Self.local.compactMap(IPAddress.init))
    }

    /// 한 출발지에서 한 목적지 포트로 열어 주는 규칙.
    private func rule(src: String, dst: String = "*", ports: String = #"{"First":0,"Last":65535}"#, proto: String = "") -> String {
        #"{"SrcIPs":["\#(src)"],"DstPorts":[{"IP":"\#(dst)","Ports":\#(ports)}]\#(proto)}"#
    }

    private func verdict(_ filter: inout PacketFilter, _ bytes: [UInt8]) throws -> PacketFilter.Verdict {
        filter.checkInbound(try IPPacket(parsing: bytes))
    }

    private func udp(from source: String, _ sourcePort: UInt16 = 40000, to destination: String = "100.64.0.1", _ destinationPort: UInt16 = 7) -> [UInt8] {
        TestPacket.udp(from: source, sourcePort, to: destination, destinationPort)
    }

    private func syn(from source: String, to destination: String = "100.64.0.1", _ port: UInt16 = 22) -> [UInt8] {
        TestPacket.tcp(from: source, 50000, to: destination, port, flags: 0x02)
    }

    // MARK: - 주소 표현

    @Test("`*`는 IPv4와 IPv6의 모든 출발지")
    func wildcard() throws {
        var filter = try filter("[\(rule(src: "*"))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, udp(from: "10.1.2.3")) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .accept)
    }

    @Test("CIDR 출발지는 그 안의 주소만")
    func cidrSource() throws {
        var filter = try filter("[\(rule(src: "100.64.0.0/30"))]")
        #expect(try verdict(&filter, udp(from: "100.64.0.3")) == .accept)
        #expect(try verdict(&filter, udp(from: "100.64.0.4")) == .drop(.noRuleMatched))
        // IPv4 규칙은 IPv6 패킷에 맞지 않는다.
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))
    }

    @Test("단일 주소 출발지")
    func singleAddressSource() throws {
        var filter = try filter("[\(rule(src: Self.peer6))]")
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .accept)
        #expect(try verdict(&filter, udp(from: "fd7a:115c:a1e0::3", to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))
    }

    @Test("a-b 범위는 양 끝을 포함한다")
    func rangeSource() throws {
        var filter = try filter("[\(rule(src: "100.64.0.2-100.64.0.5")),\(rule(src: "fd7a:115c:a1e0::2-fd7a:115c:a1e0::ff"))]")
        for (source, expected) in [("100.64.0.1", false), ("100.64.0.2", true), ("100.64.0.5", true), ("100.64.0.6", false)] {
            #expect(try verdict(&filter, udp(from: source)) == (expected ? .accept : .drop(.noRuleMatched)), "\(source)")
        }
        #expect(try verdict(&filter, udp(from: "fd7a:115c:a1e0::ff", to: "fd7a:115c:a1e0::1")) == .accept)
        #expect(try verdict(&filter, udp(from: "fd7a:115c:a1e0::100", to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))
    }

    @Test("아주 넓은 범위도 풀지 않고 그대로 견준다")
    func hugeRanges() throws {
        var filter = try filter("[\(rule(src: "0.0.0.1-255.255.255.254")),\(rule(src: "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .accept)
    }

    @Test("목적지 표현도 같은 규칙으로 해석한다. 자기 주소가 아닌 목적지는 넓은 규칙이 있어도 버린다")
    func destinations() throws {
        var filter = try filter("[\(rule(src: "*", dst: "100.64.0.1"))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))

        var wide = try self.filter("[\(rule(src: "*"))]")
        #expect(try verdict(&wide, udp(from: Self.peer4, to: "100.64.0.9")) == .drop(.notForUs))
        #expect(try verdict(&wide, udp(from: Self.peer6, to: "fd7a:115c:a1e0::9")) == .drop(.notForUs))
    }

    @Test("multicast·link-local 목적지는 먼저 버린다", arguments: ["224.0.0.1", "239.255.255.250", "169.254.169.254", "ff02::1", "fe80::1"])
    func multicastAndLinkLocal(destination: String) throws {
        var filter = PacketFilter(rules: try decodeFilterRules("[\(rule(src: "*"))]"), localAddresses: [IPAddress(destination)].compactMap { $0 })
        let source = destination.contains(":") ? Self.peer6 : Self.peer4
        #expect(try verdict(&filter, udp(from: source, to: destination)) == .drop(.multicastOrLinkLocal))
    }

    @Test("cap: 출발지는 지원하지 않으므로 그 항목만 버린다")
    func capabilitySource() throws {
        var capOnly = try filter("[\(rule(src: "cap:tailscale.com/cap/ssh"))]")
        #expect(try verdict(&capOnly, udp(from: Self.peer4)) == .drop(.noRuleMatched))

        var mixed = try filter(#"[{"SrcIPs":["cap:x","100.64.0.2"],"DstPorts":[{"IP":"*","Ports":{"First":7,"Last":7}}]}]"#)
        #expect(try verdict(&mixed, udp(from: Self.peer4)) == .accept)
    }

    @Test("잘못된 주소 표현은 그 항목만 버리고 나머지는 남긴다")
    func invalidEntries() throws {
        // 호스트 비트가 남은 CIDR, 역순 범위, 계열이 섞인 범위, 범위 표기의 '-' 둘, 주소가 아닌 문자열.
        let sources = ["100.64.0.2/24", "100.64.0.9-100.64.0.3", "100.64.0.1-fd7a:115c:a1e0::1", "1-2-3", "peer", "", "100.64.0.2%en0"]
        let quoted = (sources + ["100.64.0.7"]).map { "\"\($0)\"" }.joined(separator: ",")
        var filter = try filter(#"[{"SrcIPs":[\#(quoted)],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]"#)
        #expect(try verdict(&filter, udp(from: "100.64.0.7")) == .accept)
        for source in ["100.64.0.2", "100.64.0.3", "100.64.0.5"] {
            #expect(try verdict(&filter, udp(from: source)) == .drop(.noRuleMatched), "\(source)")
        }
    }

    @Test("어떤 규칙 문자열로도 죽지 않는다")
    func hostileStrings() throws {
        let texts = [
            "*", "**", "-", "--", "/", "//", "cap:", "cap", "0.0.0.0-255.255.255.255", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "100.64.0.1/33", "100.64.0.1/-1", "100.64.0.1/999999999999999999999", "fd7a::/129", "1.2.3.4/", "/8",
            "1.2.3", "01.2.3.4", "999.1.1.1", "::ffff:1.2.3.4", "fe80::1%en0", "🦊", String(repeating: "1", count: 10_000),
        ]
        for text in texts {
            let json = rule(src: text, dst: text)
            var filter = try filter("[\(json)]")
            _ = try verdict(&filter, udp(from: Self.peer4))
            _ = try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1"))
        }
    }

    // MARK: - 포트와 프로토콜

    @Test("포트 범위는 양 끝을 포함한다. First > Last면 어떤 포트도 맞지 않는다")
    func portBounds() throws {
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":7,"Last":9}"#))]")
        for (port, expected) in [(UInt16(6), false), (7, true), (9, true), (10, false)] {
            #expect(try verdict(&filter, udp(from: Self.peer4, to: "100.64.0.1", port)) == (expected ? .accept : .drop(.noRuleMatched)), "\(port)")
        }
        var inverted = try self.filter("[\(rule(src: Self.peer4, ports: #"{"First":9,"Last":7}"#))]")
        #expect(try verdict(&inverted, udp(from: Self.peer4, to: "100.64.0.1", 8)) == .drop(.noRuleMatched))
    }

    @Test("빈 IPProto는 TCP·UDP·ICMP만")
    func defaultProtocols() throws {
        var filter = try filter("[\(rule(src: Self.peer4))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, TestPacket.icmp(from: Self.peer4, to: "100.64.0.1", type: 8)) == .accept)
        let gre = TestPacket.ipv4(from: Self.peer4, to: "100.64.0.1", protocolNumber: 47, transport: [])
        #expect(try verdict(&filter, gre) == .drop(.noRuleMatched))
    }

    @Test("명시한 프로토콜만 연다")
    func explicitProtocols() throws {
        var filter = try filter("[\(rule(src: Self.peer4, proto: #","IPProto":[17]"#))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("범위 밖 프로토콜 번호만 있으면 빈 집합이다(기본 집합으로 돌아가지 않는다)")
    func outOfRangeProtocols() throws {
        var filter = try filter("[\(rule(src: Self.peer4, proto: #","IPProto":[-1,256,9223372036854775807]"#))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("그 밖의 프로토콜은 그 번호와 포트 전체를 연 규칙이 있을 때만")
    func otherProtocols() throws {
        let gre = TestPacket.ipv4(from: Self.peer4, to: "100.64.0.1", protocolNumber: 47, transport: [])
        var allPorts = try filter("[\(rule(src: Self.peer4, proto: #","IPProto":[47]"#))]")
        #expect(try verdict(&allPorts, gre) == .accept)
        var somePorts = try filter("[\(rule(src: Self.peer4, ports: #"{"First":0,"Last":65534}"#, proto: #","IPProto":[47]"#))]")
        #expect(try verdict(&somePorts, gre) == .drop(.noRuleMatched))
    }

    @Test("SCTP는 UDP와 같다: 규칙의 목적 포트를 보고, 먼저 보낸 것의 응답은 규칙 없이 받는다")
    func sctp() throws {
        let toPort9 = TestPacket.sctp(from: Self.peer4, 40000, to: "100.64.0.1", 9)
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":9,"Last":9}"#, proto: #","IPProto":[132]"#))]")
        #expect(try verdict(&filter, toPort9) == .accept)
        #expect(try verdict(&filter, TestPacket.sctp(from: Self.peer4, 40000, to: "100.64.0.1", 10)) == .drop(.noRuleMatched))
        // 기본 프로토콜 집합에는 SCTP가 없다.
        var defaults = try self.filter("[\(rule(src: Self.peer4))]")
        #expect(try verdict(&defaults, toPort9) == .drop(.noRuleMatched))

        var none = try self.filter("[]")
        none.recordOutbound(try IPPacket(parsing: TestPacket.sctp(from: "fd7a:115c:a1e0::1", 5000, to: Self.peer6, 9)))
        #expect(try verdict(&none, TestPacket.sctp(from: Self.peer6, 9, to: "fd7a:115c:a1e0::1", 5000)) == .accept)
        // 같은 주소·포트의 UDP는 SCTP 흐름 기록에 맞지 않는다.
        #expect(try verdict(&none, TestPacket.udp(from: Self.peer6, 9, to: "fd7a:115c:a1e0::1", 5000)) == .drop(.noRuleMatched))
    }

    // MARK: - 옛 형식과 CapGrant

    @Test("SrcBits가 있으면 필터 전체에 규칙이 없다")
    func srcBits() throws {
        var filter = try filter(#"[\#(rule(src: "*")),{"SrcIPs":["100.64.0.2"],"SrcBits":[32],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]"#)
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("DstPorts의 Bits가 있으면 필터 전체에 규칙이 없다")
    func dstBits() throws {
        var filter = try filter(#"[\#(rule(src: "*")),{"SrcIPs":["*"],"DstPorts":[{"IP":"100.64.0.1","Bits":32,"Ports":{"First":0,"Last":65535}}]}]"#)
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("규칙이 없어도 먼저 보낸 UDP의 응답은 받는다(옛 형식으로 비운 필터 포함)")
    func emptyRulesStillTrackFlows() throws {
        var filter = try filter(#"[{"SrcIPs":["*"],"SrcBits":[0],"DstPorts":[]}]"#)
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 7, to: Self.peer4, 40000)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 40000, to: "100.64.0.1", 7)) == .accept)
    }

    @Test("CapGrant만 있는 규칙은 패킷을 열지 않는다")
    func capGrantOnly() throws {
        var filter = try filter(#"[{"SrcIPs":["*"],"CapGrant":[{"Dsts":["100.64.0.1/32"],"CapMap":{"tailscale.com/cap/x":[{}]}}]}]"#)
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: Self.peer4, to: "100.64.0.1", type: 8)) == .drop(.noRuleMatched))
    }

    @Test("netmap 전의 allowNone은 모든 새 흐름을 버린다")
    func allowNone() throws {
        var filter = PacketFilter.allowNone
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.notForUs))
    }

    // MARK: - TCP와 ICMP

    @Test("TCP: SYN만 규칙을 본다. SYN-ACK·ACK·RST는 규칙 없이 받는다")
    func tcp() throws {
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":22,"Last":22}"#))]")
        #expect(try verdict(&filter, syn(from: Self.peer4, 22)) == .accept)
        #expect(try verdict(&filter, syn(from: Self.peer4, 23)) == .drop(.noRuleMatched))
        for flags: UInt8 in [0x12, 0x10, 0x04, 0x11] {
            let packet = TestPacket.tcp(from: "100.64.0.9", 80, to: "100.64.0.1", 50000, flags: flags)
            #expect(try verdict(&filter, packet) == .accept, "flags \(flags)")
        }
    }

    @Test("ICMP: 포트를 보지 않고 출발·목적 주소가 맞는 규칙이면 받는다")
    func icmpAddressesOnly() throws {
        // TCP 22만 연 규칙이어도 같은 출발지의 echo request는 받는다.
        var filter = try filter("[\(rule(src: Self.peer4, dst: "100.64.0.1", ports: #"{"First":22,"Last":22}"#, proto: #","IPProto":[6]"#))]")
        #expect(try verdict(&filter, TestPacket.icmp(from: Self.peer4, to: "100.64.0.1", type: 8)) == .accept)
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.3", to: "100.64.0.1", type: 8)) == .drop(.noRuleMatched))
    }

    @Test("ICMP echo reply와 오류는 규칙 없이 받는다")
    func icmpRepliesAndErrors() throws {
        var filter = try filter("[]")
        for type: UInt8 in [0, 3, 11, 12] {
            #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: type)) == .accept, "v4 type \(type)")
        }
        for type: UInt8 in [129, 1, 2, 3, 4] {
            #expect(try verdict(&filter, TestPacket.icmp(from: "fd7a:115c:a1e0::9", to: "fd7a:115c:a1e0::1", type: type)) == .accept, "v6 type \(type)")
        }
        // echo request, code가 0이 아닌 echo reply, Go의 0x12(18)는 규칙이 있어야 한다.
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: 8)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: 0, code: 1)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: 18)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: "fd7a:115c:a1e0::9", to: "fd7a:115c:a1e0::1", type: 128)) == .drop(.noRuleMatched))
    }

    // MARK: - UDP 흐름 기록

    @Test("먼저 보낸 UDP의 응답은 규칙 없이 받는다. 튜플이 하나라도 다르면 받지 않는다")
    func udpReplies() throws {
        var filter = try filter("[]")
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 5000, to: Self.peer4, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5000)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 8, to: "100.64.0.1", 5000)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5001)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, udp(from: "100.64.0.3", 7, to: "100.64.0.1", 5000)) == .drop(.noRuleMatched))
        // 프로토콜이 다르면(TCP SYN) 흐름 기록과 무관하다.
        let tcp = TestPacket.tcp(from: Self.peer4, 7, to: "100.64.0.1", 5000, flags: 0x02)
        #expect(try verdict(&filter, tcp) == .drop(.noRuleMatched))

        filter.recordOutbound(try IPPacket(parsing: udp(from: "fd7a:115c:a1e0::1", 5000, to: Self.peer6, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer6, 7, to: "fd7a:115c:a1e0::1", 5000)) == .accept)
    }

    @Test("받은 UDP와 UDP가 아닌 송신은 기록을 만들지 않는다")
    func onlyOutboundUDPIsRecorded() throws {
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":7,"Last":7}"#))]")
        #expect(try verdict(&filter, udp(from: Self.peer4, 40000, to: "100.64.0.1", 7)) == .accept)
        // 위 수신이 기록을 만들었다면 이 역방향(우리가 보낸 것처럼 보이는) 패킷이 받아졌을 것이다.
        filter.recordOutbound(try IPPacket(parsing: TestPacket.tcp(from: "100.64.0.1", 5000, to: Self.peer4, 8, flags: 0x02)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 8, to: "100.64.0.1", 5000)) == .drop(.noRuleMatched))
    }

    @Test("흐름 기록은 512개 LRU다. 513번째가 가장 오래 쓰지 않은 것을 내보낸다")
    func lruCapacity() throws {
        var filter = try filter("[]")
        for port in UInt16(1)...513 {
            filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", port, to: Self.peer4, 7)))
        }
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 1)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 2)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 513)) == .accept)
    }

    @Test("조회도 최근 사용 순서를 갱신한다")
    func lookupRefreshesRecency() throws {
        var filter = try filter("[]")
        for port in UInt16(1)...512 {
            filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", port, to: Self.peer4, 7)))
        }
        // 1번을 조회하면 가장 오래 쓰지 않은 것은 2번이 된다.
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 1)) == .accept)
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 600, to: Self.peer4, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 1)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 2)) == .drop(.noRuleMatched))
        // 이미 있는 흐름을 다시 기록해도 다른 것을 내보내지 않는다.
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 600, to: Self.peer4, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 3)) == .accept)
    }

    @Test("규칙을 바꿔도 흐름 기록은 이어 간다")
    func replaceRulesKeepsFlows() throws {
        var filter = try filter("[\(rule(src: "*"))]")
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 5000, to: Self.peer4, 7)))
        filter.replaceRules([], localAddresses: Self.local.compactMap(IPAddress.init))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5000)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5001)) == .drop(.noRuleMatched))
    }
}
