// Contract behavior 6. Filter rule conversion and verdicts. Items 3–6 in §7 of the notes (netmap-engine.md).
// The local addresses are 100.64.0.1 and fd7a:115c:a1e0::1. The peer addresses are 100.64.0.2 and fd7a:115c:a1e0::2.

import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("Packet filter")
struct PacketFilterTests {
    static let local = ["100.64.0.1", "fd7a:115c:a1e0::1"]
    static let peer4 = "100.64.0.2"
    static let peer6 = "fd7a:115c:a1e0::2"

    /// Builds a filter from rule JSON and local addresses.
    private func filter(_ rulesJSON: String) throws -> PacketFilter {
        PacketFilter(rules: try decodeFilterRules(rulesJSON), localAddresses: Self.local.compactMap(IPAddress.init))
    }

    /// Builds a rule that allows one source to reach one destination port.
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

    // MARK: - Address expressions

    @Test("`*` matches all IPv4 and IPv6 sources")
    func wildcard() throws {
        var filter = try filter("[\(rule(src: "*"))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, udp(from: "10.1.2.3")) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .accept)
    }

    @Test("A CIDR source matches only addresses within it")
    func cidrSource() throws {
        var filter = try filter("[\(rule(src: "100.64.0.0/30"))]")
        #expect(try verdict(&filter, udp(from: "100.64.0.3")) == .accept)
        #expect(try verdict(&filter, udp(from: "100.64.0.4")) == .drop(.noRuleMatched))
        // An IPv4 rule does not match IPv6 packets.
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))
    }

    @Test("Single-address source")
    func singleAddressSource() throws {
        var filter = try filter("[\(rule(src: Self.peer6))]")
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .accept)
        #expect(try verdict(&filter, udp(from: "fd7a:115c:a1e0::3", to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))
    }

    @Test("The a-b range includes both endpoints")
    func rangeSource() throws {
        var filter = try filter("[\(rule(src: "100.64.0.2-100.64.0.5")),\(rule(src: "fd7a:115c:a1e0::2-fd7a:115c:a1e0::ff"))]")
        for (source, expected) in [("100.64.0.1", false), ("100.64.0.2", true), ("100.64.0.5", true), ("100.64.0.6", false)] {
            #expect(try verdict(&filter, udp(from: source)) == (expected ? .accept : .drop(.noRuleMatched)), "\(source)")
        }
        #expect(try verdict(&filter, udp(from: "fd7a:115c:a1e0::ff", to: "fd7a:115c:a1e0::1")) == .accept)
        #expect(try verdict(&filter, udp(from: "fd7a:115c:a1e0::100", to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))
    }

    @Test("Compare even very wide ranges without expanding them")
    func hugeRanges() throws {
        var filter = try filter("[\(rule(src: "0.0.0.1-255.255.255.254")),\(rule(src: "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .accept)
    }

    @Test("Parse destination expressions by the same rules. Drop nonlocal destinations even if a broad rule matches")
    func destinations() throws {
        var filter = try filter("[\(rule(src: "*", dst: "100.64.0.1"))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer6, to: "fd7a:115c:a1e0::1")) == .drop(.noRuleMatched))

        var wide = try self.filter("[\(rule(src: "*"))]")
        #expect(try verdict(&wide, udp(from: Self.peer4, to: "100.64.0.9")) == .drop(.notForUs))
        #expect(try verdict(&wide, udp(from: Self.peer6, to: "fd7a:115c:a1e0::9")) == .drop(.notForUs))
    }

    @Test("Drop multicast and link-local destinations first", arguments: ["224.0.0.1", "239.255.255.250", "169.254.169.254", "ff02::1", "fe80::1"])
    func multicastAndLinkLocal(destination: String) throws {
        var filter = PacketFilter(rules: try decodeFilterRules("[\(rule(src: "*"))]"), localAddresses: [IPAddress(destination)].compactMap { $0 })
        let source = destination.contains(":") ? Self.peer6 : Self.peer4
        #expect(try verdict(&filter, udp(from: source, to: destination)) == .drop(.multicastOrLinkLocal))
    }

    @Test("Drop only the unsupported cap: source entry")
    func capabilitySource() throws {
        var capOnly = try filter("[\(rule(src: "cap:tailscale.com/cap/ssh"))]")
        #expect(try verdict(&capOnly, udp(from: Self.peer4)) == .drop(.noRuleMatched))

        var mixed = try filter(#"[{"SrcIPs":["cap:x","100.64.0.2"],"DstPorts":[{"IP":"*","Ports":{"First":7,"Last":7}}]}]"#)
        #expect(try verdict(&mixed, udp(from: Self.peer4)) == .accept)
    }

    @Test("Drop only the invalid address expression and keep the rest")
    func invalidEntries() throws {
        // CIDR with host bits set, reversed range, mixed-family range, two '-' characters in a range, and a string that is not an address.
        let sources = ["100.64.0.2/24", "100.64.0.9-100.64.0.3", "100.64.0.1-fd7a:115c:a1e0::1", "1-2-3", "peer", "", "100.64.0.2%en0"]
        let quoted = (sources + ["100.64.0.7"]).map { "\"\($0)\"" }.joined(separator: ",")
        var filter = try filter(#"[{"SrcIPs":[\#(quoted)],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]"#)
        #expect(try verdict(&filter, udp(from: "100.64.0.7")) == .accept)
        for source in ["100.64.0.2", "100.64.0.3", "100.64.0.5"] {
            #expect(try verdict(&filter, udp(from: source)) == .drop(.noRuleMatched), "\(source)")
        }
    }

    @Test("No rule string causes a crash")
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

    // MARK: - Ports and protocols

    @Test("Port ranges include both endpoints. If First > Last, no port matches")
    func portBounds() throws {
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":7,"Last":9}"#))]")
        for (port, expected) in [(UInt16(6), false), (7, true), (9, true), (10, false)] {
            #expect(try verdict(&filter, udp(from: Self.peer4, to: "100.64.0.1", port)) == (expected ? .accept : .drop(.noRuleMatched)), "\(port)")
        }
        var inverted = try self.filter("[\(rule(src: Self.peer4, ports: #"{"First":9,"Last":7}"#))]")
        #expect(try verdict(&inverted, udp(from: Self.peer4, to: "100.64.0.1", 8)) == .drop(.noRuleMatched))
    }

    @Test("Empty IPProto matches only TCP, UDP, and ICMP")
    func defaultProtocols() throws {
        var filter = try filter("[\(rule(src: Self.peer4))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, TestPacket.icmp(from: Self.peer4, to: "100.64.0.1", type: 8)) == .accept)
        let gre = TestPacket.ipv4(from: Self.peer4, to: "100.64.0.1", protocolNumber: 47, transport: [])
        #expect(try verdict(&filter, gre) == .drop(.noRuleMatched))
    }

    @Test("Allow only explicitly specified protocols")
    func explicitProtocols() throws {
        var filter = try filter("[\(rule(src: Self.peer4, proto: #","IPProto":[17]"#))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .accept)
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("Only out-of-range protocol numbers yield an empty set (no fallback to the default set)")
    func outOfRangeProtocols() throws {
        var filter = try filter("[\(rule(src: Self.peer4, proto: #","IPProto":[-1,256,9223372036854775807]"#))]")
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("Other protocols need a rule that allows their number and the entire port range")
    func otherProtocols() throws {
        let gre = TestPacket.ipv4(from: Self.peer4, to: "100.64.0.1", protocolNumber: 47, transport: [])
        var allPorts = try filter("[\(rule(src: Self.peer4, proto: #","IPProto":[47]"#))]")
        #expect(try verdict(&allPorts, gre) == .accept)
        var somePorts = try filter("[\(rule(src: Self.peer4, ports: #"{"First":0,"Last":65534}"#, proto: #","IPProto":[47]"#))]")
        #expect(try verdict(&somePorts, gre) == .drop(.noRuleMatched))
    }

    @Test("SCTP follows UDP behavior. Check the rule's destination port and accept replies to outbound traffic without a rule")
    func sctp() throws {
        let toPort9 = TestPacket.sctp(from: Self.peer4, 40000, to: "100.64.0.1", 9)
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":9,"Last":9}"#, proto: #","IPProto":[132]"#))]")
        #expect(try verdict(&filter, toPort9) == .accept)
        #expect(try verdict(&filter, TestPacket.sctp(from: Self.peer4, 40000, to: "100.64.0.1", 10)) == .drop(.noRuleMatched))
        // The default protocol set excludes SCTP.
        var defaults = try self.filter("[\(rule(src: Self.peer4))]")
        #expect(try verdict(&defaults, toPort9) == .drop(.noRuleMatched))

        var none = try self.filter("[]")
        none.recordOutbound(try IPPacket(parsing: TestPacket.sctp(from: "fd7a:115c:a1e0::1", 5000, to: Self.peer6, 9)))
        #expect(try verdict(&none, TestPacket.sctp(from: Self.peer6, 9, to: "fd7a:115c:a1e0::1", 5000)) == .accept)
        // UDP with the same addresses and ports does not match the SCTP flow record.
        #expect(try verdict(&none, TestPacket.udp(from: Self.peer6, 9, to: "fd7a:115c:a1e0::1", 5000)) == .drop(.noRuleMatched))
    }

    // MARK: - Legacy formats and CapGrant

    @Test("SrcBits anywhere leaves the entire filter without rules")
    func srcBits() throws {
        var filter = try filter(#"[\#(rule(src: "*")),{"SrcIPs":["100.64.0.2"],"SrcBits":[32],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]"#)
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("A Bits field in DstPorts leaves the entire filter without rules")
    func dstBits() throws {
        var filter = try filter(#"[\#(rule(src: "*")),{"SrcIPs":["*"],"DstPorts":[{"IP":"100.64.0.1","Bits":32,"Ports":{"First":0,"Last":65535}}]}]"#)
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
    }

    @Test("Accept replies to outbound UDP even without rules, including when a legacy format empties the filter")
    func emptyRulesStillTrackFlows() throws {
        var filter = try filter(#"[{"SrcIPs":["*"],"SrcBits":[0],"DstPorts":[]}]"#)
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 7, to: Self.peer4, 40000)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 40000, to: "100.64.0.1", 7)) == .accept)
    }

    @Test("A rule with only CapGrant allows no packets")
    func capGrantOnly() throws {
        var filter = try filter(#"[{"SrcIPs":["*"],"CapGrant":[{"Dsts":["100.64.0.1/32"],"CapMap":{"tailscale.com/cap/x":[{}]}}]}]"#)
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, syn(from: Self.peer4)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: Self.peer4, to: "100.64.0.1", type: 8)) == .drop(.noRuleMatched))
    }

    @Test("Before the netmap, allowNone drops all new flows")
    func allowNone() throws {
        var filter = PacketFilter.allowNone
        #expect(try verdict(&filter, udp(from: Self.peer4)) == .drop(.notForUs))
    }

    // MARK: - TCP and ICMP

    @Test("TCP checks rules only for SYN. Accept SYN-ACK, ACK, and RST without a rule")
    func tcp() throws {
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":22,"Last":22}"#))]")
        #expect(try verdict(&filter, syn(from: Self.peer4, 22)) == .accept)
        #expect(try verdict(&filter, syn(from: Self.peer4, 23)) == .drop(.noRuleMatched))
        for flags: UInt8 in [0x12, 0x10, 0x04, 0x11] {
            let packet = TestPacket.tcp(from: "100.64.0.9", 80, to: "100.64.0.1", 50000, flags: flags)
            #expect(try verdict(&filter, packet) == .accept, "flags \(flags)")
        }
    }

    @Test("Accept ICMP when a rule matches the source and destination addresses, regardless of ports")
    func icmpAddressesOnly() throws {
        // A rule allowing only TCP 22 also accepts an echo request from the same source.
        var filter = try filter("[\(rule(src: Self.peer4, dst: "100.64.0.1", ports: #"{"First":22,"Last":22}"#, proto: #","IPProto":[6]"#))]")
        #expect(try verdict(&filter, TestPacket.icmp(from: Self.peer4, to: "100.64.0.1", type: 8)) == .accept)
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.3", to: "100.64.0.1", type: 8)) == .drop(.noRuleMatched))
    }

    @Test("Accept ICMP echo replies and errors without a rule")
    func icmpRepliesAndErrors() throws {
        var filter = try filter("[]")
        for type: UInt8 in [0, 3, 11, 12] {
            #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: type)) == .accept, "v4 type \(type)")
        }
        for type: UInt8 in [129, 1, 2, 3, 4] {
            #expect(try verdict(&filter, TestPacket.icmp(from: "fd7a:115c:a1e0::9", to: "fd7a:115c:a1e0::1", type: type)) == .accept, "v6 type \(type)")
        }
        // Echo requests, echo replies with a nonzero code, and Go's 0x12 (18) require a rule.
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: 8)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: 0, code: 1)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: "100.64.0.9", to: "100.64.0.1", type: 18)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, TestPacket.icmp(from: "fd7a:115c:a1e0::9", to: "fd7a:115c:a1e0::1", type: 128)) == .drop(.noRuleMatched))
    }

    // MARK: - UDP flow tracking

    @Test("Accept replies to outbound UDP without a rule. Every tuple element must match")
    func udpReplies() throws {
        var filter = try filter("[]")
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 5000, to: Self.peer4, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5000)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 8, to: "100.64.0.1", 5000)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5001)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, udp(from: "100.64.0.3", 7, to: "100.64.0.1", 5000)) == .drop(.noRuleMatched))
        // A different protocol (TCP SYN) does not use the flow record.
        let tcp = TestPacket.tcp(from: Self.peer4, 7, to: "100.64.0.1", 5000, flags: 0x02)
        #expect(try verdict(&filter, tcp) == .drop(.noRuleMatched))

        filter.recordOutbound(try IPPacket(parsing: udp(from: "fd7a:115c:a1e0::1", 5000, to: Self.peer6, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer6, 7, to: "fd7a:115c:a1e0::1", 5000)) == .accept)
    }

    @Test("Inbound UDP and outbound non-UDP traffic create no flow records")
    func onlyOutboundUDPIsRecorded() throws {
        var filter = try filter("[\(rule(src: Self.peer4, ports: #"{"First":7,"Last":7}"#))]")
        #expect(try verdict(&filter, udp(from: Self.peer4, 40000, to: "100.64.0.1", 7)) == .accept)
        // If the inbound packet above had created a record, this reverse packet (which looks like one we sent) would have been accepted.
        filter.recordOutbound(try IPPacket(parsing: TestPacket.tcp(from: "100.64.0.1", 5000, to: Self.peer4, 8, flags: 0x02)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 8, to: "100.64.0.1", 5000)) == .drop(.noRuleMatched))
    }

    @Test("Flow tracking uses a 512-entry LRU cache. The 513th entry evicts the least recently used one")
    func lruCapacity() throws {
        var filter = try filter("[]")
        for port in UInt16(1)...513 {
            filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", port, to: Self.peer4, 7)))
        }
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 1)) == .drop(.noRuleMatched))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 2)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 513)) == .accept)
    }

    @Test("Lookups also update the order of most recent use")
    func lookupRefreshesRecency() throws {
        var filter = try filter("[]")
        for port in UInt16(1)...512 {
            filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", port, to: Self.peer4, 7)))
        }
        // Looking up entry 1 makes entry 2 the least recently used.
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 1)) == .accept)
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 600, to: Self.peer4, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 1)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 2)) == .drop(.noRuleMatched))
        // Recording an existing flow again does not evict another entry.
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 600, to: Self.peer4, 7)))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 3)) == .accept)
    }

    @Test("Keep flow records when the rules change")
    func replaceRulesKeepsFlows() throws {
        var filter = try filter("[\(rule(src: "*"))]")
        filter.recordOutbound(try IPPacket(parsing: udp(from: "100.64.0.1", 5000, to: Self.peer4, 7)))
        filter.replaceRules([], localAddresses: Self.local.compactMap(IPAddress.init))
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5000)) == .accept)
        #expect(try verdict(&filter, udp(from: Self.peer4, 7, to: "100.64.0.1", 5001)) == .drop(.noRuleMatched))
    }
}
