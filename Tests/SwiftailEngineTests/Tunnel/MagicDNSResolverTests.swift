// MagicDNS 응답기 시험. 계약 `docs/contracts/SwiftailTunnel.md` 동작 D와 "시험" 2, 노트 `dns-state-node.md` 3.1·4.2.
//
// "Go 응답기와 같은 바이트" 시험의 벡터는 Go로 얻었다: `Tools/interop` 모듈(tailscale.com v1.104.6)에서 임시 프로그램이
// `resolver.New` + `SetConfig(LocalDomains: 아래 baseZones)` + `SetMagicDNSHosts`(아래 netmap과 같은 고정 표: self
// 100.64.0.1, 피어 100.64.0.2, PTR 100.64.0.1 → self, fd7a:115c:a1e0::2 → 피어)로 `Query(…, "udp", …)`를 불러 질의와
// 응답을 16진으로 찍었다. SOA SERIAL은 1_800_000_000(0x6b49d200)으로 바꿨다. 나머지 시험의 기대값은 계약 동작 D와
// 노트(Go 소스)의 규칙에서 정했다.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine

@Suite("MagicDNS 응답기")
struct MagicDNSResolverTests {
    /// SOA SERIAL이 1_800_000_000이 되는 시각.
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    /// 설정 산출(동작 S5)이 MagicDNS를 켠 tailnet에 내는 영역: 접미사, ULA 역방향, 100.64/10 역방향 64개.
    private static let baseZones = ["tail0001.ts.net.", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."]
        + (64...127).map { "\($0).100.in-addr.arpa." }

    private static let selfName = "rd-mac-1a2b3c4d.tail0001.ts.net."
    private static let peerName = "rd-phone-5e6f7a8b.tail0001.ts.net."

    private static func node(id: Int64, name: String, addresses: [String], extra: String = "") -> String {
        let list = addresses.map { "\"\($0)\"" }.joined(separator: ",")
        let key = makeNodeKey(byte: UInt8(id))
        return #"{"ID":\#(id),"Name":"\#(name)","Key":"\#(key)","Addresses":[\#(list)]\#(extra)}"#
    }

    /// self(IPv4·IPv6)와 피어 하나(IPv4·IPv6)인 netmap. `dnsConfig`는 `DNSConfig` JSON.
    private static func netmap(
        selfNode: String = node(id: 1, name: selfName, addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"]),
        peers: [String] = [node(id: 2, name: peerName, addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])],
        dnsConfig: String = #"{"Proxied":true}"#
    ) throws -> Netmap {
        let json = #"{"Node":\#(selfNode),"Peers":[\#(peers.joined(separator: ","))],"DNSConfig":\#(dnsConfig)}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: wallClockStart).netmap)
    }

    private static func resolver(_ netmap: Netmap?, zones: [String] = baseZones) -> MagicDNSResolver {
        MagicDNSResolver(netmap: netmap, localZones: zones)
    }

    private func ask(_ resolver: MagicDNSResolver, _ name: String, type: UInt16, flags: UInt16 = DNSWire.recursionDesired) throws -> DecodedResponse {
        try DecodedResponse(resolver.response(to: DNSWire.query(name, type: type, flags: flags), at: now))
    }

    private func address(_ text: String) throws -> [UInt8] {
        try #require(IPAddress(text)).bytes
    }

    // MARK: Go 응답기와 같은 바이트

    struct GoVector: CustomTestStringConvertible, Sendable {
        let label: String
        let query: String
        let response: String
        init(_ label: String, _ query: String, _ response: String) {
            self.label = label
            self.query = query
            self.response = response
        }
        var testDescription: String { label }
    }

    static let goVectors: [GoVector] = [
        GoVector("self의 A",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000010001",
                 "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("대소문자 섞인 이름, RD=0이면 RA=0이고 질문·답변 이름은 질의 대소문자 그대로",
                 "beef000000010000000000000f52642d4d41432d3161326233633464085441494c30303031027473036e65740000010001",
                 "beef840000010001000000000f52642d4d41432d3161326233633464085441494c30303031027473036e657400000100010f52642d4d41432d3161326233633464085441494c30303031027473036e6574000001000100000005000464400001"),
        GoVector("IPv4가 있는 피어의 AAAA는 NOERROR 빈 답 + SOA",
                 "beef010000010000000000001172642d70686f6e652d3565366637613862087461696c30303031027473036e657400001c0001",
                 "beef858000010000000100001172642d70686f6e652d3565366637613862087461696c30303031027473036e657400001c0001087461696c30303031027473036e657400000600010000000a0036087461696c30303031027473036e657400087461696c30303031027473036e6574006b49d2000000000a0000000a0000000a0000000a"),
        GoVector("영역 안의 모르는 이름은 NXDOMAIN + SOA",
                 "beef01000001000000000000046e6f7065087461696c30303031027473036e65740000010001",
                 "beef85830001000000010000046e6f7065087461696c30303031027473036e65740000010001087461696c30303031027473036e657400000600010000000a0036087461696c30303031027473036e657400087461696c30303031027473036e6574006b49d2000000000a0000000a0000000a0000000a"),
        GoVector("영역 밖의 이름은 SERVFAIL(AA=1)",
                 "beef01000001000000000000076578616d706c6503636f6d0000010001",
                 "beef85020001000000000000076578616d706c6503636f6d0000010001"),
        GoVector("IPv4 PTR",
                 "beef01000001000000000000013101300236340331303007696e2d61646472046172706100000c0001",
                 "beef85800001000100000000013101300236340331303007696e2d61646472046172706100000c0001013101300236340331303007696e2d61646472046172706100000c00010000000500210f72642d6d61632d3161326233633464087461696c30303031027473036e657400"),
        GoVector("IPv6 PTR",
                 "beef010000010000000000000132013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef858000010001000000000132013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c00010132013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c00010000000500231172642d70686f6e652d3565366637613862087461696c30303031027473036e657400"),
        GoVector("니블이 32개가 아닌 ip6.arpa 이름은 영역 안이어도 SERVFAIL",
                 "beef0100000100000000000001320130013001300130013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef8502000100000000000001320130013001300130013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c0001"),
        GoVector("Bonjour 역방향 이름은 NXDOMAIN(AA 없음, RA = RD)",
                 "beef010000010000000000000162075f646e732d7364045f75647001300130033136380331393207696e2d61646472046172706100000c0001",
                 "beef818300010000000000000162075f646e732d7364045f75647001300130033136380331393207696e2d61646472046172706100000c0001"),
        GoVector("있는 이름의 TXT는 NOERROR 빈 답, SOA 없음",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000100001",
                 "beef858000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000100001"),
        GoVector("있는 이름의 NS는 NOTIMP",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000020001",
                 "beef858400010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000020001"),
        GoVector("질문 0개는 FORMERR, 질문 없음",
                 "beef01000000000000000000",
                 "beef85810000000000000000"),
        GoVector("Opcode·TC·AD·CD는 보존하고 Z는 지우고 RCODE는 덮는다",
                 "beef137500010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000010001",
                 "beef97b000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("EDNS 질의에도 응답에 OPT가 없다",
                 "beef010000010000000000010f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010000291000000000000000",
                 "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("EDNS 광고 크기보다 길면 TC",
                 "beef010000010000000000010f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010000290014000000000000",
                 "beef878000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector(".onion은 NXDOMAIN(영역 밖이라 SOA 없음)",
                 "beef010000010000000000000178056f6e696f6e0000010001",
                 "beef858300010000000000000178056f6e696f6e0000010001"),
        GoVector("magicdns.localhost-tailscale-daemon.의 AAAA는 IPv6 서비스 IP",
                 "beef01000001000000000000086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00001c0001",
                 "beef85800001000100000000086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00001c0001086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00001c0001000000050010fd7a115ca1e000000000000000000053"),
        GoVector("서비스 IP의 PTR",
                 "beef010000010000000000000331303003313030033130300331303007696e2d61646472046172706100000c0001",
                 "beef858000010001000000000331303003313030033130300331303007696e2d61646472046172706100000c00010331303003313030033130300331303007696e2d61646472046172706100000c0001000000050025086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00"),
        GoVector("4to6 주소의 PTR은 100.x.y.z의 노드",
                 "beef010000010000000000000131013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef858000010001000000000131013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c00010131013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c00010000000500210f72642d6d61632d3161326233633464087461696c30303031027473036e657400"),
        GoVector("모르는 4to6 주소는 ip6.arpa 영역의 NXDOMAIN + SOA",
                 "beef010000010000000000000139013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef858300010000000100000139013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c000101300165013101610163013501310131016101370164016603697036046172706100000600010000000a005801300165013101610163013501310131016101370164016603697036046172706100013001650131016101630135013101310161013701640166036970360461727061006b49d2000000000a0000000a0000000a0000000a"),
        GoVector("ANY는 첫 주소 하나",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000ff0001",
                 "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000ff00010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("공백이 든 이름은 FORMERR, 질문 포함",
                 "beef0100000100000000000003612062087461696c30303031027473036e65740000010001",
                 "beef8581000100000000000003612062087461696c30303031027473036e65740000010001"),
    ]

    @Test("Go 응답기와 같은 바이트를 낸다", arguments: goVectors)
    func matchesGo(_ vector: GoVector) throws {
        let resolver = Self.resolver(try Self.netmap())
        #expect(resolver.response(to: try hexBytes(vector.query), at: now) == (try hexBytes(vector.response)))
    }

    @Test("머리가 짧은 질의는 ID 0의 FORMERR, 질문 없음")
    func truncatedHeader() throws {
        // Go는 풀에서 다시 쓴 파서에 남은 앞 질의의 질문을 싣는다(결함). 계약 동작 D2는 질문 없음이다.
        let response = Self.resolver(try Self.netmap()).response(to: [0x12, 0x34, 0x01], at: now)
        #expect(response == [0, 0, 0x84, 0x01, 0, 0, 0, 0, 0, 0, 0, 0])
        #expect(Self.resolver(nil, zones: []).response(to: [], at: now) == response)
    }

    @Test("응답(QR=1)에는 FORMERR, 질문 없음")
    func responseIsNotAQuery() throws {
        var query = DNSWire.query(Self.selfName, type: 1)
        query[2] |= 0x80
        let response = Self.resolver(try Self.netmap()).response(to: query, at: now)
        #expect(response == [0xBE, 0xEF, 0x85, 0x81, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    @Test("이름을 읽지 못한 질의는 FORMERR, 질문 없음")
    func malformedName() throws {
        let query = DNSWire.header(id: 9, flags: 0, questions: 1) + [0xC0, 12, 0, 1, 0, 1]
        let response = try DecodedResponse(Self.resolver(try Self.netmap()).response(to: query, at: now))
        #expect(response.id == 9)
        #expect(response.responseCode == 1)
        #expect(response.questionName == nil)
    }

    @Test("유효하지 않은 이름이고 QTYPE이 0이면 FORMERR에 질문을 싣지 않는다")
    func formatErrorWithZeroType() throws {
        let response = try ask(Self.resolver(try Self.netmap()), "a\u{01}b.tail0001.ts.net.", type: 0)
        #expect(response.responseCode == 1)
        #expect(response.questionName == nil)
    }

    @Test("질문이 둘이면 첫 질문에 답하고 응답에는 질문 하나만 싣는다")
    func twoQuestions() throws {
        let query = DNSWire.header(id: 3, flags: DNSWire.recursionDesired, questions: 2)
            + DNSWire.question(Self.selfName, type: 1) + DNSWire.question(Self.peerName, type: 1)
        let response = try DecodedResponse(Self.resolver(try Self.netmap()).response(to: query, at: now))
        #expect(response.questionName == Self.selfName)
        #expect(response.answer?.data == (try address("100.64.0.1")))
    }

    // MARK: 정방향 이름

    @Test("피어의 짧은 이름과 대소문자 섞인 이름에 답한다")
    func shortAndMixedCaseNames() throws {
        let resolver = Self.resolver(try Self.netmap())
        for name in ["rd-phone-5e6f7a8b.", "RD-Phone-5E6F7A8B.", "Rd-Phone-5e6f7a8b.Tail0001.TS.net."] {
            let response = try ask(resolver, name, type: 1)
            #expect(response.responseCode == 0)
            #expect(response.questionName == name)
            #expect(response.answer?.name == name)
            #expect(response.answer?.ttl == 5)
            #expect(response.answer?.data == (try address("100.64.0.2")))
        }
    }

    @Test("끝 점 없는 노드 이름도 찾고 PTR 답에는 끝 점을 붙인다")
    func nodeNameWithoutTrailingDot() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net", addresses: ["100.64.0.3/32"])
        let resolver = Self.resolver(try Self.netmap(peers: [peer]))
        #expect(try ask(resolver, "rd-tv-11223344.tail0001.ts.net.", type: 1).answer?.data == (try address("100.64.0.3")))
        #expect(try ask(resolver, "rd-tv-11223344.", type: 1).answer?.data == (try address("100.64.0.3")))
        let pointer = try ask(resolver, "3.0.64.100.in-addr.arpa.", type: 12)
        #expect(pointer.answer?.data == DNSWire.name("rd-tv-11223344.tail0001.ts.net."))
    }

    @Test("MagicDNS가 꺼져 있으면 짧은 이름을 찾지 않고 FQDN만 찾는다")
    func proxiedOff() throws {
        let resolver = Self.resolver(try Self.netmap(dnsConfig: #"{"Proxied":false}"#), zones: [])
        #expect(try ask(resolver, "rd-phone-5e6f7a8b.", type: 1).responseCode == 2)
        #expect(try ask(resolver, Self.peerName, type: 1).answer?.data == (try address("100.64.0.2")))
    }

    @Test("주소가 하나도 없는 노드는 모르는 이름이다")
    func nodeWithoutAddresses() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net.", addresses: [])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), "rd-tv-11223344.tail0001.ts.net.", type: 1)
        #expect(response.responseCode == 3)
        #expect(response.authority?.name == "tail0001.ts.net.")
    }

    /// 고치기 전에는 빈 이름의 노드가 색인에 들어가 `.`의 A 질의에 그 노드의 주소가 답으로 나왔다.
    @Test("이름이 빈 노드는 색인에 없다: 루트 이름의 질의는 영역 밖이라 SERVFAIL이다")
    func namelessNodeIsNotIndexed() throws {
        let peer = Self.node(id: 3, name: "", addresses: ["100.64.0.3/32"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), ".", type: 1)
        #expect(response.responseCode == 2)
        #expect(response.answer == nil)
    }

    @Test("A가 없는 노드의 A는 NOERROR 빈 답 + SOA")
    func missingFamilyGetsNoData() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::3/128"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), "rd-tv-11223344.tail0001.ts.net.", type: 1)
        #expect(response.responseCode == 0)
        #expect(response.answer == nil)
        #expect(response.authority?.type == 6)
        #expect(response.authority?.ttl == 10)
    }

    @Test("IPv6만 있는 피어의 AAAA는 magicdns-aaaa 없이도 답한다")
    func ipv6OnlyPeer() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::3/128"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), "rd-tv-11223344.tail0001.ts.net.", type: 28)
        #expect(response.answer?.type == 28)
        #expect(response.answer?.data == (try address("fd7a:115c:a1e0::3")))
    }

    @Test("자기 노드에 magicdns-aaaa가 있으면 IPv4가 있는 피어의 AAAA에도 답한다")
    func peerAAAACapability() throws {
        let selfNode = Self.node(id: 1, name: Self.selfName, addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                                 extra: #","CapMap":{"magicdns-aaaa":null}"#)
        let resolver = Self.resolver(try Self.netmap(selfNode: selfNode))
        #expect(try ask(resolver, Self.peerName, type: 28).answer?.data == (try address("fd7a:115c:a1e0::2")))
        // ANY는 여전히 대상 Addresses 순서의 첫 주소다.
        #expect(try ask(resolver, Self.peerName, type: 255).answer?.data == (try address("100.64.0.2")))
    }

    @Test("자기 노드가 IPv6 전용이면 대상의 IPv6만 답한다")
    func ipv6OnlySelf() throws {
        let selfNode = Self.node(id: 1, name: Self.selfName, addresses: ["fd7a:115c:a1e0::1/128"])
        let resolver = Self.resolver(try Self.netmap(selfNode: selfNode))
        let a = try ask(resolver, Self.peerName, type: 1)
        #expect(a.responseCode == 0)
        #expect(a.answer == nil)
        #expect(a.authority?.name == "tail0001.ts.net.")
        #expect(try ask(resolver, Self.peerName, type: 28).answer?.data == (try address("fd7a:115c:a1e0::2")))
        #expect(try ask(resolver, Self.peerName, type: 255).answer?.data == (try address("fd7a:115c:a1e0::2")))
    }

    @Test("같은 이름이면 피어 목록의 뒤쪽 노드가 이긴다")
    func laterPeerWins() throws {
        let first = Self.node(id: 2, name: Self.peerName, addresses: ["100.64.0.2/32"])
        let second = Self.node(id: 3, name: Self.peerName, addresses: ["100.64.0.3/32"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [first, second])), Self.peerName, type: 1)
        #expect(response.answer?.data == (try address("100.64.0.3")))
    }

    @Test("SOA·AXFR·HINFO는 NOTIMP, 모르는 타입은 NOERROR 빈 답이고 SOA를 싣지 않는다")
    func otherTypes() throws {
        let resolver = Self.resolver(try Self.netmap())
        for type: UInt16 in [6, 252, 13] {
            let response = try ask(resolver, Self.selfName, type: type)
            #expect(response.responseCode == 4)
            #expect(response.authority == nil)
        }
        for type: UInt16 in [16, 33, 65280] {
            let response = try ask(resolver, Self.selfName, type: type)
            #expect(response.responseCode == 0)
            #expect(response.answer == nil)
            #expect(response.authority == nil)
        }
    }

    @Test("ExtraRecords가 노드 색인보다 먼저이고 역방향에도 쓰인다")
    func extraRecords() throws {
        let dnsConfig = #"""
        {"Proxied":true,"ExtraRecords":[
          {"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","Value":"100.64.9.9"},
          {"Name":"Svc.tail0001.ts.net","Type":"AAAA","Value":"fd7a:115c:a1e0::99"},
          {"Name":"svc.tail0001.ts.net.","Type":"A","Value":"100.64.9.10"},
          {"Name":"skip.tail0001.ts.net.","Type":"CNAME","Value":"100.64.9.11"},
          {"Name":"bad.tail0001.ts.net.","Value":"not-an-ip"}]}
        """#
        let resolver = Self.resolver(try Self.netmap(dnsConfig: dnsConfig))
        #expect(try ask(resolver, Self.selfName, type: 1).answer?.data == (try address("100.64.9.9")))
        // 같은 이름의 레코드는 이어 붙고, AAAA 거르기는 노드에만 쓴다.
        #expect(try ask(resolver, "svc.tail0001.ts.net.", type: 1).answer?.data == (try address("100.64.9.10")))
        #expect(try ask(resolver, "svc.tail0001.ts.net.", type: 28).answer?.data == (try address("fd7a:115c:a1e0::99")))
        #expect(try ask(resolver, "skip.tail0001.ts.net.", type: 1).responseCode == 3)
        #expect(try ask(resolver, "bad.tail0001.ts.net.", type: 1).responseCode == 3)
        #expect(try ask(resolver, "10.9.64.100.in-addr.arpa.", type: 12).answer?.data == DNSWire.name("Svc.tail0001.ts.net."))
    }

    @Test("magicdns.localhost-tailscale-daemon.의 A는 IPv4 서비스 IP이고 다른 타입은 영역 밖 이름처럼 다룬다")
    func symbolicName() throws {
        let resolver = Self.resolver(try Self.netmap())
        #expect(try ask(resolver, "MagicDNS.localhost-tailscale-daemon.", type: 1).answer?.data == [100, 100, 100, 100])
        #expect(try ask(resolver, "magicdns.localhost-tailscale-daemon.", type: 16).responseCode == 2)
    }

    // MARK: 영역 밖과 실패

    @Test("Bonjour 탐색 이름은 PTR이 아니어도 영역 밖이면 NXDOMAIN이고 RD=0이면 RA도 0이다")
    func bonjourOutsideZones() throws {
        let response = try ask(Self.resolver(try Self.netmap()), "lb._dns-sd._udp.example.", type: 1, flags: 0x0080)
        #expect(response.responseCode == 3)
        #expect(response.has(0x8000))
        #expect(!response.has(0x0400))
        #expect(!response.has(0x0080))
        #expect(response.questionName == "lb._dns-sd._udp.example.")
        #expect(response.authority == nil)
    }

    @Test("SERVFAIL은 RA를 질의 값 그대로 둔다")
    func serverFailureKeepsRecursionAvailable() throws {
        let response = try ask(Self.resolver(try Self.netmap()), "example.com.", type: 1, flags: 0x0080)
        #expect(response.responseCode == 2)
        #expect(response.has(0x0400))
        #expect(response.has(0x0080))
        #expect(!response.has(0x0100))
    }

    @Test("netmap이 없고 영역이 비면 노드 이름도 SERVFAIL이다")
    func closedWithoutNetmap() throws {
        let resolver = Self.resolver(nil, zones: [])
        #expect(try ask(resolver, Self.selfName, type: 1).responseCode == 2)
        #expect(try ask(resolver, "1.0.64.100.in-addr.arpa.", type: 12).responseCode == 2)
    }

    @Test("영역은 끝 점이 없어도 되고 대소문자를 가리지 않으며 이름을 포함하는 첫 영역이 SOA가 된다")
    func zoneNormalization() throws {
        let resolver = Self.resolver(try Self.netmap(), zones: ["TS.net", "Tail0001.ts.net", "not a zone"])
        let response = try ask(resolver, "nope.tail0001.ts.net.", type: 1)
        #expect(response.responseCode == 3)
        // 끝 점 포함 표기의 바이트 순으로 "tail0001.ts.net." < "ts.net."이다.
        #expect(response.authority?.name == "tail0001.ts.net.")
        #expect(response.authority?.data.prefix(17) == DNSWire.name("tail0001.ts.net.")[...])
    }

    @Test("SOA SERIAL은 넘긴 시각의 유닉스 초다")
    func serialIsGivenTime() throws {
        let resolver = Self.resolver(try Self.netmap())
        let query = DNSWire.query("nope.tail0001.ts.net.", type: 1)
        let response = try DecodedResponse(resolver.response(to: query, at: Date(timeIntervalSince1970: 1_234_567_890.9)))
        let data = try #require(response.authority?.data)
        #expect(Array(data[34..<38]) == [0x49, 0x96, 0x02, 0xD2])
        #expect(Array(data[38...]) == [0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10])
    }

    // MARK: 역방향

    @Test("IPv6 서비스 IP와 IPv6 자기 주소의 PTR")
    func ipv6Pointers() throws {
        let resolver = Self.resolver(try Self.netmap())
        let service = "3.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."
        #expect(try ask(resolver, service, type: 12).answer?.data == DNSWire.name("magicdns.localhost-tailscale-daemon."))
        let selfAddress = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.IP6.ARPA."
        let response = try ask(resolver, selfAddress, type: 12)
        #expect(response.questionName == selfAddress)
        #expect(response.answer?.data == DNSWire.name(Self.selfName))
    }

    @Test("형식이 틀린 역방향 이름은 로컬 답이 없다")
    func malformedReverseNames() throws {
        let resolver = Self.resolver(try Self.netmap())
        for name in ["01.0.64.100.in-addr.arpa.", "0.64.100.in-addr.arpa.", "256.0.64.100.in-addr.arpa.", "in-addr.arpa.",
                     "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."] {
            #expect(try ask(resolver, name, type: 12).responseCode == 2, "\(name)")
        }
    }

    @Test("모르는 주소의 PTR은 영역 안이면 NXDOMAIN + SOA, 밖이면 SERVFAIL")
    func unknownPointers() throws {
        let resolver = Self.resolver(try Self.netmap())
        let inside = try ask(resolver, "9.0.64.100.in-addr.arpa.", type: 12)
        #expect(inside.responseCode == 3)
        #expect(inside.authority?.name == "64.100.in-addr.arpa.")
        #expect(try ask(resolver, "1.0.168.192.in-addr.arpa.", type: 12).responseCode == 2)
    }

    // MARK: UDP 크기

    @Test("EDNS가 없으면 512바이트까지는 TC가 없고 513바이트면 TC")
    func truncationAt512() throws {
        // 표기 100바이트(선 형식 101바이트) 영역의 NXDOMAIN은 47 + 질문 첫 레이블 길이 + 4 × 101바이트다.
        let zone = String(repeating: "a", count: 49) + "." + String(repeating: "b", count: 49) + "."
        let resolver = Self.resolver(nil, zones: [zone])
        let fits = resolver.response(to: DNSWire.query(String(repeating: "x", count: 61) + "." + zone, type: 1), at: now)
        #expect(fits.count == 512)
        #expect(fits[2] & 0x02 == 0)
        let over = resolver.response(to: DNSWire.query(String(repeating: "x", count: 62) + "." + zone, type: 1), at: now)
        #expect(over.count == 513)
        #expect(over[2] & 0x02 != 0)
        #expect(try DecodedResponse(over).responseCode == 3)

        let edns = resolver.response(to: DNSWire.query(String(repeating: "x", count: 62) + "." + zone, type: 1, udpPayloadSize: 513), at: now)
        #expect(edns[2] & 0x02 == 0)
        #expect(try DecodedResponse(edns).additionalCount == 0)
    }

    // MARK: 임의 입력

    @Test("임의 바이트와 일부를 바꾼 질의에도 트랩 없이 머리가 있는 응답을 낸다")
    func randomInput() throws {
        let resolver = Self.resolver(try Self.netmap())
        var random = FuzzRandom(seed: 0xD15_C0DE)
        let seeds = [
            DNSWire.query(Self.selfName, type: 1),
            DNSWire.query("1.0.64.100.in-addr.arpa.", type: 12),
            DNSWire.query("2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.", type: 12),
            DNSWire.query(Self.peerName, type: 28, udpPayloadSize: 100),
        ]
        for round in 0..<10_000 {
            var bytes: [UInt8]
            if round.isMultiple(of: 2) {
                bytes = random.bytes(Int.random(in: 0...300, using: &random))
            } else {
                bytes = seeds[round % seeds.count]
                for _ in 0..<Int.random(in: 1...4, using: &random) {
                    bytes[Int.random(in: 0..<bytes.count, using: &random)] = UInt8.random(in: .min ... .max, using: &random)
                }
            }
            let response = resolver.response(to: bytes, at: now)
            #expect(response.count >= 12)
            #expect(response[2] & 0x80 != 0)
        }
    }
}
