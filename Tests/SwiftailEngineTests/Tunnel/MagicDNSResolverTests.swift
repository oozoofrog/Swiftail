// MagicDNS responder tests. Contract `docs/contracts/SwiftailTunnel.md` behavior D and "Tests" item 2, and `dns-state-node.md` notes 3.1 and 4.2.
//
// Go produced the vectors for the test that matches Go responder bytes. A temporary program in the `Tools/interop` module (tailscale.com v1.104.6)
// used `resolver.New`, `SetConfig(LocalDomains: baseZones)` with the baseZones below, and `SetMagicDNSHosts` with the same fixed table as the netmap below (self
// 100.64.0.1, peer 100.64.0.2, PTR 100.64.0.1 → self, fd7a:115c:a1e0::2 → peer), called `Query(…, "udp", …)`, and printed the queries and
// responses in hex. The SOA SERIAL was changed to 1_800_000_000 (0x6b49d200). The other tests take their expected results from contract behavior D and
// the rules in the notes (Go sources).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine

@Suite("MagicDNS responder")
struct MagicDNSResolverTests {
    /// The time that yields SOA SERIAL 1_800_000_000.
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    /// The zones computed by behavior S5 for a tailnet with MagicDNS enabled. Includes the suffix, the ULA reverse zone, and 64 reverse zones for 100.64/10.
    private static let baseZones = ["tail0001.ts.net.", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."]
        + (64...127).map { "\($0).100.in-addr.arpa." }

    private static let selfName = "rd-mac-1a2b3c4d.tail0001.ts.net."
    private static let peerName = "rd-phone-5e6f7a8b.tail0001.ts.net."

    private static func node(id: Int64, name: String, addresses: [String], extra: String = "") -> String {
        let list = addresses.map { "\"\($0)\"" }.joined(separator: ",")
        let key = makeNodeKey(byte: UInt8(id))
        return #"{"ID":\#(id),"Name":"\#(name)","Key":"\#(key)","Addresses":[\#(list)]\#(extra)}"#
    }

    /// A netmap with self (IPv4 and IPv6) and one peer (IPv4 and IPv6). `dnsConfig` is the `DNSConfig` JSON.
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

    // MARK: Byte-for-byte comparison with the Go responder

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
        GoVector("A for self",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000010001",
                 "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("Mixed-case name. If RD=0, RA=0, and the question and answer names preserve the query's case",
                 "beef000000010000000000000f52642d4d41432d3161326233633464085441494c30303031027473036e65740000010001",
                 "beef840000010001000000000f52642d4d41432d3161326233633464085441494c30303031027473036e657400000100010f52642d4d41432d3161326233633464085441494c30303031027473036e6574000001000100000005000464400001"),
        GoVector("AAAA for a peer with IPv4 returns NOERROR with an empty answer + SOA",
                 "beef010000010000000000001172642d70686f6e652d3565366637613862087461696c30303031027473036e657400001c0001",
                 "beef858000010000000100001172642d70686f6e652d3565366637613862087461696c30303031027473036e657400001c0001087461696c30303031027473036e657400000600010000000a0036087461696c30303031027473036e657400087461696c30303031027473036e6574006b49d2000000000a0000000a0000000a0000000a"),
        GoVector("An unknown name inside the zone returns NXDOMAIN + SOA",
                 "beef01000001000000000000046e6f7065087461696c30303031027473036e65740000010001",
                 "beef85830001000000010000046e6f7065087461696c30303031027473036e65740000010001087461696c30303031027473036e657400000600010000000a0036087461696c30303031027473036e657400087461696c30303031027473036e6574006b49d2000000000a0000000a0000000a0000000a"),
        GoVector("A name outside the zone returns SERVFAIL (AA=1)",
                 "beef01000001000000000000076578616d706c6503636f6d0000010001",
                 "beef85020001000000000000076578616d706c6503636f6d0000010001"),
        GoVector("IPv4 PTR",
                 "beef01000001000000000000013101300236340331303007696e2d61646472046172706100000c0001",
                 "beef85800001000100000000013101300236340331303007696e2d61646472046172706100000c0001013101300236340331303007696e2d61646472046172706100000c00010000000500210f72642d6d61632d3161326233633464087461696c30303031027473036e657400"),
        GoVector("IPv6 PTR",
                 "beef010000010000000000000132013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef858000010001000000000132013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c00010132013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c00010000000500231172642d70686f6e652d3565366637613862087461696c30303031027473036e657400"),
        GoVector("An ip6.arpa name without exactly 32 nibbles returns SERVFAIL even inside the zone",
                 "beef0100000100000000000001320130013001300130013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef8502000100000000000001320130013001300130013001300130013001300130013001300130013001300130013001300130013001300130013001300165013101610163013501310131016101370164016603697036046172706100000c0001"),
        GoVector("Bonjour reverse names return NXDOMAIN (AA unset, RA = RD)",
                 "beef010000010000000000000162075f646e732d7364045f75647001300130033136380331393207696e2d61646472046172706100000c0001",
                 "beef818300010000000000000162075f646e732d7364045f75647001300130033136380331393207696e2d61646472046172706100000c0001"),
        GoVector("TXT for a known name returns NOERROR with an empty answer and no SOA",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000100001",
                 "beef858000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000100001"),
        GoVector("NS for a known name returns NOTIMP",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000020001",
                 "beef858400010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000020001"),
        GoVector("With 0 questions, return FORMERR with no question",
                 "beef01000000000000000000",
                 "beef85810000000000000000"),
        GoVector("Preserve Opcode, TC, AD, and CD, clear Z, and overwrite RCODE",
                 "beef137500010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000010001",
                 "beef97b000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("The response has no OPT even for an EDNS query",
                 "beef010000010000000000010f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010000291000000000000000",
                 "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("Set TC when longer than the EDNS advertised size",
                 "beef010000010000000000010f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010000290014000000000000",
                 "beef878000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector(".onion returns NXDOMAIN (no SOA because it is outside the zone)",
                 "beef010000010000000000000178056f6e696f6e0000010001",
                 "beef858300010000000000000178056f6e696f6e0000010001"),
        GoVector("AAAA for magicdns.localhost-tailscale-daemon. returns the IPv6 service IP",
                 "beef01000001000000000000086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00001c0001",
                 "beef85800001000100000000086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00001c0001086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00001c0001000000050010fd7a115ca1e000000000000000000053"),
        GoVector("PTR for the service IP",
                 "beef010000010000000000000331303003313030033130300331303007696e2d61646472046172706100000c0001",
                 "beef858000010001000000000331303003313030033130300331303007696e2d61646472046172706100000c00010331303003313030033130300331303007696e2d61646472046172706100000c0001000000050025086d61676963646e731a6c6f63616c686f73742d7461696c7363616c652d6461656d6f6e00"),
        GoVector("PTR for a 4to6 address returns the 100.x.y.z node",
                 "beef010000010000000000000131013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef858000010001000000000131013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c00010131013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c00010000000500210f72642d6d61632d3161326233633464087461696c30303031027473036e657400"),
        GoVector("An unknown 4to6 address returns NXDOMAIN + SOA for its ip6.arpa zone",
                 "beef010000010000000000000139013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c0001",
                 "beef858300010000000100000139013001300130013001340132013601360139016401630133013401380134013201310162016101300165013101610163013501310131016101370164016603697036046172706100000c000101300165013101610163013501310131016101370164016603697036046172706100000600010000000a005801300165013101610163013501310131016101370164016603697036046172706100013001650131016101630135013101310161013701640166036970360461727061006b49d2000000000a0000000a0000000a0000000a"),
        GoVector("ANY returns just the first address",
                 "beef010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000ff0001",
                 "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000ff00010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"),
        GoVector("A name containing a space returns FORMERR with the question",
                 "beef0100000100000000000003612062087461696c30303031027473036e65740000010001",
                 "beef8581000100000000000003612062087461696c30303031027473036e65740000010001"),
    ]

    @Test("Match the Go responder byte for byte", arguments: goVectors)
    func matchesGo(_ vector: GoVector) throws {
        let resolver = Self.resolver(try Self.netmap())
        #expect(resolver.response(to: try hexBytes(vector.query), at: now) == (try hexBytes(vector.response)))
    }

    @Test("A query with a short header returns FORMERR with ID 0 and no question")
    func truncatedHeader() throws {
        // Go includes the previous question left in a parser reused from the pool (a defect). Contract behavior D2 specifies no question.
        let response = Self.resolver(try Self.netmap()).response(to: [0x12, 0x34, 0x01], at: now)
        #expect(response == [0, 0, 0x84, 0x01, 0, 0, 0, 0, 0, 0, 0, 0])
        #expect(Self.resolver(nil, zones: []).response(to: [], at: now) == response)
    }

    @Test("A response (QR=1) returns FORMERR with no question")
    func responseIsNotAQuery() throws {
        var query = DNSWire.query(Self.selfName, type: 1)
        query[2] |= 0x80
        let response = Self.resolver(try Self.netmap()).response(to: query, at: now)
        #expect(response == [0xBE, 0xEF, 0x85, 0x81, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    @Test("A query with an unreadable name returns FORMERR with no question")
    func malformedName() throws {
        let query = DNSWire.header(id: 9, flags: 0, questions: 1) + [0xC0, 12, 0, 1, 0, 1]
        let response = try DecodedResponse(Self.resolver(try Self.netmap()).response(to: query, at: now))
        #expect(response.id == 9)
        #expect(response.responseCode == 1)
        #expect(response.questionName == nil)
    }

    @Test("FORMERR omits the question when the name is invalid and QTYPE is 0")
    func formatErrorWithZeroType() throws {
        let response = try ask(Self.resolver(try Self.netmap()), "a\u{01}b.tail0001.ts.net.", type: 0)
        #expect(response.responseCode == 1)
        #expect(response.questionName == nil)
    }

    @Test("With two questions, answer the first and include only one question in the response")
    func twoQuestions() throws {
        let query = DNSWire.header(id: 3, flags: DNSWire.recursionDesired, questions: 2)
            + DNSWire.question(Self.selfName, type: 1) + DNSWire.question(Self.peerName, type: 1)
        let response = try DecodedResponse(Self.resolver(try Self.netmap()).response(to: query, at: now))
        #expect(response.questionName == Self.selfName)
        #expect(response.answer?.data == (try address("100.64.0.1")))
    }

    // MARK: Forward names

    @Test("Answer queries for short and mixed-case peer names")
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

    @Test("Resolve a node name without a trailing dot and append a trailing dot in PTR answers")
    func nodeNameWithoutTrailingDot() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net", addresses: ["100.64.0.3/32"])
        let resolver = Self.resolver(try Self.netmap(peers: [peer]))
        #expect(try ask(resolver, "rd-tv-11223344.tail0001.ts.net.", type: 1).answer?.data == (try address("100.64.0.3")))
        #expect(try ask(resolver, "rd-tv-11223344.", type: 1).answer?.data == (try address("100.64.0.3")))
        let pointer = try ask(resolver, "3.0.64.100.in-addr.arpa.", type: 12)
        #expect(pointer.answer?.data == DNSWire.name("rd-tv-11223344.tail0001.ts.net."))
    }

    @Test("Resolve only FQDNs when MagicDNS is disabled")
    func proxiedOff() throws {
        let resolver = Self.resolver(try Self.netmap(dnsConfig: #"{"Proxied":false}"#), zones: [])
        #expect(try ask(resolver, "rd-phone-5e6f7a8b.", type: 1).responseCode == 2)
        #expect(try ask(resolver, Self.peerName, type: 1).answer?.data == (try address("100.64.0.2")))
    }

    @Test("A node with zero addresses is an unknown name")
    func nodeWithoutAddresses() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net.", addresses: [])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), "rd-tv-11223344.tail0001.ts.net.", type: 1)
        #expect(response.responseCode == 3)
        #expect(response.authority?.name == "tail0001.ts.net.")
    }

    /// Before the fix, an unnamed node entered the index, so an A query for `.` returned that node's address.
    @Test("Unnamed nodes stay out of the index. A query for the root name returns SERVFAIL because it is outside the zone")
    func namelessNodeIsNotIndexed() throws {
        let peer = Self.node(id: 3, name: "", addresses: ["100.64.0.3/32"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), ".", type: 1)
        #expect(response.responseCode == 2)
        #expect(response.answer == nil)
    }

    @Test("An A query for a node with no A record returns NOERROR with an empty answer + SOA")
    func missingFamilyGetsNoData() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::3/128"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), "rd-tv-11223344.tail0001.ts.net.", type: 1)
        #expect(response.responseCode == 0)
        #expect(response.answer == nil)
        #expect(response.authority?.type == 6)
        #expect(response.authority?.ttl == 10)
    }

    @Test("Answer AAAA for an IPv6-only peer even without magicdns-aaaa")
    func ipv6OnlyPeer() throws {
        let peer = Self.node(id: 3, name: "rd-tv-11223344.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::3/128"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [peer])), "rd-tv-11223344.tail0001.ts.net.", type: 28)
        #expect(response.answer?.type == 28)
        #expect(response.answer?.data == (try address("fd7a:115c:a1e0::3")))
    }

    @Test("With magicdns-aaaa on the local node, also answer AAAA for peers with IPv4")
    func peerAAAACapability() throws {
        let selfNode = Self.node(id: 1, name: Self.selfName, addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                                 extra: #","CapMap":{"magicdns-aaaa":null}"#)
        let resolver = Self.resolver(try Self.netmap(selfNode: selfNode))
        #expect(try ask(resolver, Self.peerName, type: 28).answer?.data == (try address("fd7a:115c:a1e0::2")))
        // ANY still returns the target's first address in Addresses order.
        #expect(try ask(resolver, Self.peerName, type: 255).answer?.data == (try address("100.64.0.2")))
    }

    @Test("An IPv6-only local node answers only with the target's IPv6 addresses")
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

    @Test("For identical names, the node later in the peer list wins")
    func laterPeerWins() throws {
        let first = Self.node(id: 2, name: Self.peerName, addresses: ["100.64.0.2/32"])
        let second = Self.node(id: 3, name: Self.peerName, addresses: ["100.64.0.3/32"])
        let response = try ask(Self.resolver(try Self.netmap(peers: [first, second])), Self.peerName, type: 1)
        #expect(response.answer?.data == (try address("100.64.0.3")))
    }

    @Test("SOA, AXFR, and HINFO return NOTIMP. Unknown types return NOERROR with an empty answer and no SOA")
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

    @Test("ExtraRecords take precedence over the node index and are also used for reverse lookups")
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
        // Combine records with the same name. AAAA filtering applies only to nodes.
        #expect(try ask(resolver, "svc.tail0001.ts.net.", type: 1).answer?.data == (try address("100.64.9.10")))
        #expect(try ask(resolver, "svc.tail0001.ts.net.", type: 28).answer?.data == (try address("fd7a:115c:a1e0::99")))
        #expect(try ask(resolver, "skip.tail0001.ts.net.", type: 1).responseCode == 3)
        #expect(try ask(resolver, "bad.tail0001.ts.net.", type: 1).responseCode == 3)
        #expect(try ask(resolver, "10.9.64.100.in-addr.arpa.", type: 12).answer?.data == DNSWire.name("Svc.tail0001.ts.net."))
    }

    @Test("A for magicdns.localhost-tailscale-daemon. returns the IPv4 service IP. Treat other types as queries for out-of-zone names")
    func symbolicName() throws {
        let resolver = Self.resolver(try Self.netmap())
        #expect(try ask(resolver, "MagicDNS.localhost-tailscale-daemon.", type: 1).answer?.data == [100, 100, 100, 100])
        #expect(try ask(resolver, "magicdns.localhost-tailscale-daemon.", type: 16).responseCode == 2)
    }

    // MARK: Out-of-zone names and failures

    @Test("Out-of-zone Bonjour discovery names return NXDOMAIN even for non-PTR queries. If RD=0, RA is also 0")
    func bonjourOutsideZones() throws {
        let response = try ask(Self.resolver(try Self.netmap()), "lb._dns-sd._udp.example.", type: 1, flags: 0x0080)
        #expect(response.responseCode == 3)
        #expect(response.has(0x8000))
        #expect(!response.has(0x0400))
        #expect(!response.has(0x0080))
        #expect(response.questionName == "lb._dns-sd._udp.example.")
        #expect(response.authority == nil)
    }

    @Test("SERVFAIL preserves the query's RA value")
    func serverFailureKeepsRecursionAvailable() throws {
        let response = try ask(Self.resolver(try Self.netmap()), "example.com.", type: 1, flags: 0x0080)
        #expect(response.responseCode == 2)
        #expect(response.has(0x0400))
        #expect(response.has(0x0080))
        #expect(!response.has(0x0100))
    }

    @Test("Node names also return SERVFAIL when there is no netmap and the zones are empty")
    func closedWithoutNetmap() throws {
        let resolver = Self.resolver(nil, zones: [])
        #expect(try ask(resolver, Self.selfName, type: 1).responseCode == 2)
        #expect(try ask(resolver, "1.0.64.100.in-addr.arpa.", type: 12).responseCode == 2)
    }

    @Test("Zones can omit a trailing dot and are case-insensitive. The first zone containing the name supplies the SOA")
    func zoneNormalization() throws {
        let resolver = Self.resolver(try Self.netmap(), zones: ["TS.net", "Tail0001.ts.net", "not a zone"])
        let response = try ask(resolver, "nope.tail0001.ts.net.", type: 1)
        #expect(response.responseCode == 3)
        // In byte order with trailing dots, "tail0001.ts.net." < "ts.net."
        #expect(response.authority?.name == "tail0001.ts.net.")
        #expect(response.authority?.data.prefix(17) == DNSWire.name("tail0001.ts.net.")[...])
    }

    @Test("The SOA SERIAL is the supplied time in Unix seconds")
    func serialIsGivenTime() throws {
        let resolver = Self.resolver(try Self.netmap())
        let query = DNSWire.query("nope.tail0001.ts.net.", type: 1)
        let response = try DecodedResponse(resolver.response(to: query, at: Date(timeIntervalSince1970: 1_234_567_890.9)))
        let data = try #require(response.authority?.data)
        #expect(Array(data[34..<38]) == [0x49, 0x96, 0x02, 0xD2])
        #expect(Array(data[38...]) == [0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10])
    }

    // MARK: Reverse lookups

    @Test("PTR for the IPv6 service IP and the local IPv6 address")
    func ipv6Pointers() throws {
        let resolver = Self.resolver(try Self.netmap())
        let service = "3.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."
        #expect(try ask(resolver, service, type: 12).answer?.data == DNSWire.name("magicdns.localhost-tailscale-daemon."))
        let selfAddress = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.IP6.ARPA."
        let response = try ask(resolver, selfAddress, type: 12)
        #expect(response.questionName == selfAddress)
        #expect(response.answer?.data == DNSWire.name(Self.selfName))
    }

    @Test("Malformed reverse names get no local answer")
    func malformedReverseNames() throws {
        let resolver = Self.resolver(try Self.netmap())
        for name in ["01.0.64.100.in-addr.arpa.", "0.64.100.in-addr.arpa.", "256.0.64.100.in-addr.arpa.", "in-addr.arpa.",
                     "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."] {
            #expect(try ask(resolver, name, type: 12).responseCode == 2, "\(name)")
        }
    }

    @Test("PTR for an unknown address returns NXDOMAIN + SOA inside the zone and SERVFAIL outside")
    func unknownPointers() throws {
        let resolver = Self.resolver(try Self.netmap())
        let inside = try ask(resolver, "9.0.64.100.in-addr.arpa.", type: 12)
        #expect(inside.responseCode == 3)
        #expect(inside.authority?.name == "64.100.in-addr.arpa.")
        #expect(try ask(resolver, "1.0.168.192.in-addr.arpa.", type: 12).responseCode == 2)
    }

    // MARK: UDP size

    @Test("Without EDNS, TC is clear through 512 bytes and set at 513 bytes")
    func truncationAt512() throws {
        // NXDOMAIN for a zone with a 100-byte presentation form (101 bytes in wire format) takes 47 + the length of the question's first label + 4 × 101 bytes.
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

    // MARK: Random input

    @Test("Return a response with a header without trapping, even for random bytes and partially modified queries")
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
