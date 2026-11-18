import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailMagicsock
import Testing
@testable import Swiftail

/// Tests selection of `Magicsock` home candidate regions from a DERPMap and conversion from `DERPNode` to `DERPServer`.
/// Engine contract "Changes in M4" N3, magicsock contract behavior E3, derp-stun notes 4.1·4.8.
@Suite("DERPMap conversion")
struct DERPMapConversionTests {
    /// DERP node JSON. The defaults describe one usable server.
    private static func node(
        hostName: String = "derp.example.com",
        certName: String = "",
        ipv4: String = "127.0.0.1",
        ipv6: String = "none",
        derpPort: Int = 8443,
        stunPort: Int = 0,
        stunTestIP: String = "",
        stunOnly: Bool = false,
        insecureForTests: Bool = false
    ) -> String {
        #"{"Name":"1a","RegionID":1,"HostName":"\#(hostName)","CertName":"\#(certName)","IPv4":"\#(ipv4)","IPv6":"\#(ipv6)","#
            + #""DERPPort":\#(derpPort),"STUNPort":\#(stunPort),"STUNTestIP":"\#(stunTestIP)","#
            + #""STUNOnly":\#(stunOnly),"InsecureForTests":\#(insecureForTests)}"#
    }

    private static func derpMap(_ regions: String, homeParams: String = "") throws -> DERPMap {
        let params = homeParams.isEmpty ? "" : #","HomeParams":\#(homeParams)"#
        return try JSONDecoder().decode(DERPMap.self, from: Data(#"{"Regions":{\#(regions)}\#(params)}"#.utf8))
    }

    private static func server(_ json: String) throws -> DERPServer? {
        DERPServer(try JSONDecoder().decode(DERPNode.self, from: Data(json.utf8)))
    }

    private static func stun(_ json: String) throws -> IPEndpoint? {
        Magicsock.Region.stunServer(of: try JSONDecoder().decode(DERPNode.self, from: Data(json.utf8)))
    }

    private static func endpoint(_ text: String) throws -> IPEndpoint {
        try #require(IPEndpoint(text))
    }

    // MARK: Home candidate regions

    @Test("Selects usable regions in ascending ID order")
    func candidatesInOrder() throws {
        let map = try Self.derpMap(#""9":{"RegionID":9,"Nodes":[\#(Self.node())]},"2":{"RegionID":2,"Nodes":[\#(Self.node())]},"10":{"RegionID":10,"Nodes":[\#(Self.node())]}"#)
        #expect(Magicsock.Region.homeCandidates(in: map).map(\.id) == [2, 9, 10])
    }

    @Test("Excludes noMeasureNoHome regions and regions without a server to connect to. An absent DERPMap gives an empty list")
    func skipsUnusableRegions() throws {
        let stunOnly = Self.node(stunOnly: true)
        let map = try Self.derpMap(
            #""1":{"RegionID":1,"NoMeasureNoHome":true,"Nodes":[\#(Self.node())]},"2":{"RegionID":2,"Nodes":[\#(stunOnly)]},"#
                + #""3":{"RegionID":3,"Nodes":[]},"4":{"RegionID":4,"Nodes":[\#(Self.node())]}"#
        )
        #expect(Magicsock.Region.homeCandidates(in: map).map(\.id) == [4])
        #expect(Magicsock.Region.homeCandidates(in: nil).isEmpty)
        #expect(Magicsock.Region.homeCandidates(in: try Self.derpMap("")).isEmpty)
    }

    @Test("Collects STUN addresses from the region's nodes in order, including stunOnly nodes. Uses the score from regionScore, or 0 if absent")
    func stunServersAndScore() throws {
        let first = Self.node(ipv4: "127.0.0.1", stunPort: 3479)
        let stunOnly = Self.node(ipv4: "127.0.0.2", stunOnly: true)
        let noSTUN = Self.node(ipv4: "127.0.0.3", stunPort: -1)
        let map = try Self.derpMap(
            #""1":{"RegionID":1,"Nodes":[\#(first),\#(stunOnly),\#(noSTUN)]},"2":{"RegionID":2,"Nodes":[\#(Self.node())]}"#,
            homeParams: #"{"RegionScore":{"1":1.5}}"#
        )
        #expect(Magicsock.Region.homeCandidates(in: map) == [
            Magicsock.Region(id: 1, stunServers: [try Self.endpoint("127.0.0.1:3479"), try Self.endpoint("127.0.0.2:3478")], score: 1.5),
            Magicsock.Region(id: 2, stunServers: [try Self.endpoint("127.0.0.1:3478")], score: 0),
        ])
    }

    @Test("STUN addresses prefer stunTestIP, use only IPv4 literals, use 3478 for port 0, and skip negative and out-of-range ports")
    func stunServerRules() throws {
        #expect(try Self.stun(Self.node(ipv4: "127.0.0.1", stunTestIP: "127.0.0.9")) == (try Self.endpoint("127.0.0.9:3478")))
        #expect(try Self.stun(Self.node(stunTestIP: "::1")) == nil)
        #expect(try Self.stun(Self.node(ipv4: "")) == nil)
        #expect(try Self.stun(Self.node(ipv4: "none")) == nil)
        #expect(try Self.stun(Self.node(ipv4: "::1")) == nil)
        #expect(try Self.stun(Self.node(stunPort: 0)) == (try Self.endpoint("127.0.0.1:3478")))
        #expect(try Self.stun(Self.node(stunPort: 65535)) == (try Self.endpoint("127.0.0.1:65535")))
        #expect(try Self.stun(Self.node(stunPort: -1)) == nil)
        #expect(try Self.stun(Self.node(stunPort: 65536)) == nil)
    }

    // MARK: DERPServer conversion

    @Test("Test server node: IPv4 address, specified port, verification disabled")
    func testServerNode() throws {
        let server = try #require(try Self.server(Self.node(hostName: "127.0.0.1", insecureForTests: true)))
        #expect(server.hostName == "127.0.0.1")
        #expect(server.targets == [.address(try #require(IPAddress("127.0.0.1")))])
        #expect(server.port == 8443)
        #expect(server.verification == .noneForTests)
    }

    /// Go `shouldDialProto` uses `HostName` for an empty field and the address for a matching-family IP literal. Any other value disables dialing that family.
    /// If both fields disable dialing, the node is unused (`dialNode`'s "both IPv4 and IPv6 are explicitly disabled").
    @Test("All combinations of IPv4 and IPv6 field values {empty, matching-family literal, none, other-family literal, garbage} produce dial targets that match Go's rules")
    func dialTargetsFollowGo() throws {
        let v4 = try #require(IPAddress("192.0.2.1"))
        let v6 = try #require(IPAddress("2001:db8::1"))
        // The value in the field and the target it represents (nil means do not dial that family).
        let ipv4Cells: [(text: String, target: DERPServer.Target?)] = [
            ("", .hostName), ("192.0.2.1", .address(v4)), ("none", nil), ("2001:db8::1", nil), ("derp", nil),
        ]
        let ipv6Cells: [(text: String, target: DERPServer.Target?)] = [
            ("", .hostName), ("2001:db8::1", .address(v6)), ("none", nil), ("192.0.2.1", nil), ("derp", nil),
        ]
        for ipv4 in ipv4Cells {
            for ipv6 in ipv6Cells {
                let server = try Self.server(Self.node(ipv4: ipv4.text, ipv6: ipv6.text))
                let expected: [DERPServer.Target]? = switch (ipv4.target, ipv6.target) {
                case (nil, nil): nil
                case (.hostName?, .hostName?): [.hostName]
                case let (first, second): [first, second].compactMap { $0 }
                }
                #expect(server?.targets == expected, "IPv4 \"\(ipv4.text)\", IPv6 \"\(ipv6.text)\"")
            }
        }
    }

    @Test("Representative dial targets: two literals in IPv4 then IPv6 order, one hostname when both fields are empty, and the hostname plus the other field's literal when only one is empty")
    func dialTargetExamples() throws {
        let v4 = try #require(IPAddress("192.0.2.1"))
        let v6 = try #require(IPAddress("2001:db8::1"))
        #expect(try Self.server(Self.node(ipv4: "192.0.2.1", ipv6: "2001:db8::1"))?.targets == [.address(v4), .address(v6)])
        #expect(try Self.server(Self.node(ipv4: "", ipv6: ""))?.targets == [.hostName])
        #expect(try Self.server(Self.node(ipv4: "", ipv6: "2001:db8::1"))?.targets == [.hostName, .address(v6)])
        #expect(try Self.server(Self.node(ipv4: "none", ipv6: "2001:db8::1"))?.targets == [.address(v6)])
        #expect(try Self.server(Self.node(ipv4: "none", ipv6: "none")) == nil)
        #expect(try Self.server(Self.node(ipv4: "")).map(\.verification) == .system)
    }

    @Test("Uses 443 when derpPort is 0 and skips an out-of-range port")
    func ports() throws {
        #expect(try Self.server(Self.node(derpPort: 0))?.port == 443)
        #expect(try Self.server(Self.node(derpPort: -1)) == nil)
        #expect(try Self.server(Self.node(derpPort: 65536)) == nil)
    }

    @Test("Skips stunOnly nodes and empty hostName values")
    func unusableNodes() throws {
        #expect(try Self.server(Self.node(stunOnly: true)) == nil)
        #expect(try Self.server(Self.node(hostName: "")) == nil)
    }

    @Test("Certificate verification pins the exact suffix of sha256-raw:, uses a certName distinct from hostName as the name, and otherwise follows insecureForTests",
          arguments: [false, true])
    func verification(insecureForTests: Bool) throws {
        func verification(_ certName: String) throws -> DERPServer.Verification? {
            try Self.server(Self.node(certName: certName, insecureForTests: insecureForTests))?.verification
        }
        let hash = String(repeating: "0f", count: 32)
        // 1·2 take precedence over insecureForTests (Go `tlsClient` reinstalls the verification hook when CertName is present).
        #expect(try verification("sha256-raw:\(hash)") == .pinned(sha256Hex: hash))
        #expect(try verification("other.example.com") == .named("other.example.com"))
        // Uppercase, short, and empty values are used as is. In Go too, they match no certificate and the connection fails.
        #expect(try verification("sha256-raw:\(hash.uppercased())") == .pinned(sha256Hex: hash.uppercased()))
        #expect(try verification("sha256-raw:00ff") == .pinned(sha256Hex: "00ff"))
        #expect(try verification("sha256-raw:") == .pinned(sha256Hex: ""))
        // The prefix is case-sensitive (Go `strings.CutPrefix`). A different prefix is a name.
        #expect(try verification("SHA256-RAW:\(hash)") == .named("SHA256-RAW:\(hash)"))
        // 3: If empty or equal to hostName, keep the current behavior.
        let plain: DERPServer.Verification = insecureForTests ? .noneForTests : .system
        #expect(try verification("") == plain)
        #expect(try verification("derp.example.com") == plain)
    }
}
