import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailMagicsock
import Testing
@testable import Swiftail

/// DERPMap에서 `Magicsock`의 홈 후보 지역 뽑기와 `DERPNode` → `DERPServer` 변환.
/// 계약 엔진 "M4에서 바뀌는 것" N3, magicsock 계약 동작 E3, 노트 derp-stun 4.1·4.8.
@Suite("DERPMap 변환")
struct DERPMapConversionTests {
    /// DERP 노드 JSON. 기본값은 쓸 수 있는 서버 하나다.
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

    // MARK: 홈 후보 지역

    @Test("쓸 수 있는 지역을 ID 오름차순으로 뽑는다")
    func candidatesInOrder() throws {
        let map = try Self.derpMap(#""9":{"RegionID":9,"Nodes":[\#(Self.node())]},"2":{"RegionID":2,"Nodes":[\#(Self.node())]},"10":{"RegionID":10,"Nodes":[\#(Self.node())]}"#)
        #expect(Magicsock.Region.homeCandidates(in: map).map(\.id) == [2, 9, 10])
    }

    @Test("noMeasureNoHome 지역과 연결할 서버가 없는 지역은 뺀다. DERPMap이 없으면 빈 목록이다")
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

    @Test("STUN 주소는 지역의 노드를 순서대로 모으고 stunOnly 노드도 넣는다. 점수는 regionScore에서, 없으면 0")
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

    @Test("STUN 주소: stunTestIP가 앞서고, IPv4 리터럴만 쓰며, 포트 0은 3478, 음수와 범위 밖은 쓰지 않는다")
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

    // MARK: DERPServer 변환

    @Test("시험 서버의 노드: IPv4 주소, 지정 포트, 검증 끔")
    func testServerNode() throws {
        let server = try #require(try Self.server(Self.node(hostName: "127.0.0.1", insecureForTests: true)))
        #expect(server.hostName == "127.0.0.1")
        #expect(server.address == IPAddress("127.0.0.1"))
        #expect(server.port == 8443)
        #expect(server.verification == .noneForTests)
    }

    @Test("IPv4가 비었으면 DNS로 찾는다")
    func emptyIPv4UsesDNS() throws {
        let server = try #require(try Self.server(Self.node(ipv4: "")))
        #expect(server.address == nil)
        #expect(server.verification == .system)
    }

    @Test("IPv4가 none이면 IPv6를 같은 규칙으로 본다")
    func fallsBackToIPv6() throws {
        let literal = try #require(try Self.server(Self.node(ipv4: "none", ipv6: "::1")))
        #expect(literal.address == IPAddress("::1"))
        let dns = try #require(try Self.server(Self.node(ipv4: "none", ipv6: "")))
        #expect(dns.address == nil)
    }

    @Test("IPv4 칸의 IPv6 주소는 IPv4로 쓰지 않는다")
    func wrongFamilyIsNotUsed() throws {
        #expect(try Self.server(Self.node(ipv4: "::1")) == nil)
        #expect(try Self.server(Self.node(ipv4: "none", ipv6: "127.0.0.1")) == nil)
    }

    @Test("IPv4와 IPv6를 둘 다 쓸 수 없으면 건너뛴다")
    func neitherFamily() throws {
        #expect(try Self.server(Self.node(ipv4: "none", ipv6: "none")) == nil)
    }

    @Test("derpPort가 0이면 443, 범위 밖이면 건너뛴다")
    func ports() throws {
        #expect(try Self.server(Self.node(derpPort: 0))?.port == 443)
        #expect(try Self.server(Self.node(derpPort: -1)) == nil)
        #expect(try Self.server(Self.node(derpPort: 65536)) == nil)
    }

    @Test("stunOnly 노드와 빈 hostName은 건너뛴다")
    func unusableNodes() throws {
        #expect(try Self.server(Self.node(stunOnly: true)) == nil)
        #expect(try Self.server(Self.node(hostName: "")) == nil)
    }

    @Test("certName이 hostName과 다르면 건너뛰고, 같으면 쓴다")
    func certName() throws {
        #expect(try Self.server(Self.node(certName: "other.example.com")) == nil)
        #expect(try Self.server(Self.node(certName: "sha256-raw:00ff")) == nil)
        #expect(try Self.server(Self.node(certName: "derp.example.com")) != nil)
    }
}
