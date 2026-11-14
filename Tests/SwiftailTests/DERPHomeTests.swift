import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import Testing
@testable import Swiftail

/// 홈 DERP 지역 선택과 `DERPNode` → `DERPServer` 변환. 계약 노드 API 동작 3, 노트 derp-stun 4.1·4.8.
@Suite("홈 DERP 선택")
struct DERPHomeTests {
    /// DERP 노드 JSON. 기본값은 쓸 수 있는 서버 하나다.
    private static func node(
        hostName: String = "derp.example.com",
        certName: String = "",
        ipv4: String = "127.0.0.1",
        ipv6: String = "none",
        derpPort: Int = 8443,
        stunOnly: Bool = false,
        insecureForTests: Bool = false
    ) -> String {
        #"{"Name":"1a","RegionID":1,"HostName":"\#(hostName)","CertName":"\#(certName)","IPv4":"\#(ipv4)","IPv6":"\#(ipv6)","#
            + #""DERPPort":\#(derpPort),"STUNOnly":\#(stunOnly),"InsecureForTests":\#(insecureForTests)}"#
    }

    private static func derpMap(_ regions: String) throws -> DERPMap {
        try JSONDecoder().decode(DERPMap.self, from: Data(#"{"Regions":{\#(regions)}}"#.utf8))
    }

    private static func server(_ json: String) throws -> DERPServer? {
        DERPServer(try JSONDecoder().decode(DERPNode.self, from: Data(json.utf8)))
    }

    // MARK: 지역 선택

    @Test("쓸 수 있는 지역 가운데 ID가 가장 작은 것을 고른다")
    func smallestRegion() throws {
        let map = try Self.derpMap(#""9":{"RegionID":9,"Nodes":[\#(Self.node())]},"2":{"RegionID":2,"Nodes":[\#(Self.node())]},"10":{"RegionID":10,"Nodes":[\#(Self.node())]}"#)
        #expect(DERPHome.choose(from: map, keeping: 0)?.regionID == 2)
    }

    @Test("noMeasureNoHome 지역은 고르지 않는다")
    func skipsNoMeasureNoHome() throws {
        let map = try Self.derpMap(#""1":{"RegionID":1,"NoMeasureNoHome":true,"Nodes":[\#(Self.node())]},"5":{"RegionID":5,"Nodes":[\#(Self.node())]}"#)
        #expect(DERPHome.choose(from: map, keeping: 0)?.regionID == 5)
    }

    @Test("쓸 서버가 없는 지역은 고르지 않는다")
    func skipsRegionWithoutUsableServer() throws {
        let stunOnly = Self.node(stunOnly: true)
        let map = try Self.derpMap(#""1":{"RegionID":1,"Nodes":[\#(stunOnly)]},"2":{"RegionID":2,"Nodes":[]},"3":{"RegionID":3,"Nodes":[\#(Self.node())]}"#)
        let home = DERPHome.choose(from: map, keeping: 0)
        #expect(home?.regionID == 3)
        #expect(home?.servers.count == 1)
    }

    @Test("쓸 수 있는 지역이 없으면 nil")
    func noRegions() throws {
        #expect(DERPHome.choose(from: nil, keeping: 0) == nil)
        #expect(DERPHome.choose(from: try Self.derpMap(""), keeping: 0) == nil)
        let map = try Self.derpMap(#""1":{"RegionID":1,"NoMeasureNoHome":true,"Nodes":[\#(Self.node())]}"#)
        #expect(DERPHome.choose(from: map, keeping: 0) == nil)
    }

    @Test("지금 홈을 계속 쓸 수 있으면 더 작은 지역이 생겨도 그대로 둔다")
    func keepsCurrentHome() throws {
        let map = try Self.derpMap(#""1":{"RegionID":1,"Nodes":[\#(Self.node())]},"7":{"RegionID":7,"Nodes":[\#(Self.node())]}"#)
        #expect(DERPHome.choose(from: map, keeping: 7)?.regionID == 7)
    }

    @Test("지금 홈이 사라지거나 쓸 수 없게 되면 다시 고른다")
    func replacesLostHome() throws {
        let gone = try Self.derpMap(#""4":{"RegionID":4,"Nodes":[\#(Self.node())]}"#)
        #expect(DERPHome.choose(from: gone, keeping: 7)?.regionID == 4)
        let unusable = try Self.derpMap(#""4":{"RegionID":4,"Nodes":[\#(Self.node())]},"7":{"RegionID":7,"NoMeasureNoHome":true,"Nodes":[\#(Self.node())]}"#)
        #expect(DERPHome.choose(from: unusable, keeping: 7)?.regionID == 4)
    }

    @Test("홈 지역의 서버가 바뀌면 결과가 달라진다(클라이언트를 다시 띄울 근거)")
    func serverChangeIsVisible() throws {
        let before = try Self.derpMap(#""1":{"RegionID":1,"Nodes":[\#(Self.node())]}"#)
        let after = try Self.derpMap(#""1":{"RegionID":1,"Nodes":[\#(Self.node(derpPort: 9443))]}"#)
        #expect(DERPHome.choose(from: before, keeping: 1) != DERPHome.choose(from: after, keeping: 1))
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
