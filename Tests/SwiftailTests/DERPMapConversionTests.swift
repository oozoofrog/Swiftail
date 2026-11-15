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
        #expect(server.targets == [.address(try #require(IPAddress("127.0.0.1")))])
        #expect(server.port == 8443)
        #expect(server.verification == .noneForTests)
    }

    /// Go `shouldDialProto`: 빈 칸은 `HostName`, 그 칸의 체계의 IP 리터럴은 그 주소, 그 밖의 값은 그 체계를 걸지 않는다.
    /// 두 칸이 모두 걸지 않으면 그 노드는 쓰지 않는다(`dialNode`의 "both IPv4 and IPv6 are explicitly disabled").
    @Test("걸 대상: IPv4·IPv6 칸의 {빈 값, 맞는 체계의 리터럴, none, 다른 체계의 리터럴, 쓰레기} 모든 조합이 Go 규칙과 같다")
    func dialTargetsFollowGo() throws {
        let v4 = try #require(IPAddress("192.0.2.1"))
        let v6 = try #require(IPAddress("2001:db8::1"))
        // 칸에 넣는 값과, 그 칸이 뜻하는 대상(nil이면 그 체계로 걸지 않는다).
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

    @Test("걸 대상의 대표 경우: 두 리터럴은 IPv4·IPv6 순서, 두 칸이 비면 이름 하나, 한 칸만 비면 이름과 다른 칸의 리터럴")
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
