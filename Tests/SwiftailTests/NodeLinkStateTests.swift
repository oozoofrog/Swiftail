import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

/// 끊긴 연결과 `running`·`reconnecting`. 계약 노드 API 동작 3·4.
@Suite("노드의 연결 상태")
struct NodeLinkStateTests {
    private static let derpNode =
        #"{"Name":"1a","RegionID":1,"HostName":"derp.example.com","IPv4":"127.0.0.1","IPv6":"none","DERPPort":8443}"#

    /// 자기 주소가 `100.64.0.1`인 netmap. `regions`는 DERPMap의 `Regions` 안쪽 JSON이다.
    private static func netmap(regions: String) throws -> Netmap {
        let key = "nodekey:" + String(repeating: "11", count: 32)
        let json = #"{"Node":{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":101,"Key":"\#(key)","Addresses":["100.64.0.1/32"]},"#
            + #""Peers":[],"DERPMap":{"Regions":{\#(regions)}}}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    /// 고치기 전에는 DERP가 끊긴 채로 홈 지역이 없어지면 끊긴 연결 목록에서 DERP가 빠지지 않아 `running`이 다시 나오지 않았다.
    @Test("DERP가 끊긴 뒤 홈 지역이 없어지면 DERP를 끊긴 것으로 세지 않고 running을 다시 알린다")
    func homeLossClearsBrokenDERP() async throws {
        let node = TailnetNode(configuration: NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")),
            hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9"))
        ))
        await node.apply(try Self.netmap(regions: #""1":{"RegionID":1,"Nodes":[\#(Self.derpNode)]}"#))
        await node.linkBroke(.derp)
        await node.apply(try Self.netmap(regions: ""))

        #expect(await node.brokenLinks.isEmpty)
        await node.eventContinuation.finish()
        var seen: [String] = []
        for await event in node.events {
            switch event {
            case let .running(addresses): seen.append("running \(addresses.map(\.description))")
            case .reconnecting: seen.append("reconnecting")
            case .loginRequired: seen.append("loginRequired")
            case .peerPathChanged: seen.append("peerPathChanged")
            }
        }
        #expect(seen == ["running [\"100.64.0.1\"]", "reconnecting", "running [\"100.64.0.1\"]"])
    }
}
