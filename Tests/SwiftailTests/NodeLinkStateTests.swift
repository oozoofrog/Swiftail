import CryptoKit
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

    /// 고치기 전에는 DERPMap에서 사라진 지역만 닫아, 서버가 바뀐 지역의 연결이 옛 서버로만 다시 붙으려 했다.
    @Test("서버 정의가 바뀐 지역의 연결은 닫고, 홈이면 새 서버로 다시 연다. 정의가 같으면 그대로 둔다")
    func redefinedRegionIsReopened() async throws {
        let node = TailnetNode(configuration: NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")),
            hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9"))
        ))
        func region(_ id: Int, host: String) -> String {
            #""\#(id)":{"RegionID":\#(id),"Nodes":[{"Name":"\#(id)a","RegionID":\#(id),"HostName":"\#(host)","IPv4":"127.0.0.1","IPv6":"none","DERPPort":8443}]}"#
        }
        await node.setNodeKeyForTesting(Curve25519.KeyAgreement.PrivateKey())
        await node.apply(try Self.netmap(regions: region(1, host: "a.example.com") + "," + region(2, host: "b.example.com")))
        await node.homeRegionChanged(to: 1)
        await node.openDERPLink(to: 2)
        let home = try #require(await node.derpLinks[1])
        let other = try #require(await node.derpLinks[2])

        // 같은 정의가 다시 오면 연결은 그대로다.
        await node.apply(try Self.netmap(regions: region(1, host: "a.example.com") + "," + region(2, host: "b.example.com")))
        #expect(await node.derpLinks[1]?.client === home.client)
        #expect(await node.derpLinks[2]?.client === other.client)

        // 두 지역의 호스트가 바뀐다. 홈은 새 서버로 다시 열리고, 홈이 아닌 지역은 닫힌 채 다음 송신을 기다린다.
        await node.apply(try Self.netmap(regions: region(1, host: "c.example.com") + "," + region(2, host: "d.example.com")))
        let reopened = try #require(await node.derpLinks[1])
        #expect(reopened.client !== home.client)
        #expect(reopened.servers.map(\.hostName) == ["c.example.com"])
        #expect(await node.derpLinks[2] == nil)
    }
}

private extension TailnetNode {
    /// 등록을 거치지 않고 node 키만 넣는다. DERP 연결은 node 키가 있어야 열린다.
    func setNodeKeyForTesting(_ key: Curve25519.KeyAgreement.PrivateKey) {
        nodeKey = key
    }
}
