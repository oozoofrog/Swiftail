// `whoIs` 시험의 공용 도우미: 노드와 사용자 프로필을 고를 수 있는 netmap.
// tailcfg 값의 필드는 바깥에서 쓸 수 없으므로 제어 서버가 보내는 것과 같은 JSON을 해독해 만든다.

import Foundation
import SwiftailControl
import Testing

enum WhoIsTestSupport {
    /// netmap에 넣을 노드 하나. 기본값은 사용자 101이 만든 평범한 노드다.
    struct TestNode {
        var id: Int64
        var stableID: String
        var name: String
        var user: Int64 = 101
        var key: UInt8
        var addresses: [String]
        /// nil이면 제어 서버가 `AllowedIPs`를 생략한 것이고, `addresses`와 같다.
        var allowedIPs: [String]?
        var hostname: String = ""
        var tags: [String] = []
        var expired = false
        var online = true
    }

    static let selfName = "rd-mac-1a2b3c4d.tail0001.ts.net."

    static let selfNode = TestNode(
        id: 1, stableID: "nStableSelf", name: selfName, key: 0x11, addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])

    static let phone = TestNode(
        id: 2, stableID: "nStablePhone", name: "rd-phone-1a2b3c4d.tail0001.ts.net.", key: 0x22,
        addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])

    static let alice = (id: Int64(101), loginName: "alice@example.com")

    /// `selfNode`와 `peers`의 netmap. `profiles`에 든 사용자만 netmap의 `userProfiles`에 있다.
    static func netmap(
        selfNode: TestNode = selfNode, peers: [TestNode] = [], profiles: [(id: Int64, loginName: String)] = [alice]
    ) throws -> Netmap {
        func list(_ values: [String]) -> String { values.map { "\"\($0)\"" }.joined(separator: ",") }
        func json(_ node: TestNode) -> String {
            #"{"ID":\#(node.id),"StableID":"\#(node.stableID)","Name":"\#(node.name)","User":\#(node.user),"#
                + #""Key":"\#(NodeTestSupport.nodeKey(node.key))","Addresses":[\#(list(node.addresses))],"#
                + (node.allowedIPs.map { #""AllowedIPs":[\#(list($0))],"# } ?? "")
                + #""Hostinfo":{"Hostname":"\#(node.hostname)"},"Tags":[\#(list(node.tags))],"#
                + #""Expired":\#(node.expired),"Online":\#(node.online),"HomeDERP":1,"MachineAuthorized":true}"#
        }
        let profileList = profiles.map { #"{"ID":\#($0.id),"LoginName":"\#($0.loginName)"}"# }.joined(separator: ",")
        let document = #"{"Node":\#(json(selfNode)),"Peers":[\#(peers.map(json).joined(separator: ","))],"#
            + #""UserProfiles":[\#(profileList)],"Domain":"tail0001.ts.net"}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(document.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }
}
