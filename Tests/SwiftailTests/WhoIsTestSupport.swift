// Shared `whoIs` test helpers for netmaps with configurable nodes and user profiles.
// The fields of tailcfg values are inaccessible externally, so create the values by decoding the same JSON the control server sends.

import Foundation
import SwiftailControl
import Testing

enum WhoIsTestSupport {
    /// One node to include in a netmap. Defaults to a regular node created by user 101.
    struct TestNode {
        var id: Int64
        var stableID: String
        var name: String
        var user: Int64 = 101
        var key: UInt8
        var addresses: [String]
        /// A nil value means the control server omitted `AllowedIPs`, so it is the same as `addresses`.
        var allowedIPs: [String]?
        var hostname: String = ""
        var tags: [String] = []
        var expired = false
        /// The key expiration time. A nil value means it does not expire.
        var keyExpiry: Date?
        var online = true
    }

    static let selfName = "rd-mac-1a2b3c4d.tail0001.ts.net."

    static let selfNode = TestNode(
        id: 1, stableID: "nStableSelf", name: selfName, key: 0x11, addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])

    static let phone = TestNode(
        id: 2, stableID: "nStablePhone", name: "rd-phone-1a2b3c4d.tail0001.ts.net.", key: 0x22,
        addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])

    static let alice = (id: Int64(101), loginName: "alice@example.com")

    /// A netmap with `selfNode` and `peers`. Only users in `profiles` are in the netmap's `userProfiles`.
    static func netmap(
        selfNode: TestNode = selfNode, peers: [TestNode] = [], profiles: [(id: Int64, loginName: String)] = [alice]
    ) throws -> Netmap {
        func list(_ values: [String]) -> String { values.map { "\"\($0)\"" }.joined(separator: ",") }
        func json(_ node: TestNode) -> String {
            #"{"ID":\#(node.id),"StableID":"\#(node.stableID)","Name":"\#(node.name)","User":\#(node.user),"#
                + #""Key":"\#(NodeTestSupport.nodeKey(node.key))","Addresses":[\#(list(node.addresses))],"#
                + (node.allowedIPs.map { #""AllowedIPs":[\#(list($0))],"# } ?? "")
                + (node.keyExpiry.map { #""KeyExpiry":"\#($0.formatted(Date.ISO8601FormatStyle(includingFractionalSeconds: true)))","# } ?? "")
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
