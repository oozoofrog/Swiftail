// Build a netmap for settings computation tests. Decode the same JSON the control server sends and apply it to a session
// (tailcfg fields cannot be set from outside their module). This helper is separate because `makeNetmap` in `TestSupport.swift` cannot include DNS settings.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

enum SettingsFixture {
    static let selfAddresses = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"]
    /// The fields needed to add a peer to the data plane (disco key and home DERP).
    static let reachable = #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#

    /// A different node key for each node ID.
    static func key(_ id: Int64) -> NodePublicKey {
        var bytes = [UInt8](repeating: 0x42, count: 32)
        for index in 0..<8 {
            bytes[index] = UInt8(truncatingIfNeeded: id >> (8 * (7 - index)))
        }
        return NodePublicKey(rawValue: bytes) ?? .zero
    }

    /// Returns node JSON. `extra` starts with a comma, as in `,"Expired":true`.
    static func node(id: Int64, addresses: [String], name: String? = nil, extra: String = "") -> String {
        let addressList = addresses.map { "\"\($0)\"" }.joined(separator: ",")
        let nodeName = name ?? "node\(id).tail0001.ts.net."
        return #"{"ID":\#(id),"Name":"\#(nodeName)","User":\#(100 + id),"Key":"\#(key(id))","Addresses":[\#(addressList)]\#(extra)}"#
    }

    /// Returns JSON for a peer that can be added to the data plane.
    static func peer(id: Int64, addresses: [String], extra: String = "") -> String {
        node(id: id, addresses: addresses, extra: reachable + extra)
    }

    /// Returns the netmap from a session initialized with one map response. A nil `dns` omits DNSConfig.
    static func netmap(
        selfAddresses: [String] = selfAddresses, selfName: String? = nil, selfExtra: String = "",
        peers: [String] = [], dns: String? = #"{"Proxied":true}"#
    ) throws -> Netmap {
        let selfNode = node(id: 1, addresses: selfAddresses, name: selfName, extra: selfExtra)
        let dnsField = dns.map { #","DNSConfig":\#($0)"# } ?? ""
        let json = #"{"Node":\#(selfNode),"Peers":[\#(peers.joined(separator: ","))]\#(dnsField)}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: wallClockStart).netmap)
    }

    /// Computes the settings. Fails the test if there is no local address.
    static func settings(_ netmap: Netmap, mtu: Int = 1280, at now: Date = wallClockStart) throws -> TunnelNetworkSettings {
        try #require(TunnelNetworkSettings(netmap: netmap, mtu: mtu, at: now))
    }

    /// Returns the `n`th address within CGNAT (`100.64.0.0/10`). `n` is at least 0 and less than 4,194,304.
    static func cgnatAddress(_ n: Int) -> String {
        "100.\(64 + (n >> 16)).\((n >> 8) & 0xFF).\(n & 0xFF)/32"
    }
}
