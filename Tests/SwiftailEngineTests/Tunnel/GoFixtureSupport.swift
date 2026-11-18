// Shared helpers for tests against Go reference fixtures. Read fixture files and convert their node tables to a Netmap.
// tailcfg fields cannot be set from outside their module, so decode the same JSON the control server sends and apply it to a session
// (like `makeNetmap` in `TestSupport.swift`, with a separate helper to include DNSConfig, CapMap, and expiration fields).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// Returns the bytes of one JSON file in `Tests/SwiftailEngineTests/Fixtures`.
func loadGoFixtureData(_ name: String) throws -> Data {
    let url = try #require(
        Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"),
        "Expected the \(name).json resource, got none")
    return try Data(contentsOf: url)
}

/// Values for converting one fixture node into control server node JSON.
struct GoFixtureNode: Sendable {
    var id: Int64
    var name: String
    /// A CIDR string (`100.64.0.1/32`).
    var addresses: [String]
    /// Omit the `AllowedIPs` field if nil.
    var allowedIPs: [String]?
    var expired = false
    /// An RFC 3339 string.
    var keyExpiry: String?
    /// If true, include the disco key and home DERP so the peer can be added to the data plane. The fixture provides no disco key.
    var reachable = false
    /// The local node's `CapMap` keys. The values are `null`, as emitted by Go.
    var capabilities: [String] = []
    /// Capabilities sent in the legacy `Capabilities` list. The session merges them into `CapMap`.
    var legacyCapabilities: [String] = []

    /// A different node key for each node ID.
    private var key: NodePublicKey { makeNodeKey(byte: UInt8(truncatingIfNeeded: id &+ 0x40)) }

    var json: String {
        func list(_ values: [String]) -> String { "[" + values.map { "\"\($0)\"" }.joined(separator: ",") + "]" }
        var text = #"{"ID":\#(id),"Name":"\#(name)","User":\#(100 + id),"Key":"\#(key)","Addresses":\#(list(addresses))"#
        if let allowedIPs { text += #","AllowedIPs":\#(list(allowedIPs))"# }
        if expired { text += #","Expired":true"# }
        if let keyExpiry { text += #","KeyExpiry":"\#(keyExpiry)""# }
        if reachable { text += #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"# }
        if !capabilities.isEmpty {
            text += #","CapMap":{"# + capabilities.map { "\"\($0)\":null" }.joined(separator: ",") + "}"
        }
        if !legacyCapabilities.isEmpty { text += #","Capabilities":\#(list(legacyCapabilities))"# }
        return text + "}"
    }
}

/// Returns the netmap from a session initialized with one map response.
/// - Parameters:
///   - dnsConfigJSON: The JSON object for `DNSConfig`. Omit the field if nil.
///   - receivedAt: When the map response was received (the fixture's `now`).
func makeGoFixtureNetmap(
    selfNode: GoFixtureNode, peers: [GoFixtureNode], dnsConfigJSON: String?, receivedAt: Date
) throws -> Netmap {
    let dnsField = dnsConfigJSON.map { #","DNSConfig":\#($0)"# } ?? ""
    let json = #"{"Node":\#(selfNode.json),"Peers":[\#(peers.map(\.json).joined(separator: ","))]\#(dnsField)}"#
    let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
    var session = MapSession()
    return try #require(try session.apply(response, receivedAt: receivedAt).netmap, "Expected a generated netmap, got nil")
}

/// Parses an RFC 3339 time (`2026-01-02T03:04:05Z`).
func parseGoFixtureDate(_ text: String) throws -> Date {
    let formatter = ISO8601DateFormatter()
    return try #require(formatter.date(from: text), "Expected an RFC 3339 time, got\(text)")
}
