// 설정 산출 시험의 netmap 만들기. 제어 서버가 보내는 것과 같은 JSON을 해독해 세션에 적용한다
// (tailcfg 값의 필드는 바깥에서 쓸 수 없다). `TestSupport.swift`의 `makeNetmap`은 DNS 설정을 싣지 못해 따로 둔다.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

enum SettingsFixture {
    static let selfAddresses = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"]
    /// 피어를 데이터면에 올리는 데 필요한 필드(disco 키와 홈 DERP).
    static let reachable = #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#

    /// 노드 ID마다 다른 node 키.
    static func key(_ id: Int64) -> NodePublicKey {
        var bytes = [UInt8](repeating: 0x42, count: 32)
        for index in 0..<8 {
            bytes[index] = UInt8(truncatingIfNeeded: id >> (8 * (7 - index)))
        }
        return NodePublicKey(rawValue: bytes) ?? .zero
    }

    /// 노드 JSON. `extra`는 `,"Expired":true`처럼 쉼표로 시작한다.
    static func node(id: Int64, addresses: [String], name: String? = nil, extra: String = "") -> String {
        let addressList = addresses.map { "\"\($0)\"" }.joined(separator: ",")
        let nodeName = name ?? "node\(id).tail0001.ts.net."
        return #"{"ID":\#(id),"Name":"\#(nodeName)","User":\#(100 + id),"Key":"\#(key(id))","Addresses":[\#(addressList)]\#(extra)}"#
    }

    /// 데이터면에 올릴 수 있는 피어 JSON.
    static func peer(id: Int64, addresses: [String], extra: String = "") -> String {
        node(id: id, addresses: addresses, extra: reachable + extra)
    }

    /// 맵 응답 하나로 시작한 세션의 netmap. `dns`가 nil이면 DNSConfig 필드가 없다.
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

    /// 설정을 산출한다. 자기 주소가 없으면 시험 실패.
    static func settings(_ netmap: Netmap, mtu: Int = 1280, at now: Date = wallClockStart) throws -> TunnelNetworkSettings {
        try #require(TunnelNetworkSettings(netmap: netmap, mtu: mtu, at: now))
    }

    /// CGNAT(`100.64.0.0/10`) 안의 `n`번째 주소. `n`은 0 이상 4,194,304 미만이다.
    static func cgnatAddress(_ n: Int) -> String {
        "100.\(64 + (n >> 16)).\((n >> 8) & 0xFF).\(n & 0xFF)/32"
    }
}
