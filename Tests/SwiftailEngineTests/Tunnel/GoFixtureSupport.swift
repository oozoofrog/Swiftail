// Go 기준 자료 대조 시험의 공용 보조 코드: 자료 파일 읽기와 "자료의 노드 표 → Netmap" 변환.
// tailcfg 값의 필드는 바깥에서 쓸 수 없으므로 제어 서버가 보내는 것과 같은 JSON을 해독해 세션에 적용한다
// (`TestSupport.swift`의 `makeNetmap`과 같은 방식. DNSConfig·CapMap·만료 필드를 실을 수 있게 따로 둔다).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// `Tests/SwiftailEngineTests/Fixtures`의 JSON 파일 하나의 바이트.
func loadGoFixtureData(_ name: String) throws -> Data {
    let url = try #require(
        Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"),
        "기대=\(name).json 리소스 실제=없음")
    return try Data(contentsOf: url)
}

/// 자료의 노드 하나를 제어 서버의 노드 JSON으로 옮기기 위한 값.
struct GoFixtureNode: Sendable {
    var id: Int64
    var name: String
    /// CIDR 문자열(`100.64.0.1/32`).
    var addresses: [String]
    /// nil이면 `AllowedIPs` 필드를 싣지 않는다.
    var allowedIPs: [String]?
    var expired = false
    /// RFC 3339 문자열.
    var keyExpiry: String?
    /// 참이면 disco 키와 홈 DERP를 싣는다(피어를 데이터면에 올릴 수 있는 조건. 자료는 disco 키를 주지 않는다).
    var reachable = false
    /// 자기 노드의 `CapMap` 키들. 값은 Go가 내보낸 것처럼 `null`이다.
    var capabilities: [String] = []
    /// 옛 `Capabilities` 목록으로 싣는 속성(세션이 `CapMap`에 합친다).
    var legacyCapabilities: [String] = []

    /// 노드 ID마다 다른 node 키.
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

/// 맵 응답 하나로 시작한 세션의 netmap.
/// - Parameters:
///   - dnsConfigJSON: `DNSConfig` 필드의 JSON 객체. nil이면 필드를 싣지 않는다.
///   - receivedAt: 맵 응답을 받은 시각(자료의 `now`).
func makeGoFixtureNetmap(
    selfNode: GoFixtureNode, peers: [GoFixtureNode], dnsConfigJSON: String?, receivedAt: Date
) throws -> Netmap {
    let dnsField = dnsConfigJSON.map { #","DNSConfig":\#($0)"# } ?? ""
    let json = #"{"Node":\#(selfNode.json),"Peers":[\#(peers.map(\.json).joined(separator: ","))]\#(dnsField)}"#
    let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
    var session = MapSession()
    return try #require(try session.apply(response, receivedAt: receivedAt).netmap, "기대=netmap 생성 실제=nil")
}

/// RFC 3339 시각(`2026-01-02T03:04:05Z`).
func parseGoFixtureDate(_ text: String) throws -> Date {
    let formatter = ISO8601DateFormatter()
    return try #require(formatter.date(from: text), "기대=RFC 3339 시각 실제=\(text)")
}
