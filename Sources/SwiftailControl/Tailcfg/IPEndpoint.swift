import SwiftailBase

// tailcfg는 `netip.AddrPort`를 텍스트(`"192.0.2.1:41641"`, `"[2001:db8::1]:41641"`)로 주고받는다.
// SwiftailBase는 JSON을 모르므로 그 텍스트 형식의 Codable을 여기서 붙인다(`IPAddress+Codable.swift`와 같다).

extension IPEndpoint: Codable {
    public init(from decoder: any Decoder) throws {
        self = try decodeText(from: decoder, as: "IP:포트")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
