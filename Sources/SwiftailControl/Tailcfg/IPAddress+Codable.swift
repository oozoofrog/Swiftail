import SwiftailBase

// tailcfg는 `netip.Addr`·`netip.Prefix`를 텍스트(`"100.64.0.1"`, `"100.64.0.1/32"`)로 주고받는다.
// SwiftailBase는 JSON을 모르므로 그 텍스트 형식의 Codable을 여기서 붙인다.
// `docs/protocol-notes/control-map.md` 3.1.

extension IPAddress: Codable {
    public init(from decoder: any Decoder) throws {
        self = try decodeText(from: decoder, as: "IP 주소")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension IPPrefix: Codable {
    public init(from decoder: any Decoder) throws {
        self = try decodeText(from: decoder, as: "CIDR 접두")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// 문자열 하나를 `LosslessStringConvertible` 값으로 읽는다. 해석하지 못하면 `dataCorrupted`.
func decodeText<Value: LosslessStringConvertible>(from decoder: any Decoder, as name: String) throws -> Value {
    let container = try decoder.singleValueContainer()
    let text = try container.decode(String.self)
    guard let value = Value(text) else {
        throw DecodingError.dataCorruptedError(in: container, debugDescription: "\(name)가 아니다: \(text)")
    }
    return value
}
