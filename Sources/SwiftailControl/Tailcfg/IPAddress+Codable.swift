import SwiftailBase

// tailcfg exchanges `netip.Addr` and `netip.Prefix` as text (`"100.64.0.1"`, `"100.64.0.1/32"`).
// SwiftailBase has no JSON support, so add Codable for that text format here.
// `docs/protocol-notes/control-map.md` 3.1.

extension IPAddress: Codable {
    public init(from decoder: any Decoder) throws {
        self = try decodeText(from: decoder, as: "IP address")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension IPPrefix: Codable {
    public init(from decoder: any Decoder) throws {
        self = try decodeText(from: decoder, as: "CIDR prefix")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// Decodes a string as a `LosslessStringConvertible` value. Throws `dataCorrupted` if parsing fails.
func decodeText<Value: LosslessStringConvertible>(from decoder: any Decoder, as name: String) throws -> Value {
    let container = try decoder.singleValueContainer()
    let text = try container.decode(String.self)
    guard let value = Value(text) else {
        throw DecodingError.dataCorruptedError(in: container, debugDescription: "Expected \(name): \(text)")
    }
    return value
}
