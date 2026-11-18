import SwiftailBase

// tailcfg exchanges `netip.AddrPort` as text (`"192.0.2.1:41641"`, `"[2001:db8::1]:41641"`).
// SwiftailBase has no JSON support, so add Codable for that text format here (as in `IPAddress+Codable.swift`).

extension IPEndpoint: Codable {
    public init(from decoder: any Decoder) throws {
        self = try decodeText(from: decoder, as: "IP:port")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
