import Foundation

// Helpers for reading and writing individual Go `encoding/json` fields whose representations differ from Swift `Codable` defaults.
// Model `init(from:)` and `encode(to:)` use these helpers to keep the listed wire formats independent of value strategies such as date encoding.
// Decoder or encoder settings that change the JSON key names still apply.
//
// - Time: An RFC 3339 string (`GoTime`).
// - Byte sequences (`[]byte`, `MarshaledSignature`): Standard base64 strings with padding.
// - Maps with integer ID keys (such as `map[NodeID]bool`): JSON objects with decimal integer strings as keys.
//
// On decoding, Go treats both `null` and absent keys as the zero value. A `nil` from `decodeIfPresent` therefore matches Go
// when it represents both. Delta semantics distinguish `nil` from empty arrays and objects, a distinction `Optional<[T]>`
// preserves. `docs/protocol-notes/control-map.md` §3.1.

extension KeyedDecodingContainer {
    /// A timestamp, or `nil` for a missing key or `null`. Returns the zero time unchanged because its meaning varies by field.
    func decodeTimeIfPresent(forKey key: Key) throws -> Date? {
        guard let text = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let date = GoTime.parse(text) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Expected an RFC 3339 timestamp")
        }
        return date
    }

    /// A base64 byte sequence, or `nil` for a missing key or `null`.
    func decodeBytesIfPresent(forKey key: Key) throws -> [UInt8]? {
        guard let text = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let data = Data(base64Encoded: text) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Expected base64")
        }
        return [UInt8](data)
    }

    /// A JSON object with decimal integer strings as keys. A noninteger or out-of-range key is an error.
    func decodeIntegerKeyedIfPresent<Value: Decodable>(_ type: Value.Type, forKey key: Key) throws -> [Int64: Value]? {
        guard let object = try decodeIfPresent([String: Value].self, forKey: key) else { return nil }
        var result: [Int64: Value] = [:]
        for (text, value) in object {
            guard let id = Int64(text) else {
                throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "Expected an integer key: \(text)")
            }
            result[id] = value
        }
        return result
    }

    /// `NodeCapMap` and `PeerCapMap`: Capability name → argument array. A `null` value means an empty array (no arguments).
    func decodeCapMapIfPresent(forKey key: Key) throws -> [String: [JSONValue]]? {
        try decodeIfPresent([String: [JSONValue]?].self, forKey: key)?.mapValues { $0 ?? [] }
    }
}

extension KeyedEncodingContainer {
    /// A timestamp. Writes Go's zero time for `nil` (a `time.Time` field without `omitempty`).
    mutating func encodeTime(_ date: Date?, forKey key: Key) throws {
        guard let text = GoTime.format(date ?? GoTime.zero) else {
            throw EncodingError.invalidValue(date as Any, .init(codingPath: codingPath + [key], debugDescription: "Timestamp outside the year range 0~9999"))
        }
        try encode(text, forKey: key)
    }

    /// A byte sequence. Writes `null` if empty (a Go nil slice without `omitempty`).
    mutating func encodeBytesOrNull(_ bytes: [UInt8], forKey key: Key) throws {
        if bytes.isEmpty {
            try encodeNil(forKey: key)
        } else {
            try encode(Data(bytes).base64EncodedString(), forKey: key)
        }
    }

    /// Omits zero values (empty string, `false`, 0, empty array, or empty object). Matches Go's `omitempty` and `omitzero`.
    mutating func encodeUnlessEmpty(_ value: String, forKey key: Key) throws {
        if !value.isEmpty { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty(_ value: Bool, forKey key: Key) throws {
        if value { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty(_ value: Int64, forKey key: Key) throws {
        if value != 0 { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty<Element: Encodable>(_ value: [Element], forKey key: Key) throws {
        if !value.isEmpty { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty<Value: Encodable>(_ value: [String: Value], forKey key: Key) throws {
        if !value.isEmpty { try encode(value, forKey: key) }
    }
}
