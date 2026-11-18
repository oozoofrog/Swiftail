/// A JSON value retained without interpretation. Corresponds to Go `tailcfg.RawMessage`.
///
/// Node capability (`CapMap`) and application grant (`CapGrant.CapMap`) arguments have a different format for each capability.
/// This layer keeps the values as is because their format is unknown here. The consumer of the capability interprets them.
///
/// Stores numbers in `Int64` → `UInt64` → `Double` order. Integers in the 64-bit ranges are preserved exactly,
/// so `9007199254740992` and `9007199254740993` are distinct values (as in Go's `RawMessage`).
/// Integers outside those ranges and high-precision decimals that `Double` cannot represent can round to the same `Double`.
/// Integers written with decimal syntax, such as `1.0`, also become `integer(1)` (Go preserves the bytes).
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    /// An integer in the `Int64` range.
    case integer(Int64)
    /// An integer in the `UInt64` range greater than `Int64.max`.
    case unsignedInteger(UInt64)
    /// Any other number, which may lose precision.
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

extension JSONValue: Decodable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(UInt64.self) {
            self = .unsignedInteger(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: JSONValue].self))
        }
    }
}
