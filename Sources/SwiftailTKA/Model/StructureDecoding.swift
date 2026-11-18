// Shared rules for reading TKA structures (AUM, Key, State, Signature, and NKS) from `CBORValue`. Go reads them using the `fxamacker/cbor` v2.9.3
// struct decoder (`parseMapToStruct`, `parseToValue`, and `fill*` in `decode.go`). Contract behaviors D3–D7, notes §§3.1, 6.2, and 8.1.
// `fxamacker/cbor`: Copyright (c) 2019-present Faye Amacker. MIT.

/// The known field values extracted from a structure map.
///
/// Key rules (behaviors D3 and D4) allow nonnegative integers through 2^63−1, negative integers down to −2^63, and valid UTF-8 text only. Duplicate keys
/// are rejected. Go compares known fields by field number and unknown keys as `int64` or string values, so two encodings of the same integer count as duplicates.
/// Only integer keys identify known fields (text `"1"` is an unknown field, behavior D5). Unknown field values are discarded unread (behavior D6).
struct StructureFields {
    private var values: [UInt64: CBORValue] = [:]

    /// Null (including undefined) behaves like an empty map: all fields are zero values (Go `fillNil` leaves structs untouched). This applies at the top level
    /// and in array elements. The caller first reads null pointer fields (`Key`, `State`, `Nested`) as absent.
    /// Other non-map values are rejected (behavior D7 and type mismatch at a structure position).
    init(_ value: CBORValue, knownKeys: Set<UInt64>) throws(TKAError) {
        if value == .null { return }
        guard case .map(let pairs) = value else { throw .invalidStructure }
        var seen: Set<Key> = []
        for pair in pairs {
            let key = try Key(pair.key)
            guard seen.insert(key).inserted else { throw .invalidStructure }
            if case .integer(let number) = key, number >= 0, knownKeys.contains(UInt64(number)) {
                values[UInt64(number)] = pair.value
            }
        }
    }

    /// The known field value, or nil if absent. Null is retained as `.null`.
    subscript(key: UInt64) -> CBORValue? { values[key] }

    /// The value used to determine whether keys match.
    private enum Key: Hashable {
        case integer(Int64)
        case text([UInt8])

        init(_ value: CBORValue) throws(TKAError) {
            switch value {
            case .unsigned(let number) where number <= UInt64(Int64.max):
                self = .integer(Int64(number))
            case .negative(let number) where number <= UInt64(Int64.max):
                self = .integer(~Int64(number))  // −1 − n
            case .text(let content) where content.isValidUTF8:
                self = .text(content)
            default:
                throw .invalidStructure
            }
        }
    }
}

// MARK: Known Field Values

extension CBORValue {
    /// A value for Go unsigned integer fields (`uint8`, `uint`, `uint64`). Integers and simple values produce their numeric value, and null gives 0 (`fillNil` leaves integers
    /// untouched). Rejects values above `maximum` or of another type (behavior D5).
    func unsignedField(maximum: UInt64 = .max) throws(TKAError) -> UInt64 {
        let number: UInt64
        switch self {
        case .unsigned(let value): number = value
        case .simple(let value): number = UInt64(value)
        case .null: number = 0
        default: throw .invalidStructure
        }
        guard number <= maximum else { throw .invalidStructure }
        return number
    }

    /// A value for Go `[]byte` fields. Null gives nil.
    ///
    /// In addition to byte strings, Go reads arrays of integers or simple values from 0 to 255, or null (0), as bytes (`parseArrayToSlice` fills elements
    /// as `uint8`). Writing again produces a byte string, so its hash matches a byte string with the same contents.
    func byteField() throws(TKAError) -> [UInt8]? {
        switch self {
        case .null:
            return nil
        case .bytes(let content):
            return content
        case .array(let elements):
            var content: [UInt8] = []
            content.reserveCapacity(elements.count)
            for element in elements {
                content.append(UInt8(truncatingIfNeeded: try element.unsignedField(maximum: UInt64(UInt8.max))))
            }
            return content
        default:
            throw .invalidStructure
        }
    }

    /// A value for Go `string` fields (`Meta` keys and values). Requires valid UTF-8 text and treats null as the empty string.
    func textField() throws(TKAError) -> [UInt8] {
        switch self {
        case .null:
            return []
        case .text(let content) where content.isValidUTF8:
            return content
        default:
            throw .invalidStructure
        }
    }

    /// An array for a Go slice field. Null gives an empty array. Used only for fields that treat nil and empty slices alike (behavior E6).
    func arrayField() throws(TKAError) -> [CBORValue] {
        switch self {
        case .null: return []
        case .array(let elements): return elements
        default: throw .invalidStructure
        }
    }
}

extension [UInt8] {
    var isValidUTF8: Bool { String(validating: self, as: UTF8.self) != nil }
}

// MARK: Byte Limit

/// Checks byte length before decoding (behaviors D9 and M) and reads a single item.
func decodeItem(_ bytes: [UInt8], maximumByteCount: Int) throws(TKAError) -> CBORValue {
    guard bytes.count <= maximumByteCount else { throw .limitExceeded }
    do {
        return try CBOR.decode(bytes)
    } catch {
        throw .cbor(error)
    }
}
