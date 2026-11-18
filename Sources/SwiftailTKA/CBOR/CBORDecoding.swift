// Reads one CBOR item using the same rules as the Go TKA decoder (`cborDecOpts` in `tailscale.com/tka/tka.go`, and well-formedness checks in
// `valid.go` in fxamacker/cbor v2.9.3). Contract behaviors D1, D2, and D9, notes §§3.1, 6.2, and 8.1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.
// `fxamacker/cbor`: Copyright (c) 2019-present Faye Amacker. MIT.

/// Reasons for rejection at the CBOR item level. The structure decoder rejects violations of the AUM or NKS structure.
package enum CBORError: Error, Sendable, Equatable {
    /// Empty input, input ending within an item, or a length field larger than the remaining bytes.
    case truncated
    /// Bytes remain after the first item.
    case trailingBytes
    case indefiniteLength
    case tag
    /// A malformed item: reserved additional information 28–30, additional information 31 on integers or tags, an unmatched break (`ff`),
    /// or a simple value below 32 written in two bytes (RFC 8949 3.3).
    case malformed
    /// At least 17 nested array or map levels (the outermost is level 1).
    case nestingTooDeep
    /// An array of at least 4,097 elements.
    case arrayTooLong
    /// A map of at least 1,025 pairs.
    case mapTooLong
}

/// The entry point for CBOR decoding.
package enum CBOR {
    /// The allowed array or map nesting depth (Go `MaxNestedLevels`).
    static let maximumNestingDepth = 16
    /// The element count per array (Go `MaxArrayElements`).
    static let maximumArrayCount = 4_096
    /// The pair count per map (Go `MaxMapPairs`).
    static let maximumMapPairCount = 1_024

    /// Reads one item. The entire input must be exactly one item.
    ///
    /// Accepts non-shortest integers and unsorted map keys (behavior D2). Leaves text UTF-8 validation, map-key types, and duplicate keys
    /// to the structure decoder (behaviors D3 and D4). Reports the error at the same position Go first encounters when scanning forward.
    /// Does not preallocate based solely on length fields and bounds recursion with `maximumNestingDepth`, so no input can cause a crash.
    package static func decode(_ bytes: [UInt8]) throws(CBORError) -> CBORValue {
        guard !bytes.isEmpty else { throw .truncated }
        var reader = Reader(bytes: bytes)
        let value = try reader.item(depth: 0)
        guard reader.offset == bytes.count else { throw .trailingBytes }
        return value
    }
}

/// A reading position that moves only forward through the input.
private struct Reader {
    let bytes: [UInt8]
    var offset = 0

    /// The item header (RFC 8949 chapter 3), with major type, additional information, and argument.
    private struct Head {
        var major: UInt8
        var info: UInt8
        var argument: UInt64
        var isIndefinite: Bool { info == 31 }
    }

    /// `depth` counts arrays and maps enclosing the item.
    mutating func item(depth: Int) throws(CBORError) -> CBORValue {
        let head = try readHead()
        switch head.major {
        case 0:
            return .unsigned(head.argument)
        case 1:
            return .negative(head.argument)
        case 2, 3:
            guard !head.isIndefinite else { throw .indefiniteLength }
            let content = try readBytes(count: head.argument)
            return head.major == 2 ? .bytes(content) : .text(content)
        case 4, 5:
            // Check in Go's order: depth, indefinite length, then element count. Reject the element count before reading any elements.
            guard depth < CBOR.maximumNestingDepth else { throw .nestingTooDeep }
            guard !head.isIndefinite else { throw .indefiniteLength }
            if head.major == 4 {
                guard head.argument <= UInt64(CBOR.maximumArrayCount) else { throw .arrayTooLong }
                var elements: [CBORValue] = []
                for _ in 0..<head.argument {
                    elements.append(try item(depth: depth + 1))
                }
                return .array(elements)
            } else {
                guard head.argument <= UInt64(CBOR.maximumMapPairCount) else { throw .mapTooLong }
                var pairs: [CBORPair] = []
                for _ in 0..<head.argument {
                    let key = try item(depth: depth + 1)
                    pairs.append(CBORPair(key: key, value: try item(depth: depth + 1)))
                }
                return .map(pairs)
            }
        case 6:
            throw .tag
        default:
            // Major 7: 0–19 and 24 are simple values (only 32 or above survive 24, see `readHead`), 22 is null, and 23 is undefined.
            // The rest (20 false, 21 true, and 25–27 floating-point values) are not retained.
            switch head.info {
            case 22, 23: return .null
            case 0...19, 24: return .simple(UInt8(truncatingIfNeeded: head.argument))
            default: return .simpleOrFloat
            }
        }
    }

    private mutating func readHead() throws(CBORError) -> Head {
        guard offset < bytes.count else { throw .truncated }
        let initial = bytes[offset]
        offset += 1
        let major = initial >> 5
        let info = initial & 0x1f
        switch info {
        case 0...23:
            return Head(major: major, info: info, argument: UInt64(info))
        case 24...27:
            let argument = try readUnsigned(byteCount: 1 << Int(info - 24))
            // Simple values 0–31 use only a one-byte header (RFC 8949 3.3).
            if major == 7, info == 24, argument < 32 { throw .malformed }
            return Head(major: major, info: info, argument: argument)
        case 31:
            // Indefinite length exists only for bstr, tstr, arrays, and maps. In major 7, 31 is an unmatched break.
            guard (2...5).contains(major) else { throw .malformed }
            return Head(major: major, info: info, argument: 0)
        default:
            throw .malformed
        }
    }

    private mutating func readUnsigned(byteCount: Int) throws(CBORError) -> UInt64 {
        guard bytes.count - offset >= byteCount else { throw .truncated }
        var value: UInt64 = 0
        for byte in bytes[offset..<offset + byteCount] {
            value = value << 8 | UInt64(byte)
        }
        offset += byteCount
        return value
    }

    private mutating func readBytes(count: UInt64) throws(CBORError) -> [UInt8] {
        // Compare with the remaining length first to avoid overflow converting to `Int` and allocating for enormous lengths.
        guard count <= UInt64(bytes.count - offset) else { throw .truncated }
        let end = offset + Int(count)
        let content = Array(bytes[offset..<end])
        offset = end
        return content
    }
}
