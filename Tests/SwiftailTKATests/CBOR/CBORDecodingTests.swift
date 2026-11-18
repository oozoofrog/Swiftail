import Testing

@testable import SwiftailTKA

/// Item-level checks in contract §7 test 2 (behaviors D1, D2, and D9). TL-2 tests structure-level outcomes (key kinds, duplicates, and types).
@Suite("CBOR reading")
struct CBORDecodingTests {
    private func decode(_ hex: String) throws -> CBORValue {
        try CBOR.decode(#require(CBORTesting.bytes(hex: hex)))
    }

    private func rejection(_ hex: String) throws -> CBORError? {
        let input = try #require(CBORTesting.bytes(hex: hex))
        do {
            _ = try CBOR.decode(input)
            return nil
        } catch {
            return error
        }
    }

    // MARK: Acceptance and value representation

    @Test("Non-shortest integers and lengths decode to the same values")
    func nonShortest() throws {
        for hex in ["01", "1801", "190001", "1a00000001", "1b0000000000000001"] {
            #expect(try decode(hex) == .unsigned(1), "\(hex)")
        }
        #expect(try decode("3800") == .negative(0))
        #expect(try decode("5b0000000000000002abcd") == .bytes([0xab, 0xcd]))
        #expect(try decode("790001ff") == .text([0xff]))
        #expect(try decode("9a0000000100") == .array([.unsigned(0)]))
        #expect(try decode("b8010102") == .map([CBORPair(key: .unsigned(1), value: .unsigned(2))]))
    }

    @Test("Maps retain order and duplicates as received")
    func mapKeepsOrderAndDuplicates() throws {
        #expect(
            try decode("a3020101010103")
                == .map([
                    CBORPair(key: .unsigned(2), value: .unsigned(1)),
                    CBORPair(key: .unsigned(1), value: .unsigned(1)),
                    CBORPair(key: .unsigned(1), value: .unsigned(3)),
                ])
        )
    }

    @Test("Major type 7: null and undefined become null, simple values retain their value, and the rest become simpleOrFloat")
    func simpleValues() throws {
        #expect(try decode("f6") == .null)
        #expect(try decode("f7") == .null)
        for (hex, value) in [("e0", 0), ("f3", 19), ("f820", 32), ("f8ff", 255)] as [(String, UInt8)] {
            #expect(try decode(hex) == .simple(value), "\(hex)")
        }
        for hex in ["f4", "f5", "f90000", "f97e00", "fa7f800000", "fbfff0000000000000"] {
            #expect(try decode(hex) == .simpleOrFloat, "\(hex)")
        }
    }

    @Test("Text UTF-8 is not checked")
    func textNotValidated() throws {
        #expect(try decode("62c328") == .text([0xc3, 0x28]))
    }

    // MARK: Item-level rejection

    @Test("Empty input and trailing bytes")
    func emptyAndTrailing() throws {
        #expect(try rejection("") == .truncated)
        #expect(try rejection("0000") == .trailingBytes)
        #expect(try rejection("a0f6") == .trailingBytes)
        #expect(try rejection("80ff") == .trailingBytes)
    }

    @Test("Indefinite lengths are rejected for all four major types")
    func indefinite() throws {
        for hex in ["5fff", "7fff", "9fff", "bfff", "5f4101ff", "a1019f01ff"] {
            #expect(try rejection(hex) == .indefiniteLength, "\(hex)")
        }
    }

    @Test("Tags are rejected anywhere")
    func tags() throws {
        for hex in ["c000", "d74401020304", "d818456449455446", "db000000000000000100", "8201c24101", "a101c100"] {
            #expect(try rejection(hex) == .tag, "\(hex)")
        }
    }

    @Test("Malformed headers")
    func malformedHeads() throws {
        var hexes: [String] = []
        // Reserved additional information 28–30 in all major types.
        for major in 0..<8 {
            for info in 28...30 {
                hexes.append(CBORTesting.hex([UInt8(major << 5 | info)]))
            }
        }
        // Value 31 in a major type without indefinite lengths, and an unmatched break.
        hexes += ["1f", "3f", "df", "ff", "81ff", "a1ff"]
        // Simple values below 32 encoded in two bytes.
        hexes += (0..<32).map { "f8" + CBORTesting.hex([UInt8($0)]) }
        for hex in hexes {
            #expect(try rejection(hex) == .malformed, "\(hex)")
        }
    }

    @Test("Truncated headers and contents")
    func truncatedItems() throws {
        for hex in ["18", "1900", "1a000000", "1b00000000000000", "38", "41", "5801", "6261", "81", "8201", "a1", "a101", "d8", "f8", "f900", "fa000000", "fb00"] {
            #expect(try rejection(hex) == .truncated, "\(hex)")
        }
    }

    @Test("Length fields beyond the remaining bytes are rejected without allocating")
    func hugeLengths() throws {
        for hex in ["5bffffffffffffffff", "5b7fffffffffffffff00", "7bffffffffffffffff", "5affffffff00", "59ffff"] {
            #expect(try rejection(hex) == .truncated, "\(hex)")
        }
        // Arrays and maps are rejected on element count before reading the elements.
        #expect(try rejection("9bffffffffffffffff") == .arrayTooLong)
        #expect(try rejection("9a00001001") == .arrayTooLong)
        #expect(try rejection("bbffffffffffffffff") == .mapTooLong)
        #expect(try rejection("b90401") == .mapTooLong)
        // An in-limit count with missing elements is truncated.
        #expect(try rejection("991000") == .truncated)
        #expect(try rejection("b90400") == .truncated)
    }

    // MARK: Limit boundaries (note §8.1: 16/17 levels, 4,096/4,097 elements, and 1,024/1,025 pairs)

    @Test("Accepts up to 16 nesting levels", arguments: [CBORNesting.arrays, .maps, .mixed])
    func nesting(kind: CBORNesting) throws {
        #expect(throws: Never.self) { try CBOR.decode(kind.bytes(depth: 16)) }
        #expect(throws: CBORError.nestingTooDeep) { try CBOR.decode(kind.bytes(depth: 17)) }
        #expect(throws: CBORError.nestingTooDeep) { try CBOR.decode(kind.bytes(depth: 40)) }
    }

    @Test("An item beyond the depth limit is rejected for depth first, even if its length is indefinite")
    func nestingCheckedBeforeIndefinite() throws {
        let deep = [UInt8](repeating: 0x81, count: 16) + [0x9f, 0xff]
        #expect(throws: CBORError.nestingTooDeep) { try CBOR.decode(deep) }
    }

    @Test("Accepts arrays of up to 4,096 elements")
    func arrayLimit() {
        let accepted: [UInt8] = [0x99, 0x10, 0x00] + [UInt8](repeating: 0, count: 4_096)
        #expect((try? CBOR.decode(accepted)) == .array([CBORValue](repeating: .unsigned(0), count: 4_096)))
        let rejected: [UInt8] = [0x99, 0x10, 0x01] + [UInt8](repeating: 0, count: 4_097)
        #expect(throws: CBORError.arrayTooLong) { try CBOR.decode(rejected) }
    }

    @Test("Accepts maps of up to 1,024 pairs")
    func mapLimit() throws {
        func map(pairs: Int) -> [UInt8] {
            var writer = CBORWriter()
            writer.mapHeader(count: pairs)
            for key in 0..<pairs {
                writer.unsigned(UInt64(key))
                writer.null()
            }
            return writer.bytes
        }
        guard case .map(let pairs) = try CBOR.decode(map(pairs: 1_024)) else {
            Issue.record("Expected a map")
            return
        }
        #expect(pairs.count == 1_024)
        #expect(throws: CBORError.mapTooLong) { try CBOR.decode(map(pairs: 1_025)) }
    }

    // MARK: Crash resistance

    @Test("Rejects every proper prefix of a well-formed item as truncated")
    func everyPrefixIsTruncated() throws {
        let vectors = try CBORVectorFile.load().vectors.filter { $0.cbor == "accept" }
        for vector in vectors {
            let input = try vector.input()
            for length in 0..<input.count {
                #expect(throws: CBORError.truncated, "\(vector.name), \(length) bytes") {
                    try CBOR.decode(Array(input[..<length]))
                }
            }
        }
    }

    @Test("Arbitrary bytes and single-byte genesis mutations do not cause a crash")
    func arbitraryInput() throws {
        var random = CBORTesting.Random(state: 0x5357_4946_5441_494c)
        for _ in 0..<20_000 {
            let input = (0..<Int.random(in: 0...64, using: &random)).map { _ in UInt8.random(in: 0...255, using: &random) }
            _ = try? CBOR.decode(input)
        }
        let genesis = try #require(CBORVectorFile.load().vectors.first { $0.name == "Genesis checkpoint" }).input()
        for index in genesis.indices {
            for byte in [0x00, 0x1b, 0x5b, 0x9b, 0xbb, 0x9f, 0xc2, 0xf8, 0xff] as [UInt8] {
                var mutated = genesis
                mutated[index] = byte
                _ = try? CBOR.decode(mutated)
            }
        }
    }
}

/// Nesting shapes for depth tests.
enum CBORNesting: Sendable, CustomTestStringConvertible {
    case arrays, maps, mixed

    var testDescription: String {
        switch self {
        case .arrays: "Array"
        case .maps: "Map"
        case .mixed: "Array and map"
        }
    }

    /// Arrays and maps nested `depth` levels. The innermost is empty, and each map puts the next layer in its value.
    func bytes(depth: Int) -> [UInt8] {
        var result: [UInt8] = []
        for level in 1...depth {
            let useMap = self == .maps || (self == .mixed && level.isMultiple(of: 2))
            if level == depth {
                result.append(useMap ? 0xa0 : 0x80)
            } else {
                result += useMap ? [0xa1, 0x01] : [0x81]
            }
        }
        return result
    }
}
