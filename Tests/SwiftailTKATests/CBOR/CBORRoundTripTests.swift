import Testing

@testable import SwiftailTKA

/// Canonical encoding properties: writing and reading preserves the value, and reading and rewriting a noncanonical encoding yields canonical bytes
/// (hashes use re-encoded bytes, note §3.1 and contract behavior E5).
@Suite("CBOR round trips")
struct CBORRoundTripTests {
    private static let valueCount = 500

    @Test("Writing and reading arbitrary values preserves them, and rewriting preserves the bytes")
    func canonicalRoundTrip() throws {
        var random = CBORTesting.Random(state: 1)
        for index in 0..<Self.valueCount {
            let value = Generator.value(depth: 0, using: &random)
            let bytes = try #require(CBORTesting.canonical(value))
            let decoded = try CBOR.decode(bytes)
            #expect(decoded == value, "Value \(index)")
            #expect(CBORTesting.canonical(decoded) == bytes, "Value \(index)")
        }
    }

    @Test("Non-shortest headers and shuffled keys decode to the same values and rewrite to canonical bytes")
    func nonCanonicalInput() throws {
        var random = CBORTesting.Random(state: 2)
        for index in 0..<Self.valueCount {
            let value = Generator.value(depth: 0, using: &random)
            let canonical = try #require(CBORTesting.canonical(value))
            let loose = Generator.looseEncoding(of: value, using: &random)
            let decoded = try CBOR.decode(loose)
            #expect(CBORTesting.canonical(decoded) == canonical, "Value \(index)")
        }
    }

    /// A small generator for writable values (uint, bstr, tstr, null, arrays, and maps). Map keys have distinct canonical bytes.
    private enum Generator {
        static let boundaries: [UInt64] = [0, 1, 23, 24, 255, 256, 65_535, 65_536, 0xffff_ffff, 1 << 32, 1 << 63, .max]

        static func value(depth: Int, using random: inout CBORTesting.Random) -> CBORValue {
            let kinds = depth < 6 ? 6 : 4
            switch Int.random(in: 0..<kinds, using: &random) {
            case 0:
                if Bool.random(using: &random) {
                    return .unsigned(boundaries.randomElement(using: &random) ?? 0)
                }
                let width = UInt64.random(in: 0...63, using: &random)
                return .unsigned(UInt64.random(in: 0...(UInt64.max >> width), using: &random))
            case 1:
                return .bytes(content(using: &random))
            case 2:
                return .text(content(using: &random))
            case 3:
                return .null
            case 4:
                let count = Int.random(in: 0...5, using: &random)
                return .array((0..<count).map { _ in value(depth: depth + 1, using: &random) })
            default:
                // Retain canonical order to match the round-tripped value.
                var pairs: [(key: [UInt8], pair: CBORPair)] = []
                for _ in 0..<Int.random(in: 0...5, using: &random) {
                    let key = value(depth: depth + 1, using: &random)
                    guard let encoded = CBORTesting.canonical(key), !pairs.contains(where: { $0.key == encoded }) else { continue }
                    pairs.append((encoded, CBORPair(key: key, value: value(depth: depth + 1, using: &random))))
                }
                return .map(pairs.sorted { $0.key.lexicographicallyPrecedes($1.key) }.map(\.pair))
            }
        }

        static func content(using random: inout CBORTesting.Random) -> [UInt8] {
            let lengths = [0, 1, 23, 24, 30, 255, 256, 300]
            let count = lengths.randomElement(using: &random) ?? 0
            return (0..<count).map { _ in UInt8.random(in: 0...255, using: &random) }
        }

        /// A noncanonical but well-formed encoding: use header arguments wider than necessary and shuffle map pairs.
        static func looseEncoding(of value: CBORValue, using random: inout CBORTesting.Random) -> [UInt8] {
            switch value {
            case .unsigned(let number):
                return head(major: 0, argument: number, using: &random)
            case .bytes(let content):
                return head(major: 2, argument: UInt64(content.count), using: &random) + content
            case .text(let content):
                return head(major: 3, argument: UInt64(content.count), using: &random) + content
            case .array(let elements):
                return elements.reduce(head(major: 4, argument: UInt64(elements.count), using: &random)) {
                    $0 + looseEncoding(of: $1, using: &random)
                }
            case .map(let pairs):
                return pairs.shuffled(using: &random).reduce(head(major: 5, argument: UInt64(pairs.count), using: &random)) {
                    $0 + looseEncoding(of: $1.key, using: &random) + looseEncoding(of: $1.value, using: &random)
                }
            case .null:
                return [0xf6]
            case .negative, .simple, .simpleOrFloat:
                Issue.record("The generator produced an unwritable value")
                return []
            }
        }

        static func head(major: UInt8, argument: UInt64, using random: inout CBORTesting.Random) -> [UInt8] {
            let minimumWidth: Int =
                switch argument {
                case 0..<24: 0
                case ...0xff: 1
                case ...0xffff: 2
                case ...0xffff_ffff: 4
                default: 8
                }
            let width = [0, 1, 2, 4, 8].filter { $0 >= minimumWidth }.randomElement(using: &random) ?? 8
            guard width > 0 else { return [major << 5 | UInt8(argument)] }
            let info = UInt8(24 + width.trailingZeroBitCount)
            return [major << 5 | info] + (0..<width).reversed().map { UInt8(truncatingIfNeeded: argument >> UInt64($0 * 8)) }
        }
    }
}
