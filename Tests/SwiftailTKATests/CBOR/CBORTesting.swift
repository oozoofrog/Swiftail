@testable import SwiftailTKA

/// Shared CBOR test helpers under one name to avoid collisions with other units in the test target.
enum CBORTesting {
    static func bytes(hex: String) -> [UInt8]? {
        let digits = Array(hex.utf8)
        guard digits.count.isMultiple(of: 2) else { return nil }
        var result: [UInt8] = []
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[index..<index + 2], as: UTF8.self), radix: 16) else { return nil }
            result.append(byte)
        }
        return result
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String($0 >> 4, radix: 16) + String($0 & 0xf, radix: 16) }.joined()
    }

    /// Writes the canonical encoding of `value` with `CBORWriter`. Map pairs use lexicographic order of encoded key bytes (CTAP2, note §3.1),
    /// preserving received order for equal keys. Returns nil for unwritable items (negative integers, simple values, and floats).
    static func canonical(_ value: CBORValue) -> [UInt8]? {
        var writer = CBORWriter()
        guard write(value, into: &writer) else { return nil }
        return writer.bytes
    }

    private static func write(_ value: CBORValue, into writer: inout CBORWriter) -> Bool {
        switch value {
        case .unsigned(let number):
            writer.unsigned(number)
        case .bytes(let content):
            writer.byteString(content)
        case .text(let content):
            writer.textString(utf8: content)
        case .null:
            writer.null()
        case .array(let elements):
            writer.arrayHeader(count: elements.count)
            for element in elements {
                guard write(element, into: &writer) else { return false }
            }
        case .map(let pairs):
            var keyed: [(key: [UInt8], index: Int, pair: CBORPair)] = []
            for (index, pair) in pairs.enumerated() {
                guard let key = canonical(pair.key) else { return false }
                keyed.append((key, index, pair))
            }
            keyed.sort { $0.key == $1.key ? $0.index < $1.index : $0.key.lexicographicallyPrecedes($1.key) }
            writer.mapHeader(count: pairs.count)
            for entry in keyed {
                guard write(entry.pair.key, into: &writer), write(entry.pair.value, into: &writer) else { return false }
            }
        case .negative, .simple, .simpleOrFloat:
            return false
        }
        return true
    }

    /// Deterministic random numbers (SplitMix64). Rerun a failing test with the same seed.
    struct Random: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9e37_79b9_7f4a_7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
            z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
            return z ^ (z >> 31)
        }
    }
}
