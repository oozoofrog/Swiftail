@testable import SwiftailTKA

/// CBOR 시험이 함께 쓰는 도구. 같은 시험 타깃의 다른 단위와 이름이 부딪치지 않게 한 이름 아래 둔다.
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

    /// `value`의 정준 인코딩을 `CBORWriter`로 쓴다. 맵의 쌍은 인코딩한 키 바이트의 사전순(CTAP2, 노트 3.1)이고
    /// 같은 키끼리는 받은 순서를 지킨다. 쓰는 길이 없는 항목(음수, 단순값·실수)이 있으면 nil.
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
        case .negative, .simpleOrFloat:
            return false
        }
        return true
    }

    /// 결정적 난수(SplitMix64). 실패한 시험을 같은 씨앗으로 다시 돌릴 수 있다.
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
