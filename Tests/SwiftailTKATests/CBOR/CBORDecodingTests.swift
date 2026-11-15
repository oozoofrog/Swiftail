import Testing

@testable import SwiftailTKA

/// 계약 7절 시험 2의 항목 수준(동작 D1·D2·D9). 구조 수준의 판정(키 종류, 중복, 타입)은 TL-2의 시험이다.
@Suite("CBOR 읽기")
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

    // MARK: 받아들임과 값의 모양

    @Test("비최단 정수와 길이는 같은 값으로 읽는다")
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

    @Test("맵은 받은 순서와 중복을 그대로 쥔다")
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

    @Test("major 7: null과 undefined는 null, 단순값은 그 값, 나머지는 simpleOrFloat")
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

    @Test("텍스트의 UTF-8은 보지 않는다")
    func textNotValidated() throws {
        #expect(try decode("62c328") == .text([0xc3, 0x28]))
    }

    // MARK: 항목 수준의 거절

    @Test("빈 입력과 뒤에 남은 바이트")
    func emptyAndTrailing() throws {
        #expect(try rejection("") == .truncated)
        #expect(try rejection("0000") == .trailingBytes)
        #expect(try rejection("a0f6") == .trailingBytes)
        #expect(try rejection("80ff") == .trailingBytes)
    }

    @Test("길이 미정은 네 주 타입 모두 거절한다")
    func indefinite() throws {
        for hex in ["5fff", "7fff", "9fff", "bfff", "5f4101ff", "a1019f01ff"] {
            #expect(try rejection(hex) == .indefiniteLength, "\(hex)")
        }
    }

    @Test("태그는 어디에 있어도 거절한다")
    func tags() throws {
        for hex in ["c000", "d74401020304", "d818456449455446", "db000000000000000100", "8201c24101", "a101c100"] {
            #expect(try rejection(hex) == .tag, "\(hex)")
        }
    }

    @Test("잘 짜이지 않은 머리")
    func malformedHeads() throws {
        var hexes: [String] = []
        // 예약된 추가 정보 28~30은 모든 주 타입에서.
        for major in 0..<8 {
            for info in 28...30 {
                hexes.append(CBORTesting.hex([UInt8(major << 5 | info)]))
            }
        }
        // 길이 미정이 없는 주 타입의 31, 짝 없는 break.
        hexes += ["1f", "3f", "df", "ff", "81ff", "a1ff"]
        // 두 바이트로 쓴 32 미만 단순값.
        hexes += (0..<32).map { "f8" + CBORTesting.hex([UInt8($0)]) }
        for hex in hexes {
            #expect(try rejection(hex) == .malformed, "\(hex)")
        }
    }

    @Test("잘린 머리와 내용")
    func truncatedItems() throws {
        for hex in ["18", "1900", "1a000000", "1b00000000000000", "38", "41", "5801", "6261", "81", "8201", "a1", "a101", "d8", "f8", "f900", "fa000000", "fb00"] {
            #expect(try rejection(hex) == .truncated, "\(hex)")
        }
    }

    @Test("남은 바이트보다 긴 길이 필드는 할당하지 않고 거절한다")
    func hugeLengths() throws {
        for hex in ["5bffffffffffffffff", "5b7fffffffffffffff00", "7bffffffffffffffff", "5affffffff00", "59ffff"] {
            #expect(try rejection(hex) == .truncated, "\(hex)")
        }
        // 배열·맵은 원소를 읽기 전에 원소 수의 한도로 거절한다.
        #expect(try rejection("9bffffffffffffffff") == .arrayTooLong)
        #expect(try rejection("9a00001001") == .arrayTooLong)
        #expect(try rejection("bbffffffffffffffff") == .mapTooLong)
        #expect(try rejection("b90401") == .mapTooLong)
        // 한도 안의 원소 수인데 원소가 없으면 잘린 것이다.
        #expect(try rejection("991000") == .truncated)
        #expect(try rejection("b90400") == .truncated)
    }

    // MARK: 한도의 경계(노트 8.1: 16/17단, 4,096/4,097개, 1,024/1,025쌍)

    @Test("중첩은 16단까지 받는다", arguments: [CBORNesting.arrays, .maps, .mixed])
    func nesting(kind: CBORNesting) throws {
        #expect(throws: Never.self) { try CBOR.decode(kind.bytes(depth: 16)) }
        #expect(throws: CBORError.nestingTooDeep) { try CBOR.decode(kind.bytes(depth: 17)) }
        #expect(throws: CBORError.nestingTooDeep) { try CBOR.decode(kind.bytes(depth: 40)) }
    }

    @Test("깊이를 넘는 항목은 길이 미정이어도 깊이로 먼저 거절한다")
    func nestingCheckedBeforeIndefinite() throws {
        let deep = [UInt8](repeating: 0x81, count: 16) + [0x9f, 0xff]
        #expect(throws: CBORError.nestingTooDeep) { try CBOR.decode(deep) }
    }

    @Test("배열은 4,096개까지 받는다")
    func arrayLimit() {
        let accepted: [UInt8] = [0x99, 0x10, 0x00] + [UInt8](repeating: 0, count: 4_096)
        #expect((try? CBOR.decode(accepted)) == .array([CBORValue](repeating: .unsigned(0), count: 4_096)))
        let rejected: [UInt8] = [0x99, 0x10, 0x01] + [UInt8](repeating: 0, count: 4_097)
        #expect(throws: CBORError.arrayTooLong) { try CBOR.decode(rejected) }
    }

    @Test("맵은 1,024쌍까지 받는다")
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
            Issue.record("맵이 아니다")
            return
        }
        #expect(pairs.count == 1_024)
        #expect(throws: CBORError.mapTooLong) { try CBOR.decode(map(pairs: 1_025)) }
    }

    // MARK: 죽지 않음

    @Test("잘 짜인 항목의 모든 진접두는 잘린 것으로 거절한다")
    func everyPrefixIsTruncated() throws {
        let vectors = try CBORVectorFile.load().vectors.filter { $0.cbor == "accept" }
        for vector in vectors {
            let input = try vector.input()
            for length in 0..<input.count {
                #expect(throws: CBORError.truncated, "\(vector.name), \(length)바이트") {
                    try CBOR.decode(Array(input[..<length]))
                }
            }
        }
    }

    @Test("임의 바이트와 genesis의 한 바이트 변형으로 죽지 않는다")
    func arbitraryInput() throws {
        var random = CBORTesting.Random(state: 0x5357_4946_5441_494c)
        for _ in 0..<20_000 {
            let input = (0..<Int.random(in: 0...64, using: &random)).map { _ in UInt8.random(in: 0...255, using: &random) }
            _ = try? CBOR.decode(input)
        }
        let genesis = try #require(CBORVectorFile.load().vectors.first { $0.name == "genesis 체크포인트" }).input()
        for index in genesis.indices {
            for byte in [0x00, 0x1b, 0x5b, 0x9b, 0xbb, 0x9f, 0xc2, 0xf8, 0xff] as [UInt8] {
                var mutated = genesis
                mutated[index] = byte
                _ = try? CBOR.decode(mutated)
            }
        }
    }
}

/// 깊이 시험의 겹 모양.
enum CBORNesting: Sendable, CustomTestStringConvertible {
    case arrays, maps, mixed

    var testDescription: String {
        switch self {
        case .arrays: "배열"
        case .maps: "맵"
        case .mixed: "배열과 맵"
        }
    }

    /// `depth`겹의 배열·맵. 맨 안쪽은 빈 것이고, 맵은 값 자리에 다음 겹을 둔다.
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
