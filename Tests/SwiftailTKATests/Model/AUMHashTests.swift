import Testing

@testable import SwiftailTKA

/// `AUMHash`의 텍스트 표기(계약 7절 시험 3, 노트 3.8·8.1).
@Suite("AUMHash")
struct AUMHashTests {
    /// 노트 8.1: genesis 체크포인트의 해시.
    static let genesisText = "JJRRHYGNBVUWY77ZY436U35DVPHXPY4C5HPQZA2PHUPBNM5252UA"
    static let genesisHex = "4a6313e0cd0d696c7ff9c737ea6fa3abcf77e382e9df0c834f3d1e16b3baeea8"

    @Test("genesis 해시의 텍스트와 바이트가 Go와 같다")
    func genesis() throws {
        let hash = try #require(AUMHash(text: Self.genesisText))
        #expect(ModelTesting.hex(hash.bytes) == Self.genesisHex)
        #expect(try #require(AUMHash(ModelTesting.bytes(Self.genesisHex))).text == Self.genesisText)
    }

    @Test("바이트는 32바이트만 받는다")
    func byteCount() {
        #expect(AUMHash([UInt8](repeating: 1, count: 31)) == nil)
        #expect(AUMHash([UInt8](repeating: 1, count: 33)) == nil)
        #expect(AUMHash([]) == nil)
        #expect(AUMHash([UInt8](repeating: 1, count: 32))?.bytes == [UInt8](repeating: 1, count: 32))
    }

    @Test("임의의 해시를 텍스트로 쓰고 읽으면 같다")
    func roundTrip() throws {
        var random = CBORTesting.Random(state: 0x7a32)
        for _ in 0..<300 {
            let bytes = (0..<32).map { _ in UInt8.random(in: 0...255, using: &random) }
            let hash = try #require(AUMHash(bytes))
            #expect(hash.text.utf8.count == 52)
            #expect(AUMHash(text: hash.text) == hash)
        }
        #expect(AUMHash([UInt8](repeating: 0, count: 32))?.text == String(repeating: "A", count: 52))
        #expect(AUMHash([UInt8](repeating: 0xff, count: 32))?.text == String(repeating: "7", count: 51) + "Q")
    }

    @Test("소문자·패딩·51자·53자·알파벳 밖의 글자는 거절한다")
    func rejected() {
        let text = Self.genesisText
        #expect(AUMHash(text: text.lowercased()) == nil)
        #expect(AUMHash(text: text + "====") == nil)
        #expect(AUMHash(text: String(text.dropLast()) + "=") == nil)
        #expect(AUMHash(text: String(text.dropLast())) == nil)
        #expect(AUMHash(text: text + "A") == nil)
        #expect(AUMHash(text: "") == nil)
        for character in ["0", "1", "8", "9", "a", " ", "\n", "é"] {
            #expect(AUMHash(text: character + String(text.dropFirst())) == nil, "\(character)")
        }
        // Go는 `\r`·`\n`을 지우고 읽지만 Swiftail은 거절한다(보고의 "Go 판정 미확인").
        #expect(AUMHash(text: String(text.dropLast()) + "\n") == nil)
    }

    @Test("끝 글자의 남는 4비트는 보지 않는다: A·B·P는 같은 해시, Q는 다른 해시")
    func trailingBits() throws {
        let stem = String(Self.genesisText.dropLast())
        let a = try #require(AUMHash(text: stem + "A"))
        #expect(AUMHash(text: stem + "B") == a)
        #expect(AUMHash(text: stem + "P") == a)
        #expect(AUMHash(text: stem + "Q") != a)
        #expect(a.text == stem + "A")
    }
}
