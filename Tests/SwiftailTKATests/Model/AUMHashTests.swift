import Testing

@testable import SwiftailTKA

/// Text representation of `AUMHash` (contract §7 test 3, note §§3.8 and 8.1).
@Suite("AUMHash")
struct AUMHashTests {
    /// Note §8.1: hash of the genesis checkpoint.
    static let genesisText = "JJRRHYGNBVUWY77ZY436U35DVPHXPY4C5HPQZA2PHUPBNM5252UA"
    static let genesisHex = "4a6313e0cd0d696c7ff9c737ea6fa3abcf77e382e9df0c834f3d1e16b3baeea8"

    @Test("Genesis hash text and bytes match Go")
    func genesis() throws {
        let hash = try #require(AUMHash(text: Self.genesisText))
        #expect(ModelTesting.hex(hash.bytes) == Self.genesisHex)
        #expect(try #require(AUMHash(ModelTesting.bytes(Self.genesisHex))).text == Self.genesisText)
    }

    @Test("Accepts only 32 bytes")
    func byteCount() {
        #expect(AUMHash([UInt8](repeating: 1, count: 31)) == nil)
        #expect(AUMHash([UInt8](repeating: 1, count: 33)) == nil)
        #expect(AUMHash([]) == nil)
        #expect(AUMHash([UInt8](repeating: 1, count: 32))?.bytes == [UInt8](repeating: 1, count: 32))
    }

    @Test("Arbitrary hashes round-trip through text")
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

    @Test("Rejects lowercase, padding, 51 or 53 characters, and characters outside the alphabet")
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
        // Go strips `\r` and `\n` before decoding, and Swiftail rejects them (Unverified Go outcomes in the report).
        #expect(AUMHash(text: String(text.dropLast()) + "\n") == nil)
    }

    @Test("Ignores the last character's 4 trailing bits: A, B, and P give the same hash, and Q gives a different hash")
    func trailingBits() throws {
        let stem = String(Self.genesisText.dropLast())
        let a = try #require(AUMHash(text: stem + "A"))
        #expect(AUMHash(text: stem + "B") == a)
        #expect(AUMHash(text: stem + "P") == a)
        #expect(AUMHash(text: stem + "Q") != a)
        #expect(a.text == stem + "A")
    }
}
