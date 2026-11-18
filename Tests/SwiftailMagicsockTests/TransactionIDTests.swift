import Testing

import SwiftailBase

@testable import SwiftailMagicsock

@Suite("TransactionID")
struct TransactionIDTests {
    /// Generates the same bytes from the same seed. For tests only.
    private struct CountingGenerator: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x0102_0304_0506_0708
            return state
        }
    }

    @Test("Accepts only 12 bytes", arguments: [0, 1, 11, 13, 32])
    func wrongLengthRejected(_ count: Int) {
        #expect(TransactionID([UInt8](repeating: 7, count: count)) == nil)
    }

    @Test("Stores the 12 bytes unchanged")
    func keepsBytes() throws {
        let bytes = Array(UInt8(1)...UInt8(12))
        let id = try #require(TransactionID(bytes))
        #expect(id.bytes == bytes)
        #expect(id == TransactionID(bytes[...]))
    }

    @Test("random draws 12 bytes from the supplied generator")
    func randomUsesGenerator() {
        var first = CountingGenerator(state: 1)
        var second = CountingGenerator(state: 1)
        var other = CountingGenerator(state: 2)
        let id = TransactionID.random(using: &first)
        #expect(id.bytes.count == TransactionID.byteCount)
        #expect(id == TransactionID.random(using: &second))
        #expect(id != TransactionID.random(using: &other))
    }
}
