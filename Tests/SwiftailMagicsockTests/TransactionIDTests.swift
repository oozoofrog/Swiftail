import Testing

import SwiftailBase

@testable import SwiftailMagicsock

@Suite("TransactionID")
struct TransactionIDTests {
    /// 같은 시드면 같은 바이트를 내는 생성기. 시험 전용이다.
    private struct CountingGenerator: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x0102_0304_0506_0708
            return state
        }
    }

    @Test("12바이트만 받는다", arguments: [0, 1, 11, 13, 32])
    func wrongLengthRejected(_ count: Int) {
        #expect(TransactionID([UInt8](repeating: 7, count: count)) == nil)
    }

    @Test("12바이트는 그대로 담는다")
    func keepsBytes() throws {
        let bytes = Array(UInt8(1)...UInt8(12))
        let id = try #require(TransactionID(bytes))
        #expect(id.bytes == bytes)
        #expect(id == TransactionID(bytes[...]))
    }

    @Test("random은 넘긴 생성기로 12바이트를 뽑는다")
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
