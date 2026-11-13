import Foundation
import Testing

import SwiftailControl

@Suite("키 텍스트 형식")
struct KeysTests {
    private let hex = String(repeating: "ab", count: 32)

    @Test("접두사 + 16진 64자리를 읽고 쓴다")
    func roundTrip() throws {
        let key = try #require(NodePublicKey("nodekey:" + hex))
        #expect(key.rawValue == [UInt8](repeating: 0xAB, count: 32))
        #expect(key.description == "nodekey:" + hex)
        // 대문자 16진도 받고, 쓸 때는 소문자다.
        #expect(NodePublicKey("nodekey:" + hex.uppercased()) == key)
    }

    @Test("접두사나 길이가 다르면 거절한다", arguments: ["", "nodekey:", "mkey:" + String(repeating: "ab", count: 32), "nodekey:abcd", String(repeating: "ab", count: 32)])
    func rejects(_ text: String) {
        #expect(NodePublicKey(text) == nil)
    }

    @Test("JSON에서는 문자열이고, 0 키는 생략하지 않는다")
    func json() throws {
        let encoded = try JSONEncoder().encode([MachinePublicKey.zero])
        #expect(String(decoding: encoded, as: UTF8.self) == "[\"mkey:" + String(repeating: "0", count: 64) + "\"]")
        #expect(try JSONDecoder().decode([MachinePublicKey].self, from: encoded) == [.zero])
        #expect(MachinePublicKey.zero.isZero)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode([DiscoPublicKey].self, from: encoded) }
    }
}
