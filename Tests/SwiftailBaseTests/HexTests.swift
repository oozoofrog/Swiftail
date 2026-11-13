import Testing

import SwiftailBase

@Suite("16진 변환")
struct HexTests {
    @Test("왕복과 소문자 출력")
    func roundTrip() {
        let bytes: [UInt8] = [0x00, 0x01, 0x7f, 0x80, 0xab, 0xff]
        #expect(bytes.hex == "00017f80abff")
        #expect([UInt8](hex: "00017F80ABff") == bytes)
        #expect([UInt8](hex: "") == [])
        #expect([UInt8]().hex == "")
        let all = (0...255).map { UInt8($0) }
        #expect([UInt8](hex: all.hex) == all)
    }

    @Test("홀수 길이나 16진이 아닌 문자는 nil", arguments: ["0", "abc", "0g", "zz", " 0", "0x00", "é0", "-1"])
    func invalid(_ text: String) {
        #expect([UInt8](hex: text) == nil)
    }
}
