import Testing

import SwiftailBase

@Suite("Base-16 conversion")
struct HexTests {
    @Test("Round trip and lowercase output")
    func roundTrip() {
        let bytes: [UInt8] = [0x00, 0x01, 0x7f, 0x80, 0xab, 0xff]
        #expect(bytes.hex == "00017f80abff")
        #expect([UInt8](hex: "00017F80ABff") == bytes)
        #expect([UInt8](hex: "") == [])
        #expect([UInt8]().hex == "")
        let all = (0...255).map { UInt8($0) }
        #expect([UInt8](hex: all.hex) == all)
    }

    @Test("Odd lengths or characters outside base 16 yield nil", arguments: ["0", "abc", "0g", "zz", " 0", "0x00", "é0", "-1"])
    func invalid(_ text: String) {
        #expect([UInt8](hex: text) == nil)
    }
}
