import Testing

import SwiftailBase

@Suite("IPAddress")
struct IPAddressTests {
    @Test("IPv4 해석과 표기", arguments: ["100.64.0.1", "0.0.0.0", "255.255.255.255"])
    func ipv4RoundTrip(_ text: String) throws {
        let address = try #require(IPAddress(text))
        #expect(address.isIPv4)
        #expect(address.bytes.count == 4)
        #expect(address.description == text)
        #expect(IPAddress(address.description) == address)
    }

    @Test("IPv6 해석과 축약 표기")
    func ipv6() throws {
        let address = try #require(IPAddress("fd7a:115c:a1e0:0:0:0:0:1"))
        #expect(!address.isIPv4)
        #expect(address.bytes == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0] + [UInt8](repeating: 0, count: 9) + [1])
        #expect(address.description == "fd7a:115c:a1e0::1")
        #expect(IPAddress("::") == IPAddress(bytes: [UInt8](repeating: 0, count: 16)))
    }

    @Test("IPv4-mapped IPv6는 16바이트로 남는다")
    func ipv4Mapped() throws {
        let address = try #require(IPAddress("::ffff:100.64.0.1"))
        #expect(!address.isIPv4)
        #expect(address.bytes.suffix(6) == [0xff, 0xff, 100, 64, 0, 1])
    }

    @Test(
        "잘못된 문자열은 nil",
        arguments: [
            "", "1.2.3", "1", "1.2.3.4.5", "256.0.0.1", "010.0.0.1", "0x7f.0.0.1", "100.64.0.1/32",
            "fe80::1%en0", "::g", "::1\u{0}garbage", "fd7a:115c:a1e0::1\u{0}/64", "100.64.0.1\u{0}", "1.2.3.4 ", "hello", "::ffff:1.2.3", "::ffff:010.0.0.1", "1:2:3:4:5:6:7:8:9", "00000::1", "::00001", "fd7a:115c:a1e0::00001",
        ]
    )
    func invalid(_ text: String) {
        #expect(IPAddress(text) == nil)
    }

    @Test("바이트로 만들기: 4·16바이트만")
    func fromBytes() {
        #expect(IPAddress(bytes: [100, 64, 0, 1])?.description == "100.64.0.1")
        #expect(IPAddress(bytes: []) == nil)
        #expect(IPAddress(bytes: [1, 2, 3]) == nil)
        #expect(IPAddress(bytes: [UInt8](repeating: 0, count: 5)) == nil)
        #expect(IPAddress(bytes: [UInt8](repeating: 0, count: 17)) == nil)
    }
}
