import Testing

import SwiftailBase

@Suite("IPPrefix")
struct IPPrefixTests {
    @Test("호스트 비트를 지운다")
    func clearsHostBits() throws {
        let prefix = try #require(IPPrefix("100.64.0.1/10"))
        #expect(prefix.address == IPAddress("100.64.0.0"))
        #expect(prefix.length == 10)
        #expect(prefix.description == "100.64.0.0/10")
        #expect(prefix == IPPrefix("100.127.255.255/10"))

        let v6 = try #require(IPPrefix("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/48"))
        #expect(v6.description == "fd7a:115c:a1e0::/48")

        // 바이트 경계가 아닌 길이.
        #expect(IPPrefix("10.255.255.255/13")?.address == IPAddress("10.248.0.0"))
    }

    @Test("/32와 /128은 주소 하나만 담는다")
    func hostPrefixes() throws {
        let v4 = try #require(IPPrefix("100.64.0.1/32"))
        #expect(v4.contains(try #require(IPAddress("100.64.0.1"))))
        #expect(!v4.contains(try #require(IPAddress("100.64.0.2"))))

        let v6 = try #require(IPPrefix("fd7a:115c:a1e0::1/128"))
        #expect(v6.contains(try #require(IPAddress("fd7a:115c:a1e0::1"))))
        #expect(!v6.contains(try #require(IPAddress("fd7a:115c:a1e0::2"))))
    }

    @Test("/0은 같은 종류의 모든 주소를 담고, 다른 종류는 담지 않는다")
    func zeroLength() throws {
        let anyV4 = try #require(IPPrefix("0.0.0.0/0"))
        let anyV6 = try #require(IPPrefix("::/0"))
        let v4 = try #require(IPAddress("203.0.113.9"))
        let v6 = try #require(IPAddress("2001:db8::1"))
        #expect(anyV4.contains(v4))
        #expect(!anyV4.contains(v6))
        #expect(anyV6.contains(v6))
        #expect(!anyV6.contains(v4))
        #expect(IPPrefix("1.2.3.4/0")?.address == IPAddress("0.0.0.0"))
    }

    @Test("contains의 경계")
    func containsBoundary() throws {
        let prefix = try #require(IPPrefix("100.64.0.0/10"))
        #expect(prefix.contains(try #require(IPAddress("100.64.0.0"))))
        #expect(prefix.contains(try #require(IPAddress("100.127.255.255"))))
        #expect(!prefix.contains(try #require(IPAddress("100.128.0.0"))))
        #expect(!prefix.contains(try #require(IPAddress("100.63.255.255"))))
        // IPv4-mapped IPv6는 IPv4 접두에 속하지 않는다.
        #expect(!prefix.contains(try #require(IPAddress("::ffff:100.64.0.1"))))
    }

    @Test(
        "잘못된 문자열은 nil",
        arguments: [
            "", "100.64.0.1", "100.64.0.1/", "/8", "100.64.0.1/33", "::/129", "100.64.0.1/-1",
            "100.64.0.1/+8", "100.64.0.1/08", "100.64.0.1/8/8", "100.64.0.1/ 8", "1.2.3/8", "fe80::1%en0/64",
            "100.64.0.1/1000",
        ]
    )
    func invalid(_ text: String) {
        #expect(IPPrefix(text) == nil)
    }

    @Test("주소와 길이로 만들기: 길이 범위 검사")
    func fromAddressAndLength() throws {
        let v4 = try #require(IPAddress("100.64.0.1"))
        let v6 = try #require(IPAddress("fd7a::1"))
        #expect(IPPrefix(address: v4, length: 32) != nil)
        #expect(IPPrefix(address: v4, length: 33) == nil)
        #expect(IPPrefix(address: v4, length: -1) == nil)
        #expect(IPPrefix(address: v6, length: 128) != nil)
        #expect(IPPrefix(address: v6, length: 129) == nil)
    }
}
