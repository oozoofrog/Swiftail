import Testing

import SwiftailBase

@Suite("IPPrefix")
struct IPPrefixTests {
    @Test("Clears host bits")
    func clearsHostBits() throws {
        let prefix = try #require(IPPrefix("100.64.0.1/10"))
        #expect(prefix.address == IPAddress("100.64.0.0"))
        #expect(prefix.length == 10)
        #expect(prefix.description == "100.64.0.0/10")
        #expect(prefix == IPPrefix("100.127.255.255/10"))

        let v6 = try #require(IPPrefix("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/48"))
        #expect(v6.description == "fd7a:115c:a1e0::/48")

        // A length that does not fall on a byte boundary.
        #expect(IPPrefix("10.255.255.255/13")?.address == IPAddress("10.248.0.0"))
    }

    @Test("/32 and /128 each contain only one address")
    func hostPrefixes() throws {
        let v4 = try #require(IPPrefix("100.64.0.1/32"))
        #expect(v4.contains(try #require(IPAddress("100.64.0.1"))))
        #expect(!v4.contains(try #require(IPAddress("100.64.0.2"))))

        let v6 = try #require(IPPrefix("fd7a:115c:a1e0::1/128"))
        #expect(v6.contains(try #require(IPAddress("fd7a:115c:a1e0::1"))))
        #expect(!v6.contains(try #require(IPAddress("fd7a:115c:a1e0::2"))))
    }

    @Test("/0 contains every address of the same family and none of the other family")
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

    @Test("Boundary cases for contains")
    func containsBoundary() throws {
        let prefix = try #require(IPPrefix("100.64.0.0/10"))
        #expect(prefix.contains(try #require(IPAddress("100.64.0.0"))))
        #expect(prefix.contains(try #require(IPAddress("100.127.255.255"))))
        #expect(!prefix.contains(try #require(IPAddress("100.128.0.0"))))
        #expect(!prefix.contains(try #require(IPAddress("100.63.255.255"))))
        // IPv4-mapped IPv6 does not belong to an IPv4 prefix.
        #expect(!prefix.contains(try #require(IPAddress("::ffff:100.64.0.1"))))
    }

    @Test(
        "Invalid strings yield nil",
        arguments: [
            "", "100.64.0.1", "100.64.0.1/", "/8", "100.64.0.1/33", "::/129", "100.64.0.1/-1",
            "100.64.0.1/+8", "100.64.0.1/08", "100.64.0.1/8/8", "100.64.0.1/ 8", "1.2.3/8", "fe80::1%en0/64",
            "100.64.0.1/1000",
        ]
    )
    func invalid(_ text: String) {
        #expect(IPPrefix(text) == nil)
    }

    @Test("Initialization from an address and length checks the length range")
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
