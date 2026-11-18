import Testing

import SwiftailBase

@testable import SwiftailIO

/// Tests interface address selection (contract E1, Go `LocalAddresses` in `net/netmon/state.go`) and makes a live call.
@Suite("Interface addresses")
struct LocalInterfaceAddressesTests {
    private typealias Interface = LocalInterfaceAddresses.Interface

    private static func address(_ text: String) -> IPAddress { IPAddress(text)! }

    private static func interface(
        _ name: String,
        up: Bool = true,
        loopback: Bool = false,
        _ addresses: String...
    ) -> Interface {
        Interface(name: name, isUp: up, isLoopback: loopback, addresses: addresses.map(address))
    }

    private static func texts(_ addresses: [IPAddress]) -> [String] { addresses.map(\.description) }

    @Test("Separates regular and loopback addresses and returns each in ascending order")
    func splitsAndSorts() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("lo0", loopback: true, "127.0.0.1"),
            Self.interface("en0", "192.168.1.20", "10.0.0.7"),
            Self.interface("en1", "172.16.0.2"),
        ])
        #expect(Self.texts(result.regular) == ["10.0.0.7", "172.16.0.2", "192.168.1.20"])
        #expect(Self.texts(result.loopback) == ["127.0.0.1"])
    }

    @Test("Sorts addresses numerically rather than lexicographically")
    func sortsNumerically() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface("en0", "10.0.0.9", "10.0.0.10", "9.9.9.9", "100.1.1.1")])
        #expect(Self.texts(result.regular) == ["9.9.9.9", "10.0.0.9", "10.0.0.10", "100.1.1.1"])
    }

    @Test("Skips interfaces that are down")
    func skipsDownInterfaces() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("en0", up: false, "192.168.1.20"),
            Self.interface("lo0", up: false, loopback: true, "127.0.0.1"),
            Self.interface("en1", "10.1.1.1"),
        ])
        #expect(Self.texts(result.regular) == ["10.1.1.1"])
        #expect(result.loopback.isEmpty)
    }

    @Test("Skips ZeroTier (zt*) and NetBird (wt0)")
    func skipsProblematicInterfaces() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("ztabcdef", "10.147.17.5"),
            Self.interface("zt", "10.147.17.6"),
            Self.interface("wt0", "10.9.9.9"),
            Self.interface("wt1", "10.8.8.8"),  // Filters only the exact name wt0
            Self.interface("en0", "10.0.0.1"),
        ])
        #expect(Self.texts(result.regular) == ["10.0.0.1", "10.8.8.8"])
    }

    @Test("Loopback interface addresses and 127/8 addresses count as loopback")
    func loopbackClassification() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("lo0", loopback: true, "127.0.0.1", "10.99.0.1"),  // A regular address on a loopback interface also counts as loopback
            Self.interface("en0", "127.0.0.2", "192.168.5.5"),  // A 127/8 address on a regular interface also counts as loopback
        ])
        #expect(Self.texts(result.regular) == ["192.168.5.5"])
        #expect(Self.texts(result.loopback) == ["10.99.0.1", "127.0.0.1", "127.0.0.2"])
    }

    @Test("Excludes Tailscale addresses (100.64.0.0/10), honoring the boundaries and the ChromeOS range exception (100.115.92.0/23)")
    func tailscaleRange() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface(
            "en0",
            "100.63.255.255",  // Immediately below the range: regular address
            "100.64.0.0",  // First address in the range: excluded
            "100.100.100.100",  // Excluded
            "100.115.91.255",  // Immediately below the ChromeOS range: excluded (inside the Tailscale range)
            "100.115.92.0",  // ChromeOS range: regular address
            "100.115.93.255",  // End of the ChromeOS range: regular address
            "100.115.94.0",  // Immediately above the ChromeOS range: excluded
            "100.127.255.255",  // End of the range: excluded
            "100.128.0.0"  // Immediately above the range: regular address
        )])
        #expect(Self.texts(result.regular) == ["100.63.255.255", "100.115.92.0", "100.115.93.255", "100.128.0.0"])
        #expect(result.loopback.isEmpty)
    }

    @Test("Uses link-local (169.254/16) addresses as regular addresses only if there are no regular addresses")
    func linkLocalFallback() {
        let only = LocalInterfaceAddresses.select(from: [Self.interface("en0", "169.254.7.7", "169.254.1.1")])
        #expect(Self.texts(only.regular) == ["169.254.1.1", "169.254.7.7"])

        let mixed = LocalInterfaceAddresses.select(from: [Self.interface("en0", "169.254.7.7"), Self.interface("en1", "192.168.0.4")])
        #expect(Self.texts(mixed.regular) == ["192.168.0.4"])

        // A 169.x address outside 169.254 is not link-local.
        let edge = LocalInterfaceAddresses.select(from: [Self.interface("en0", "169.253.0.1", "169.255.0.1")])
        #expect(Self.texts(edge.regular) == ["169.253.0.1", "169.255.0.1"])
    }

    @Test("Falls back to link-local when the only regular addresses are Tailscale addresses")
    func tailscaleOnlyCountsAsNoRegular() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface("utun4", "100.64.0.5"), Self.interface("en0", "169.254.2.2")])
        #expect(Self.texts(result.regular) == ["169.254.2.2"])
    }

    @Test("A link-local address on a loopback interface counts as loopback")
    func loopbackInterfaceWinsOverLinkLocal() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface("lo0", loopback: true, "169.254.9.9")])
        #expect(result.regular.isEmpty)
        #expect(Self.texts(result.loopback) == ["169.254.9.9"])
    }

    @Test("Empty input yields two empty results")
    func emptyInput() {
        let result = LocalInterfaceAddresses.select(from: [])
        #expect(result.regular.isEmpty)
        #expect(result.loopback.isEmpty)
    }

    @Test("Does not select IPv6 addresses")
    func ignoresIPv6() {
        let result = LocalInterfaceAddresses.select(from: [Interface(
            name: "en0",
            isUp: true,
            isLoopback: false,
            addresses: [Self.address("2001:db8::1"), Self.address("10.0.0.3")]
        )])
        #expect(Self.texts(result.regular) == ["10.0.0.3"])
    }

    @Test("A live call returns loopback addresses separately without crashing")
    func currentReportsLoopback() throws {
        let result = try LocalInterfaceAddresses.current()
        #expect(result.loopback.contains(Self.address("127.0.0.1")))
        #expect(!result.regular.contains(Self.address("127.0.0.1")))
        #expect(result.regular.allSatisfy { $0.isIPv4 })
        // The list is in ascending order.
        #expect(result.regular.map(\.bytes) == result.regular.map(\.bytes).sorted { $0.lexicographicallyPrecedes($1) })
    }
}
