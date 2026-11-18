import SwiftailBase
import Testing
@testable import Swiftail

/// Tests how default interface notifications are evaluated. Contract `docs/contracts/SwiftailTunnel.md` behavior N 1·2, test list 7.
@Suite("Default interface change decisions")
struct DefaultLinkTests {
    private static func link(_ name: String = "en0", index: Int = 4, addresses: [String] = ["192.168.0.10"]) -> DefaultLink {
        DefaultLink(
            name: name, index: index,
            addresses: addresses.compactMap(IPAddress.init),
            loopbackAddresses: ["127.0.0.1"].compactMap(IPAddress.init)
        )
    }

    @Test("The first interface notification triggers rebinding")
    func first() {
        #expect(Self.link().change(from: nil, tunnelName: "utun5") == .rebind)
    }

    @Test("The same interface and address trigger only a STUN refresh")
    func same() {
        #expect(Self.link().change(from: Self.link(), tunnelName: "utun5") == .restartSTUN)
    }

    @Test("An address change alone triggers rebinding")
    func addressChanged() {
        #expect(Self.link(addresses: ["192.168.0.11"]).change(from: Self.link(), tunnelName: "utun5") == .rebind)
        #expect(Self.link(addresses: []).change(from: Self.link(), tunnelName: "utun5") == .rebind)
    }

    @Test("An interface change (name or number) triggers rebinding")
    func interfaceChanged() {
        #expect(Self.link("pdp_ip0", index: 9).change(from: Self.link(), tunnelName: "utun5") == .rebind)
        #expect(Self.link(index: 5).change(from: Self.link(), tunnelName: "utun5") == .rebind)
    }

    @Test("Ignores an interface with this node's utun name. The memory device applies no such filter")
    func ownTunnel() {
        #expect(Self.link("utun5", index: 20).change(from: Self.link(), tunnelName: "utun5") == .ignore)
        #expect(Self.link("utun5", index: 20).change(from: nil, tunnelName: "utun5") == .ignore)
        #expect(Self.link("utun5", index: 20).change(from: Self.link(), tunnelName: nil) == .rebind)
    }
}
