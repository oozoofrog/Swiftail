import Foundation
import SwiftailBase
import SwiftailEngine
import Testing
@testable import Swiftail

/// Tests when tunnel settings are published. Contract `docs/contracts/SwiftailTunnel.md` behavior E, test list 6.
@Suite("Publishing tunnel settings")
struct NetworkSettingsPublisherTests {
    private static func settings(_ addresses: [String] = ["100.64.0.1/32"]) throws -> TunnelNetworkSettings {
        try #require(TunnelNetworkSettings(netmap: try NodeTestSupport.netmap(addresses: addresses), mtu: 1280, at: Date()))
    }

    @Test("Publishes nothing without a local address (nil result)")
    func noAddresses() throws {
        var publisher = NetworkSettingsPublisher()
        #expect(TunnelNetworkSettings(netmap: try NodeTestSupport.netmap(addresses: []), mtu: 1280, at: Date()) == nil)
        #expect(publisher.publish(nil) == nil)
        #expect(publisher.published == nil)
    }

    @Test("Skips identical values and retains the last value if an addressless netmap arrives")
    func sameValue() throws {
        var publisher = NetworkSettingsPublisher()
        let first = try Self.settings()
        #expect(publisher.publish(first) == first)
        #expect(publisher.publish(try Self.settings()) == nil)
        #expect(publisher.publish(nil) == nil)
        #expect(publisher.published == first)
    }

    @Test("Publishes when only the DNS servers or only the match domains change")
    func dnsOnlyChanges() throws {
        var publisher = NetworkSettingsPublisher()
        let base = try Self.settings()
        _ = publisher.publish(base)

        var servers = base
        // Change only the DNS server list (clear it if populated, add one server if empty).
        servers.dnsServers = base.dnsServers.isEmpty ? [try #require(IPAddress("100.100.100.100"))] : []
        #expect(publisher.publish(servers) == servers)

        var domains = servers
        domains.dnsMatchDomains = servers.dnsMatchDomains + ["example.internal"]
        #expect(publisher.publish(domains) == domains)
        #expect(publisher.published == domains)
    }

    @Test("A new value replaces unread settings so the stream yields only one value, and status retains the latest value")
    func newestReplacesUnread() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try NodeTestSupport.netmap(addresses: ["100.64.0.1/32"]))
        await node.apply(try NodeTestSupport.netmap(addresses: ["100.64.0.7/32"]))
        // An addressless netmap does not publish empty settings.
        await node.apply(try NodeTestSupport.netmap(addresses: []))
        await node.settingsContinuation.finish()

        let seen = await NodeTestSupport.drain(node.networkSettings)
        let expected = try Self.settings(["100.64.0.7/32"])
        #expect(seen == [expected])
        #expect(await node.status.networkSettings == expected)
    }
}
