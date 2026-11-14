import Foundation
import SwiftailBase
import SwiftailEngine
import Testing
@testable import Swiftail

/// 터널 설정을 내는 규칙. 계약 `docs/contracts/SwiftailTunnel.md` 동작 E, 시험 목록 6.
@Suite("터널 설정 내기")
struct NetworkSettingsPublisherTests {
    private static func settings(_ addresses: [String] = ["100.64.0.1/32"]) throws -> TunnelNetworkSettings {
        try #require(TunnelNetworkSettings(netmap: try NodeTestSupport.netmap(addresses: addresses), mtu: 1280, at: Date()))
    }

    @Test("자기 주소가 없으면(산출 nil) 내지 않는다")
    func noAddresses() throws {
        var publisher = NetworkSettingsPublisher()
        #expect(TunnelNetworkSettings(netmap: try NodeTestSupport.netmap(addresses: []), mtu: 1280, at: Date()) == nil)
        #expect(publisher.publish(nil) == nil)
        #expect(publisher.published == nil)
    }

    @Test("같은 값은 내지 않고, 주소 없는 netmap이 와도 마지막 값을 지우지 않는다")
    func sameValue() throws {
        var publisher = NetworkSettingsPublisher()
        let first = try Self.settings()
        #expect(publisher.publish(first) == first)
        #expect(publisher.publish(try Self.settings()) == nil)
        #expect(publisher.publish(nil) == nil)
        #expect(publisher.published == first)
    }

    @Test("DNS 서버만, match 도메인만 바뀌어도 낸다")
    func dnsOnlyChanges() throws {
        var publisher = NetworkSettingsPublisher()
        let base = try Self.settings()
        _ = publisher.publish(base)

        var servers = base
        // DNS 서버 목록만 바꾼다(있으면 비우고, 없으면 하나 넣는다).
        servers.dnsServers = base.dnsServers.isEmpty ? [try #require(IPAddress("100.100.100.100"))] : []
        #expect(publisher.publish(servers) == servers)

        var domains = servers
        domains.dnsMatchDomains = servers.dnsMatchDomains + ["example.internal"]
        #expect(publisher.publish(domains) == domains)
        #expect(publisher.published == domains)
    }

    @Test("읽지 않은 설정은 새 것이 대신해 흐름에서 하나만 나오고, status에 마지막 값이 남는다")
    func newestReplacesUnread() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try NodeTestSupport.netmap(addresses: ["100.64.0.1/32"]))
        await node.apply(try NodeTestSupport.netmap(addresses: ["100.64.0.7/32"]))
        // 주소 없는 netmap은 빈 설정을 내지 않는다.
        await node.apply(try NodeTestSupport.netmap(addresses: []))
        await node.settingsContinuation.finish()

        let seen = await NodeTestSupport.drain(node.networkSettings)
        let expected = try Self.settings(["100.64.0.7/32"])
        #expect(seen == [expected])
        #expect(await node.status.networkSettings == expected)
    }
}
