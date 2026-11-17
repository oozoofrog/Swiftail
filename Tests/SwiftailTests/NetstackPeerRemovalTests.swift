import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// 주소의 주인이 바뀐 연결(계약 `docs/contracts/SwiftailNetstack.md` 동작 X10·S9·N7, 단위 시험 15).
///
/// 피어로 건 연결은 SYN이 나가지 않아 맺는 중에 머문다. 그래도 노드가 주인을 견주어 끊는 길은 맺어진 연결과 같다
/// (`TCPStack.removeConnections(toRemoteAddress:)`는 연결의 상태를 가리지 않는다). 자기 주소의 바뀜은 맺어진 연결로 본다.
@Suite("노드의 TCP: 주소의 주인이 바뀜", .timeLimit(.minutes(1)))
struct NetstackPeerRemovalTests {
    private typealias Support = NetstackTestSupport

    private static func pendingConnect(_ node: TailnetNode) async throws -> Task<TailnetConnection, any Error> {
        let connector = Task { () async throws -> TailnetConnection in
            try await node.connect(to: "100.64.0.2", port: 80)
        }
        try await Support.waitUntil("connect가 기다림") { await node.isConnecting }
        return connector
    }

    @Test("피어가 netmap에서 빠지면 그 주소의 연결이 peerRemoved로 끝난다")
    func peerRemoved() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = try await Self.pendingConnect(node)
            await node.apply(try Support.netmap())
            #expect(await Support.error { try await connector.value } == .peerRemoved)
            #expect(await node.trackedConnectionCount == 0)
        }
    }

    @Test("같은 주소가 다른 키의 것이 되면 peerRemoved로 끝난다")
    func ownerChanged() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = try await Self.pendingConnect(node)
            var heir = Support.phone
            heir.id = 9
            heir.key = 0x99
            await node.apply(try Support.netmap(peers: [heir]))
            #expect(await Support.error { try await connector.value } == .peerRemoved)
        }
    }

    @Test("앞 주인의 키가 만료되어 주소가 다른 노드로 넘어가면, 새 netmap이 없어도 그 연결이 끝나고 whoIs와 스택의 주인이 함께 바뀐다")
    func ownerKeyExpires() async throws {
        var low = WhoIsTestSupport.phone
        low.stableID = "nStableLow"
        var high = WhoIsTestSupport.phone
        high.id = 5
        high.stableID = "nStableHigh"
        high.key = 0x55
        let (owner, heir) = (low, high)
        let stableIDs = [
            NodeTestSupport.nodeKey(low.key): "nStableLow", NodeTestSupport.nodeKey(high.key): "nStableHigh",
        ]
        try await Support.withRunningNode(try WhoIsTestSupport.netmap(peers: [owner, heir])) { node in
            let address = try #require(IPAddress("100.64.0.2"))
            // 주인(node ID가 작은 쪽)의 키가 곧 만료되는 netmap. 주인은 그대로라 이 적용은 연결을 건드리지 않는다.
            var expiring = owner
            expiring.keyExpiry = Date().addingTimeInterval(2)
            await node.apply(try WhoIsTestSupport.netmap(peers: [expiring, heir]))
            let connector = try await Self.pendingConnect(node)
            #expect(await node.ownerViews(of: address).identity == "nStableLow")

            // 만료 시각이 지나 엔진이 피어를 바꿀 때까지 본다. 그동안 whoIs의 답은 늘 스택이 쥔 주인의 것이다.
            try await Support.waitUntil("키 만료가 처리됨") {
                let views = await node.ownerViews(of: address)
                #expect(views.identity == views.stackOwner.flatMap { stableIDs[$0.description] })
                return views.identity == "nStableHigh"
            }
            try await Support.waitUntil("옛 주인의 연결이 끝남") { await !node.isConnecting }
            #expect(await Support.error { try await connector.value } == .peerRemoved)
        }
    }

    @Test("주인이 그대로인 netmap은 연결을 건드리지 않는다")
    func unchangedOwnerKeepsConnection() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = try await Self.pendingConnect(node)
            var renamed = Support.phone
            renamed.name = "rd-phone-renamed.tail0001.ts.net."
            await node.apply(try Support.netmap(peers: [renamed]))
            try await Task.sleep(for: .milliseconds(50))
            #expect(await node.isConnecting)
            connector.cancel()
            #expect(await Support.error { try await connector.value } == .cancelled)
        }
    }

    @Test("자기 주소가 바뀌면 맺어진 연결이 양쪽 모두 peerRemoved로 끝난다")
    func selfAddressChanged() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let reader = Task { () async throws -> [UInt8]? in try await pair.server.read() }
            try await Support.waitUntil("read가 기다림") { await node.isReading(pair.server) }
            await node.apply(try Support.netmap(selfAddresses: ["100.64.0.9/32"]))
            #expect(await Support.error { try await reader.value } == .peerRemoved)
            #expect(await Support.error { try await pair.client.write([1]) } == .peerRemoved)
            await pair.client.close()
            await pair.server.close()
            #expect(await node.trackedConnectionCount == 0)
        }
    }
}

extension TailnetNode {
    /// 한 번의 actor 실행에서 본 `whoIs`의 답(`StableID`)과 스택이 그 주소의 주인으로 쥔 키.
    func ownerViews(of address: IPAddress) -> (identity: String?, stackOwner: NodePublicKey?) {
        (whoIs(address)?.stableID, netstack?.addressOwners[address])
    }
}
