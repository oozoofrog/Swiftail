// `NodeEvent.statusChanged`: `status`가 실제로 바뀔 때만 나오고, 한 갱신의 맨 뒤에 오고, 사건 버퍼에서 다른 사건을
// 밀어내지 않는다.

import Foundation
import Testing
@testable import Swiftail

@Suite("노드: status 바뀜 사건", .timeLimit(.minutes(1)))
struct NodeStatusEventTests {
    private static func node() throws -> TailnetNode {
        try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
    }

    /// 끝낸 흐름에 남은 사건을 모두 읽는다.
    private static func remaining(_ events: inout AsyncStream<NodeEvent>.Iterator) async -> [NodeEvent] {
        var rest: [NodeEvent] = []
        while let event = await events.next() { rest.append(event) }
        return rest
    }

    @Test("첫 netmap은 stateChanged 뒤에 statusChanged를 낸다. 그때 status는 이미 netmap을 담고 있다")
    func firstNetmap() async throws {
        let node = try Self.node()
        await node.markHomeConnectedForStatusTesting()
        await node.apply(try NodeTestSupport.netmap())
        node.eventQueue.finish()

        #expect(await NodeTestSupport.drain(node.events) == [.stateChanged(.running), .statusChanged])
        let status = await node.status
        #expect(status.fqdn == "rd-mac-1a2b3c4d.tail0001.ts.net")
        #expect(status.addresses.map(\.description) == ["100.64.0.1"])
    }

    @Test("같은 netmap이 다시 오면 아무것도 내지 않는다")
    func sameNetmap() async throws {
        let node = try Self.node()
        var events = node.events.makeAsyncIterator()
        await node.markHomeConnectedForStatusTesting()
        await node.apply(try NodeTestSupport.netmap())
        #expect(await events.next() == .stateChanged(.running))
        #expect(await events.next() == .statusChanged)

        await node.apply(try NodeTestSupport.netmap())
        node.eventQueue.finish()
        #expect(await Self.remaining(&events) == [])
    }

    @Test("상태가 그대로여도 피어 수나 자기 주소가 바뀌면 statusChanged만 낸다")
    func netmapContentChanges() async throws {
        let node = try Self.node()
        var events = node.events.makeAsyncIterator()
        await node.markHomeConnectedForStatusTesting()
        await node.apply(try NodeTestSupport.netmap())
        _ = await events.next()
        _ = await events.next()

        await node.apply(try NodeTestSupport.netmap(peerAddress: "100.64.0.2/32"))
        #expect(await events.next() == .statusChanged)
        #expect(await node.status.peerCount == 1)

        await node.apply(try NodeTestSupport.netmap(addresses: ["100.64.0.9/32"], peerAddress: "100.64.0.2/32"))
        node.eventQueue.finish()
        #expect(await Self.remaining(&events) == [.statusChanged])
        #expect(await node.status.addresses.map(\.description) == ["100.64.0.9"])
    }

    @Test("netmap 전의 상태 전이(로그인 필요)도 stateChanged 뒤에 statusChanged를 낸다")
    func loginRequired() async throws {
        let node = try Self.node()
        let url = try #require(URL(string: "https://login.example.com/a/0000"))
        await node.requireLoginForStatusTesting(url)
        node.eventQueue.finish()
        #expect(await NodeTestSupport.drain(node.events) == [.stateChanged(.needsLogin(url)), .statusChanged])
    }

    // MARK: 버퍼

    @Test("읽지 않은 statusChanged는 하나만, 맨 뒤에 남는다")
    func coalescesToEnd() async {
        let queue = NodeEventQueue()
        queue.push(.statusChanged)
        queue.push(.stateChanged(.running))
        queue.push(.statusChanged)
        queue.push(.peerPathChanged(fqdn: "rd-phone-1a2b3c4d.tail0001.ts.net", path: .relayed(derpRegion: 1)))
        queue.push(.statusChanged)
        queue.finish()

        var seen: [NodeEvent] = []
        while let event = await queue.next() { seen.append(event) }
        #expect(seen == [
            .stateChanged(.running), .peerPathChanged(fqdn: "rd-phone-1a2b3c4d.tail0001.ts.net", path: .relayed(derpRegion: 1)),
            .statusChanged,
        ])
    }

    @Test("버퍼가 차도 statusChanged는 다른 사건을 밀어내지 않고, 다른 사건은 가장 새 것 64개가 남는다")
    func bufferLimit() async {
        let queue = NodeEventQueue()
        let limit = TailnetNode.eventBufferLimit
        func path(_ region: Int) -> NodeEvent {
            .peerPathChanged(fqdn: "rd-phone-1a2b3c4d.tail0001.ts.net", path: .relayed(derpRegion: Int64(region)))
        }
        for region in 0..<limit { queue.push(path(region)) }
        for _ in 0..<10 { queue.push(.statusChanged) }
        var seen: [NodeEvent] = []
        queue.finish()
        while let event = await queue.next() { seen.append(event) }
        #expect(seen == (0..<limit).map(path) + [.statusChanged])

        let full = NodeEventQueue()
        full.push(.statusChanged)
        for region in 0..<(limit + 5) { full.push(path(region)) }
        full.finish()
        seen = []
        while let event = await full.next() { seen.append(event) }
        #expect(seen == [.statusChanged] + (5..<(limit + 5)).map(path))
    }

    @Test("기다리던 소비자는 넣는 즉시 받고, 소비자의 Task가 취소되면 nil을 받는다")
    func waitingConsumer() async {
        let queue = NodeEventQueue()
        let waiting = Task { await queue.next() }
        try? await Task.sleep(for: .milliseconds(20))
        queue.push(.statusChanged)
        #expect(await waiting.value == .statusChanged)

        let cancelled = Task { await queue.next() }
        cancelled.cancel()
        #expect(await cancelled.value == nil)
    }
}

private extension TailnetNode {
    /// 홈 DERP 연결이 선 것처럼 상태 기계에 넣는다(netmap 뒤면 `.running`).
    func markHomeConnectedForStatusTesting() {
        announce(stateMachine.connected())
    }

    /// 제어 서버가 로그인 URL을 준 것처럼 상태 기계에 넣는다.
    func requireLoginForStatusTesting(_ url: URL) {
        announce(stateMachine.loginRequired(url))
    }
}
