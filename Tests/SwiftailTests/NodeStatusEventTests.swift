// `NodeEvent.statusChanged` is emitted only when `status` actually changes. It comes last in an update and does not evict other events
// from the event buffer.

import Foundation
import Testing
@testable import Swiftail

@Suite("Node status change events", .timeLimit(.minutes(1)))
struct NodeStatusEventTests {
    private static func node() throws -> TailnetNode {
        try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
    }

    /// Reads all remaining events from a finished stream.
    private static func remaining(_ events: inout AsyncStream<NodeEvent>.Iterator) async -> [NodeEvent] {
        var rest: [NodeEvent] = []
        while let event = await events.next() { rest.append(event) }
        return rest
    }

    @Test("The first netmap emits statusChanged after stateChanged, with the netmap already reflected in status")
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

    @Test("An identical netmap emits nothing when it arrives again")
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

    @Test("A change in peer count or local addresses emits only statusChanged if the state is unchanged")
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

    @Test("A state transition before the netmap arrives (login required) also emits statusChanged after stateChanged")
    func loginRequired() async throws {
        let node = try Self.node()
        let url = try #require(URL(string: "https://login.example.com/a/0000"))
        await node.requireLoginForStatusTesting(url)
        node.eventQueue.finish()
        #expect(await NodeTestSupport.drain(node.events) == [.stateChanged(.needsLogin(url)), .statusChanged])
    }

    // MARK: Buffer

    @Test("Keeps only one unread statusChanged at the back")
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

    @Test("Even when the buffer fills, statusChanged does not evict other events, and the 64 newest other events remain")
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

    @Test("A waiting consumer receives an event as soon as it is inserted and receives nil if its Task is canceled")
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

extension NodeStatusEventTests {
    @Test("A second consumer does not end the first one's stream. When the stream ends, all waiting consumers receive nil")
    func secondConsumerDoesNotEndTheFirst() async {
        let queue = NodeEventQueue()
        let first = Task { await queue.next() }
        try? await Task.sleep(for: .milliseconds(20))
        let second = Task { await queue.next() }
        try? await Task.sleep(for: .milliseconds(20))
        queue.push(.stateChanged(.running))
        queue.push(.statusChanged)
        let received = [await first.value, await second.value]
        #expect(received.contains(.stateChanged(.running)))
        #expect(received.contains(.statusChanged))

        let waitingA = Task { await queue.next() }
        let waitingB = Task { await queue.next() }
        try? await Task.sleep(for: .milliseconds(20))
        queue.finish()
        #expect(await waitingA.value == nil)
        #expect(await waitingB.value == nil)
    }
}

extension NodeStatusEventTests {
    @Test("Canceling a waiting consumer's Task yields nil for that consumer, and the canceled slot does not intercept later events")
    func cancelledWaiterDoesNotSwallowEvents() async {
        let queue = NodeEventQueue()
        let cancelled = Task { await queue.next() }
        // An external observer cannot tell when a consumer begins waiting. The outcome must be the same whether cancellation occurs before the wait starts or during it.
        await Task.yield()
        cancelled.cancel()
        #expect(await cancelled.value == nil)

        queue.push(.statusChanged)
        #expect(await queue.next() == .statusChanged)
    }

    @Test("Canceling the consuming Task ends the events stream, and resubscribing yields no events")
    func cancellingTheConsumerEndsEvents() async throws {
        let node = try Self.node()
        let consumer = Task {
            var count = 0
            for await _ in node.events { count += 1 }
            return count
        }
        await Task.yield()
        consumer.cancel()
        #expect(await consumer.value == 0)

        node.eventQueue.push(.statusChanged)
        var again = node.events.makeAsyncIterator()
        #expect(await again.next() == nil)
    }
}

private extension TailnetNode {
    /// Updates the state machine as if the home DERP connection came up (`.running` after the netmap).
    func markHomeConnectedForStatusTesting() {
        announce(stateMachine.connected())
    }

    /// Updates the state machine as if the control server supplied a login URL.
    func requireLoginForStatusTesting(_ url: URL) {
        announce(stateMachine.loginRequired(url))
    }
}
