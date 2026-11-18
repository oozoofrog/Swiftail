import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// Tests connection reads and writes, waiting and cancellation, node shutdown, and devices (contract `docs/contracts/SwiftailNetstack.md` behaviors N·A, unit tests 14·16).
///
/// All connections are from one node to its own address. The listener and caller share a stack, and the engine loops back the packets.
@Suite("Node TCP connections", .timeLimit(.minutes(1)))
struct NetstackConnectionTests {
    private typealias Support = NetstackTestSupport

    // MARK: Devices (test 16)

    @Test("listen and connect on the memory device yield invalidConfiguration")
    func otherDevicesReject() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration(), device: .memory())
        guard case .invalidConfiguration = await Support.error({ try await node.listen(port: 443) }) else {
            Issue.record("listen did not yield invalidConfiguration")
            return
        }
        guard case .invalidConfiguration = await Support.error({ try await node.connect(to: "100.64.0.1", port: 443) }) else {
            Issue.record("connect did not yield invalidConfiguration")
            return
        }
        #expect(await node.netstack == nil)
    }

    @Test(".inProcess has an MTU of 1280 and yields nothing on inboundPackets. 1MiB travels in each direction to the node's own address")
    func inProcessTransfersBothWays() async throws {
        let length = 1 << 20
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            #expect(TunnelDevice.inProcess.mtu == 1280)
            let run = Task { try await node.run() }
            try await Support.waitUntil("run() started") { await node.isRunning }
            await node.prepareForTesting(try Support.netmap())

            let pair = try await Support.connectedPair(node)
            let upload = Support.pattern(length, seed: 1), download = Support.pattern(length, seed: 2)
            async let clientSends: Void = { try await pair.client.write(upload); try await pair.client.finishWriting() }()
            async let serverSends: Void = { try await pair.server.write(download); try await pair.server.finishWriting() }()
            async let serverReceived = Support.read(length + 1, from: pair.server)
            async let clientReceived = Support.read(length + 1, from: pair.client)
            try await clientSends
            try await serverSends
            #expect(try await serverReceived == upload, "Reading must continue until EOF (nil)")
            #expect(try await clientReceived == download)
            await pair.client.close()
            await pair.server.close()

            run.cancel()
            _ = await run.result
            #expect(await NodeTestSupport.drain(node.inboundPackets).isEmpty)
        }
    }

    // MARK: Waiting (test 14)

    @Test("A read with no data waits until data arrives. It yields nil once the buffer empties after the peer's FIN")
    func readWaitsForData() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            async let received = pair.server.read()
            try await Support.waitUntil("read is waiting") { await node.isReading(pair.server) }
            try await pair.client.write(Array("hello".utf8))
            #expect(try await received == Array("hello".utf8))

            async let end = pair.server.read()
            try await Support.waitUntil("read is waiting") { await node.isReading(pair.server) }
            try await pair.client.finishWriting()
            #expect(try await end == nil)
            #expect(try await pair.server.read() == nil, "Still nil after EOF")
            #expect(await Support.error { try await pair.client.write([1]) } == .closed, "write after finishWriting")
            try await pair.server.write(Array("back".utf8))
            #expect(try await pair.client.read() == Array("back".utf8), "Half-close leaves the opposite direction intact")
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("A canceled read throws cancelled and leaves the connection and subsequent data intact")
    func cancelledReadKeepsConnection() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let reader = Task { () async throws -> [UInt8]? in try await pair.server.read() }
            try await Support.waitUntil("read is waiting") { await node.isReading(pair.server) }
            reader.cancel()
            #expect(await Support.error { try await reader.value } == .cancelled)
            #expect(await !node.isReading(pair.server))

            try await pair.client.write(Array("after".utf8))
            #expect(try await pair.server.read() == Array("after".utf8))
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("A canceled write throws cancelled and resets the connection")
    func cancelledWriteResetsConnection() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            // Exceed the receive and send buffers (256KiB each) so write blocks against a peer that does not read.
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("write is waiting") { await node.isWriting(pair.client) }
            writer.cancel()
            #expect(await Support.error { try await writer.value } == .cancelled)
            #expect(await Support.error { try await pair.client.read() } == .closed, "This side's connection was aborted")

            var serverError: ConnectionError?
            while serverError == nil {
                serverError = await Support.error { try await pair.server.read() }
            }
            #expect(serverError == .reset, "The peer receives RST")
            await pair.server.close()
            await pair.client.close()
        }
    }

    @Test("A second call in the same direction yields concurrentUse and leaves the first call waiting")
    func concurrentUse() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            async let first = pair.server.read()
            try await Support.waitUntil("read is waiting") { await node.isReading(pair.server) }
            #expect(await Support.error { try await pair.server.read() } == .concurrentUse)

            let writer = Task { () async throws in try await pair.server.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("write is waiting") { await node.isWriting(pair.server) }
            #expect(await Support.error { try await pair.server.write([1]) } == .concurrentUse)

            try await pair.client.write([7])
            #expect(try await first == [7])
            await pair.server.abort()
            #expect(await Support.error { try await writer.value } == .closed, "abort wakes the waiting write")
            await pair.client.close()
        }
    }

    @Test("Dropping a connection without closing it resets the connection")
    func droppedConnectionResets() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            var pair: (client: TailnetConnection, server: TailnetConnection, listener: TailnetListener)? =
                try await Support.connectedPair(node)
            let server = try #require(pair?.server)
            pair = nil
            var error: ConnectionError?
            while error == nil {
                error = await Support.error { try await server.read() }
            }
            #expect(error == .reset)
            await server.close()
        }
    }

    @Test("When run() ends, it wakes waiting read, write, connect, and listener calls (notRunning, nil). Subsequent listen and connect calls also yield notRunning")
    func runEndWakesWaiters() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let run = Task { try await node.run() }
            try await Support.waitUntil("run() started") { await node.isRunning }
            await node.prepareForTesting(try Support.netmap(peers: [Support.phone]))

            let pair = try await Support.connectedPair(node)
            // The direction opposite the writer (client → server) has no data, so the client's read waits until the end.
            let reader = Task { () async throws -> [UInt8]? in try await pair.client.read() }
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            let other = try await node.listen(port: 9_001)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = other.makeAsyncIterator()
                return await connections.next()
            }
            // The SYN for a connection to the peer does not go out, so the connection does not establish.
            let connector = Task { () async throws -> TailnetConnection in
                try await node.connect(to: "rd-phone-1a2b3c4d", port: 80)
            }
            try await Support.waitUntil("All calls are waiting") {
                let reading = await node.isReading(pair.client), writing = await node.isWriting(pair.client)
                let accepting = await node.isAccepting(other), connecting = await node.isConnecting
                return reading && writing && accepting && connecting
            }

            run.cancel()
            _ = await run.result
            #expect(await Support.error { try await reader.value } == .notRunning)
            #expect(await Support.error { try await writer.value } == .notRunning)
            #expect(await Support.error { try await connector.value } == .notRunning)
            #expect(await accepter.value == nil)
            #expect(await Support.error { try await node.listen(port: 9_002) } == .notRunning)
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_000) } == .notRunning)
            #expect(await Support.error { try await pair.server.read() } == .notRunning)
            await pair.client.close()
        }
    }

    @Test("connect yields notRunning when the state is outside .running")
    func connectNeedsRunningState() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_000) } == .notRunning)
            let run = Task { try await node.run() }
            try await Support.waitUntil("run() started") { await node.isRunning }
            await node.apply(try Support.netmap())
            #expect(await node.status.state == .starting)
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_000) } == .notRunning)
            run.cancel()
            _ = await run.result
        }
    }

    @Test("A canceled connect throws cancelled and abandons the attempt")
    func cancelledConnect() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = Task { () async throws -> TailnetConnection in
                try await node.connect(to: "rd-phone-1a2b3c4d.tail0001.ts.net", port: 80)
            }
            try await Support.waitUntil("connect is waiting") { await node.isConnecting }
            connector.cancel()
            #expect(await Support.error { try await connector.value } == .cancelled)
            #expect(await node.trackedConnectionCount == 0)
        }
    }
}
