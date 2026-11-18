import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// Listener coverage: `listen` before `run()`, duplicate ports, limits, closing, and the queue (contract `docs/contracts/SwiftailNetstack.md` behaviors A1·S3·S5).
@Suite("Node TCP listeners", .timeLimit(.minutes(1)))
struct NetstackListenerTests {
    private typealias Support = NetstackTestSupport

    @Test("A listener opened before run() accepts connections after run() starts. Port 0 and duplicate ports are rejected")
    func listenBeforeRun() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let listener = try await node.listen(port: 9_000)
            #expect(listener.port == 9_000)
            #expect(await Support.error { try await node.listen(port: 9_000) } == .addressInUse)
            #expect(await Support.error { try await node.listen(port: 0) } == .invalidConfiguration("포트는 0이 아니어야 한다"))

            let run = Task { try await node.run() }
            try await Support.waitUntil("run() started") { await node.isRunning }
            await node.prepareForTesting(try Support.netmap())
            let client = try await node.connect(to: "100.64.0.1", port: 9_000)
            var connections = listener.makeAsyncIterator()
            let server = try #require(await connections.next())
            try await client.write([1, 2, 3])
            #expect(try await server.read() == [1, 2, 3])
            await client.close()
            await server.close()
            run.cancel()
            _ = await run.result
        }
    }

    @Test("Allows up to 16 listeners and reopens the same port after closing")
    func listenerLimitAndReuse() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            var listeners: [TailnetListener] = []
            for port in UInt16(9_000)..<9_016 {
                listeners.append(try await node.listen(port: port))
            }
            #expect(await Support.error { try await node.listen(port: 9_016) } == .limitReached)
            await listeners[0].close()
            await listeners[0].close()
            listeners[0] = try await node.listen(port: 9_000)
            #expect(await Support.error { try await node.listen(port: 9_001) } == .addressInUse)
            for listener in listeners { await listener.close() }
        }
    }

    @Test("Connections established before acceptance are yielded in arrival order and retain any data and FIN received in the meantime")
    func queuedConnections() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let listener = try await node.listen(port: 9_000)
            let first = try await node.connect(to: "100.64.0.1", port: 9_000)
            let second = try await node.connect(to: "100.64.0.1", port: 9_000)
            try await first.write(Array("queued".utf8))
            try await first.finishWriting()

            var connections = listener.makeAsyncIterator()
            let firstServer = try #require(await connections.next())
            let secondServer = try #require(await connections.next())
            #expect(firstServer.remoteEndpoint == first.localEndpoint)
            #expect(secondServer.remoteEndpoint == second.localEndpoint)
            #expect(try await Support.read(100, from: firstServer) == Array("queued".utf8))
            #expect(try await firstServer.read() == nil)
            for connection in [first, second, firstServer, secondServer] { await connection.close() }
        }
    }

    @Test("Closing a listener ends the waiting stream and resets unaccepted connections. Accepted connections stay intact")
    func closeEndsIteration() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let queued = try await node.connect(to: "100.64.0.1", port: 9_000)
            await pair.listener.close()
            var error: ConnectionError?
            while error == nil {
                error = await Support.error { try await queued.read() }
            }
            #expect(error == .reset)

            let listener = try await node.listen(port: 9_001)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = listener.makeAsyncIterator()
                return await connections.next()
            }
            try await Support.waitUntil("The stream is waiting") { await node.isAccepting(listener) }
            var second = listener.makeAsyncIterator()
            #expect(await second.next() == nil, "The second Task's stream ends immediately")
            await listener.close()
            #expect(await accepter.value == nil)

            try await pair.client.write([9])
            #expect(try await pair.server.read() == [9])
            for connection in [pair.client, pair.server, queued] { await connection.close() }
        }
    }

    @Test("Canceling the Task waiting on the stream ends only that stream and leaves the listener intact")
    func cancelledIteration() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let listener = try await node.listen(port: 9_000)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = listener.makeAsyncIterator()
                return await connections.next()
            }
            try await Support.waitUntil("The stream is waiting") { await node.isAccepting(listener) }
            accepter.cancel()
            #expect(await accepter.value == nil)

            let client = try await node.connect(to: "100.64.0.1", port: 9_000)
            var connections = listener.makeAsyncIterator()
            let server = try #require(await connections.next())
            await client.close()
            await server.close()
            await listener.close()
        }
    }

    @Test("Dropping a listener closes it so the port can be reopened")
    func droppedListenerCloses() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            var listener: TailnetListener? = try await node.listen(port: 9_000)
            #expect(listener?.port == 9_000)
            listener = nil
            try await Support.waitUntil("The port was released") {
                await Support.error { try await node.listen(port: 9_000) } == nil
            }
        }
    }

    @Test("Dropping a listener before run() releases the port. Reopening the same port gives a listener that accepts connections after run()")
    func droppedListenerBeforeRunReleasesPort() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            var dropped: TailnetListener? = try await node.listen(port: 9_000)
            #expect(dropped?.port == 9_000)
            dropped = nil
            let listener = try await node.listen(port: 9_000)

            let run = Task { try await node.run() }
            try await Support.waitUntil("run() started") { await node.isRunning }
            await node.prepareForTesting(try Support.netmap())
            let client = try await node.connect(to: "100.64.0.1", port: 9_000)
            var connections = listener.makeAsyncIterator()
            let server = try #require(await connections.next())
            await client.close()
            await server.close()
            run.cancel()
            _ = await run.result
        }
    }

    @Test("A listener dropped before run() does not count against the limit")
    func droppedListenersBeforeRunDoNotCount() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            var dropped: [TailnetListener]? = []
            for port in UInt16(9_000)..<9_016 {
                dropped?.append(try await node.listen(port: port))
            }
            #expect(await Support.error { try await node.listen(port: 9_016) } == .limitReached)
            dropped = nil
            let listener = try await node.listen(port: 9_016)
            #expect(listener.port == 9_016)
        }
    }

    @Test("Even during run(), listen on the same port immediately after dropping the listener does not yield addressInUse")
    func droppedListenerReleasesPortImmediately() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            for _ in 0..<20 {
                var listener: TailnetListener? = try await node.listen(port: 9_000)
                #expect(listener?.port == 9_000)
                listener = nil
                listener = try await node.listen(port: 9_000)
                #expect(listener?.port == 9_000)
            }
        }
    }
}
