import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// 리스너: `run()` 전의 `listen`, 포트 중복, 상한, 닫기, 대기열(계약 `docs/contracts/SwiftailNetstack.md` 동작 A1·S3·S5).
@Suite("노드의 TCP: 리스너", .timeLimit(.minutes(1)))
struct NetstackListenerTests {
    private typealias Support = NetstackTestSupport

    @Test("run() 전에 연 리스너가 run()이 시작한 뒤 연결을 받는다. 포트 0과 중복은 거절한다")
    func listenBeforeRun() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let listener = try await node.listen(port: 9_000)
            #expect(listener.port == 9_000)
            #expect(await Support.error { try await node.listen(port: 9_000) } == .addressInUse)
            #expect(await Support.error { try await node.listen(port: 0) } == .invalidConfiguration("포트는 0이 아니어야 한다"))

            let run = Task { try await node.run() }
            try await Support.waitUntil("run()이 시작됨") { await node.isRunning }
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

    @Test("리스너는 16개까지이고, 닫으면 같은 포트를 다시 열 수 있다")
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

    @Test("받아 가기 전에 맺어진 연결은 들어온 차례로 나오고, 그동안 온 데이터와 FIN을 쥐고 있다")
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

    @Test("리스너를 닫으면 기다리던 흐름이 끝나고 받아 가지 않은 연결은 RST로 끊긴다. 받아 간 연결은 그대로다")
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
            try await Support.waitUntil("흐름이 기다림") { await node.isAccepting(listener) }
            var second = listener.makeAsyncIterator()
            #expect(await second.next() == nil, "둘째 Task의 흐름은 곧바로 끝난다")
            await listener.close()
            #expect(await accepter.value == nil)

            try await pair.client.write([9])
            #expect(try await pair.server.read() == [9])
            for connection in [pair.client, pair.server, queued] { await connection.close() }
        }
    }

    @Test("흐름을 기다리던 Task를 취소하면 그 흐름만 끝나고 리스너는 그대로다")
    func cancelledIteration() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let listener = try await node.listen(port: 9_000)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = listener.makeAsyncIterator()
                return await connections.next()
            }
            try await Support.waitUntil("흐름이 기다림") { await node.isAccepting(listener) }
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

    @Test("버려진 리스너는 닫혀 포트를 다시 열 수 있다")
    func droppedListenerCloses() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            var listener: TailnetListener? = try await node.listen(port: 9_000)
            #expect(listener?.port == 9_000)
            listener = nil
            try await Support.waitUntil("포트가 풀림") {
                await Support.error { try await node.listen(port: 9_000) } == nil
            }
        }
    }
}
