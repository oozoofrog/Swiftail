import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// 연결의 읽기·쓰기, 기다림과 취소, 노드의 끝, 장치(계약 `docs/contracts/SwiftailNetstack.md` 동작 N·A, 단위 시험 14·16).
///
/// 모두 노드 하나가 자기 주소로 건 연결이다. 듣는 쪽과 거는 쪽이 같은 스택에 있고, 패킷은 엔진의 되돌리기를 거친다.
@Suite("노드의 TCP: 연결", .timeLimit(.minutes(1)))
struct NetstackConnectionTests {
    private typealias Support = NetstackTestSupport

    // MARK: 장치 (시험 16)

    @Test("메모리 장치에서 listen·connect는 invalidConfiguration이다")
    func otherDevicesReject() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration(), device: .memory())
        guard case .invalidConfiguration = await Support.error({ try await node.listen(port: 443) }) else {
            Issue.record("listen이 invalidConfiguration이 아니다")
            return
        }
        guard case .invalidConfiguration = await Support.error({ try await node.connect(to: "100.64.0.1", port: 443) }) else {
            Issue.record("connect가 invalidConfiguration이 아니다")
            return
        }
        #expect(await node.netstack == nil)
    }

    @Test(".inProcess는 MTU 1280이고 inboundPackets로 아무것도 내지 않는다. 자기 주소로 1MiB가 양방향으로 오간다")
    func inProcessTransfersBothWays() async throws {
        let length = 1 << 20
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            #expect(TunnelDevice.inProcess.mtu == 1280)
            let run = Task { try await node.run() }
            try await Support.waitUntil("run()이 시작됨") { await node.isRunning }
            await node.prepareForTesting(try Support.netmap())

            let pair = try await Support.connectedPair(node)
            let upload = Support.pattern(length, seed: 1), download = Support.pattern(length, seed: 2)
            async let clientSends: Void = { try await pair.client.write(upload); try await pair.client.finishWriting() }()
            async let serverSends: Void = { try await pair.server.write(download); try await pair.server.finishWriting() }()
            async let serverReceived = Support.read(length + 1, from: pair.server)
            async let clientReceived = Support.read(length + 1, from: pair.client)
            try await clientSends
            try await serverSends
            #expect(try await serverReceived == upload, "읽기가 끝(nil)까지 이어져야 한다")
            #expect(try await clientReceived == download)
            await pair.client.close()
            await pair.server.close()

            run.cancel()
            _ = await run.result
            #expect(await NodeTestSupport.drain(node.inboundPackets).isEmpty)
        }
    }

    // MARK: 기다림 (시험 14)

    @Test("데이터 없는 read는 기다리다 데이터가 오면 깨어난다. 상대의 FIN 뒤 버퍼가 비면 nil")
    func readWaitsForData() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            async let received = pair.server.read()
            try await Support.waitUntil("read가 기다림") { await node.isReading(pair.server) }
            try await pair.client.write(Array("hello".utf8))
            #expect(try await received == Array("hello".utf8))

            async let end = pair.server.read()
            try await Support.waitUntil("read가 기다림") { await node.isReading(pair.server) }
            try await pair.client.finishWriting()
            #expect(try await end == nil)
            #expect(try await pair.server.read() == nil, "끝난 뒤에도 nil")
            #expect(await Support.error { try await pair.client.write([1]) } == .closed, "finishWriting 뒤의 write")
            try await pair.server.write(Array("back".utf8))
            #expect(try await pair.client.read() == Array("back".utf8), "반닫힘 뒤 반대 방향은 그대로")
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("취소된 read는 cancelled를 던지고 연결과 그 뒤의 데이터는 그대로다")
    func cancelledReadKeepsConnection() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let reader = Task { () async throws -> [UInt8]? in try await pair.server.read() }
            try await Support.waitUntil("read가 기다림") { await node.isReading(pair.server) }
            reader.cancel()
            #expect(await Support.error { try await reader.value } == .cancelled)
            #expect(await !node.isReading(pair.server))

            try await pair.client.write(Array("after".utf8))
            #expect(try await pair.server.read() == Array("after".utf8))
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("취소된 write는 cancelled를 던지고 연결을 RST로 끊는다")
    func cancelledWriteResetsConnection() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            // 받는 버퍼와 보내는 버퍼(256KiB씩)를 넘겨, 읽지 않는 상대 앞에서 write가 멈추게 한다.
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("write가 기다림") { await node.isWriting(pair.client) }
            writer.cancel()
            #expect(await Support.error { try await writer.value } == .cancelled)
            #expect(await Support.error { try await pair.client.read() } == .closed, "이 쪽은 끊은 연결이다")

            var serverError: ConnectionError?
            while serverError == nil {
                serverError = await Support.error { try await pair.server.read() }
            }
            #expect(serverError == .reset, "상대는 RST를 받는다")
            await pair.server.close()
            await pair.client.close()
        }
    }

    @Test("같은 방향의 둘째 호출은 concurrentUse이고 먼저 기다리던 호출은 그대로다")
    func concurrentUse() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            async let first = pair.server.read()
            try await Support.waitUntil("read가 기다림") { await node.isReading(pair.server) }
            #expect(await Support.error { try await pair.server.read() } == .concurrentUse)

            let writer = Task { () async throws in try await pair.server.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("write가 기다림") { await node.isWriting(pair.server) }
            #expect(await Support.error { try await pair.server.write([1]) } == .concurrentUse)

            try await pair.client.write([7])
            #expect(try await first == [7])
            await pair.server.abort()
            #expect(await Support.error { try await writer.value } == .closed, "abort가 기다리던 write를 깨운다")
            await pair.client.close()
        }
    }

    @Test("닫지 않고 버려진 연결은 RST로 끊긴다")
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

    @Test("run()이 끝나면 기다리던 read·write·connect·리스너가 깨어나고(notRunning, nil) 그 뒤의 listen·connect도 notRunning")
    func runEndWakesWaiters() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let run = Task { try await node.run() }
            try await Support.waitUntil("run()이 시작됨") { await node.isRunning }
            await node.prepareForTesting(try Support.netmap(peers: [Support.phone]))

            let pair = try await Support.connectedPair(node)
            // 쓰는 쪽(client → server)의 반대 방향에는 데이터가 없으므로 client의 read는 끝까지 기다린다.
            let reader = Task { () async throws -> [UInt8]? in try await pair.client.read() }
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            let other = try await node.listen(port: 9_001)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = other.makeAsyncIterator()
                return await connections.next()
            }
            // 피어로 건 연결의 SYN은 나가지 않으므로 맺어지지 않는다.
            let connector = Task { () async throws -> TailnetConnection in
                try await node.connect(to: "rd-phone-1a2b3c4d", port: 80)
            }
            try await Support.waitUntil("모두 기다림") {
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

    @Test("상태가 .running이 아니면 connect는 notRunning이다")
    func connectNeedsRunningState() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_000) } == .notRunning)
            let run = Task { try await node.run() }
            try await Support.waitUntil("run()이 시작됨") { await node.isRunning }
            await node.apply(try Support.netmap())
            #expect(await node.status.state == .starting)
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_000) } == .notRunning)
            run.cancel()
            _ = await run.result
        }
    }

    @Test("취소된 connect는 cancelled를 던지고 시도를 버린다")
    func cancelledConnect() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = Task { () async throws -> TailnetConnection in
                try await node.connect(to: "rd-phone-1a2b3c4d.tail0001.ts.net", port: 80)
            }
            try await Support.waitUntil("connect가 기다림") { await node.isConnecting }
            connector.cancel()
            #expect(await Support.error { try await connector.value } == .cancelled)
            #expect(await node.trackedConnectionCount == 0)
        }
    }
}
