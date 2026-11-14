import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// 연결·리스너의 경계: 거절, 닫기·끊기가 기다리던 호출을 깨우는 모양, 잘못된 길이, 시작 검사에서 끝난 `run()`, 손실 아래의
/// 전송(계약 `docs/contracts/SwiftailNetstack.md` 동작 A·N).
///
/// 모두 노드 하나가 자기 주소로 건 연결이다. 멈추면 모음의 시간 제한이 시험을 실패로 끝낸다.
@Suite("노드의 TCP: 경계", .timeLimit(.minutes(1)))
struct NetstackBoundaryTests {
    private typealias Support = NetstackTestSupport

    @Test("듣지 않는 자기 포트로 건 연결은 refused다")
    func connectToClosedPortIsRefused() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_001) } == .refused)
            #expect(await node.trackedConnectionCount == 0, "거절된 시도는 기록을 남기지 않는다")
        }
    }

    @Test("close는 기다리던 read와 write를 closed로 깨운다")
    func closeWakesWaiters() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            // 같은 연결의 읽기와 쓰기는 동시에 기다릴 수 있다. server는 보내지 않으므로 client의 read는 끝까지 기다린다.
            let reader = Task { () async throws -> [UInt8]? in try await pair.client.read() }
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("read와 write가 기다림") {
                let reading = await node.isReading(pair.client), writing = await node.isWriting(pair.client)
                return reading && writing
            }
            await pair.client.close()
            #expect(await Support.error { try await reader.value } == .closed)
            #expect(await Support.error { try await writer.value } == .closed)
            await pair.server.close()
        }
    }

    @Test("상대의 abort는 기다리던 read와 write를 reset으로 끝내고, 그 뒤의 finishWriting도 reset이다")
    func peerAbortEndsWaiters() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let reader = Task { () async throws -> [UInt8]? in try await pair.client.read() }
            // server는 읽지 않으므로 받는 버퍼와 보내는 버퍼가 차서 write가 멈춘다.
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("read와 write가 기다림") {
                let reading = await node.isReading(pair.client), writing = await node.isWriting(pair.client)
                return reading && writing
            }
            await pair.server.abort()
            #expect(await Support.error { try await reader.value } == .reset)
            #expect(await Support.error { try await writer.value } == .reset)
            #expect(await Support.error { try await pair.client.finishWriting() } == .reset)
            #expect(await Support.error { try await pair.client.read() } == .reset)
            await pair.client.close()
        }
    }

    @Test("읽을 길이가 0 이하면 invalidConfiguration이고 연결은 그대로다")
    func readRejectsNonPositiveLength() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            for length in [0, -1] {
                #expect(
                    await Support.error { try await pair.server.read(upTo: length) }
                        == .invalidConfiguration("읽을 길이는 1 이상이어야 한다"))
            }
            try await pair.client.write([5])
            #expect(try await pair.server.read(upTo: 1) == [5])
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("run()이 시작 검사에서 끝나면 run() 전에 연 리스너의 흐름이 끝나고 그 뒤의 listen은 notRunning이다")
    func listenerEndsWhenRunFailsAtStart() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            #expect(StateDirectoryClaims.shared.claim(directory))
            defer { StateDirectoryClaims.shared.release(directory) }
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let listener = try await node.listen(port: 9_000)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = listener.makeAsyncIterator()
                return await connections.next()
            }
            try await Support.waitUntil("흐름이 기다림") { await node.isAccepting(listener) }

            do throws(NodeError) {
                try await node.run()
                Issue.record("run()이 던지지 않았다")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("기대 stateDirectoryInUse, 실제 \(error)")
                    return
                }
            }
            #expect(await accepter.value == nil)
            var again = listener.makeAsyncIterator()
            #expect(await again.next() == nil)
            #expect(await Support.error { try await node.listen(port: 9_001) } == .notRunning)
        }
    }

    @Test("손실 2%에서도 256KiB가 바이트까지 일치해 도착한다")
    func transferSurvivesPacketLoss() async throws {
        let length = 256 * 1_024
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            await node.setInProcessLoss(rate: 0.02, seed: 7)
            let upload = Support.pattern(length, seed: 3)
            async let sent: Void = { try await pair.client.write(upload); try await pair.client.finishWriting() }()
            async let received = Support.read(length + 1, from: pair.server)
            try await sent
            #expect(try await received == upload)
            await node.setInProcessLoss(rate: 0, seed: 0)
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("기다리던 write 중의 finishWriting은 write를 closed로 깨우고, 이미 들어간 것은 FIN 앞에 나간다")
    func finishWritingWakesWaitingWrite() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let upload = Support.pattern(1 << 20, seed: 9)
            let writer = Task { () async throws in try await pair.client.write(upload) }
            try await Support.waitUntil("write가 기다림") { await node.isWriting(pair.client) }
            try await pair.client.finishWriting()
            #expect(await Support.error { try await writer.value } == .closed)

            let received = try await Support.read(upload.count + 1, from: pair.server)
            #expect(!received.isEmpty && received.count < upload.count)
            #expect(received == Array(upload.prefix(received.count)), "FIN 앞에는 들어간 만큼만, 순서대로 나간다")
            #expect(try await pair.server.read() == nil)
            await pair.client.close()
            await pair.server.close()
        }
    }
}
