import Foundation
import Network
import SwiftailBase
import SwiftailControl
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// 루프백 다리(계약 `docs/contracts/SwiftailHost.md` 동작 B, 단위 시험 13).
///
/// tailnet 쪽은 노드 하나의 자기 연결이고, 루프백 쪽은 시험 안의 평문 `NWListener`다.
@Suite("루프백 다리: 나르기와 끊김", .timeLimit(.minutes(2)))
struct LoopbackBridgeTests {
    private typealias Support = BridgeTestSupport

    private static func withBridge(
        _ netmap: Netmap? = nil,
        _ body: (TailnetNode, LoopbackBridge, PlainLoopbackServer, _ stop: @escaping @Sendable () async -> Void) async throws -> Void
    ) async throws {
        try await Support.withRunningNode(try netmap ?? Support.netmap()) { node, stop in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            try await body(node, LoopbackBridge(node: node), server, stop)
        }
    }

    // MARK: 나르기(동작 B3·B4)

    @Test("바이트가 양방향으로 온전히 간다(4MiB씩, 해시 비교)")
    func bytesFlowBothWays() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            let upstream = Support.pattern(4 << 20, seed: 1)
            let downstream = Support.pattern(4 << 20, seed: 2)

            async let sent: Void = {
                try await link.client.write(upstream)
                try await link.client.finishWriting()
            }()
            async let clientReceived = Support.readToEnd(link.client)
            async let peerReceived = link.peer.readToEnd()
            try await link.peer.send(downstream, final: true)

            try await sent
            #expect(Support.digest(try await clientReceived) == Support.digest(downstream))
            guard case .end(let received) = await peerReceived else {
                Issue.record("루프백 서버의 읽기가 깨끗한 EOF로 끝나지 않았다")
                return
            }
            #expect(Support.digest(received) == Support.digest(upstream))
            #expect(await link.finished() == nil)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil)
        }
    }

    @Test("tailnet 쪽이 쓰기를 닫으면 루프백 서버가 EOF를 보고, 그 뒤의 응답이 tailnet으로 간다")
    func tailnetHalfClose() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write(Array("request".utf8))
            try await link.client.finishWriting()
            #expect(await link.peer.readToEnd() == .end(Array("request".utf8)))

            let response = Support.pattern(300_000, seed: 3)
            try await link.peer.send(response, final: false)
            try await link.peer.send(response, final: true)
            #expect(try await Support.readToEnd(link.client) == response + response)
            #expect(await link.finished() == nil)
        }
    }

    @Test("루프백 쪽이 쓰기를 닫으면 tailnet 쪽이 EOF를 보고, 그 뒤의 요청이 루프백으로 간다")
    func loopbackHalfClose() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send(Array("hello".utf8), final: true)
            #expect(try await Support.readToEnd(link.client) == Array("hello".utf8))

            let request = Support.pattern(300_000, seed: 4)
            try await link.client.write(request)
            try await link.client.finishWriting()
            #expect(await link.peer.readToEnd() == .end(request))
            #expect(await link.finished() == nil)
        }
    }

    /// 다리가 덩어리를 받아 갈 때까지 기다리지 않으면(역압 없이 읽으면) 거는 쪽이 멈추지 않고 모두 들어간다.
    @Test("루프백 서버가 읽지 않으면 tailnet 쪽 쓰기가 멈추고, 다시 읽으면 모두 온전히 온다")
    func slowLoopbackStopsTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            let total = BackpressureProbe.attempt
            let data = Support.pattern(total, seed: 5)
            let written = Mutex(0)
            let writer = Task { () async throws in
                var offset = 0
                while offset < total {
                    let end = min(offset + 64 << 10, total)
                    try await link.client.write(Array(data[offset..<end]))
                    offset = end
                    written.withLock { $0 = offset }
                }
                try await link.client.finishWriting()
            }
            let accepted = try await BackpressureProbe.stalled { written.withLock { $0 } }
            #expect(accepted < BackpressureProbe.bound, "\(accepted)바이트가 들어갔다")

            let ended = await link.peer.readToEnd()
            guard case .end(let received) = ended else {
                Issue.record("루프백 서버의 읽기가 깨끗한 EOF로 끝나지 않았다: \(ended), 포트 \(link.peer.remotePort), 멈춘 양 \(accepted)")
                return
            }
            #expect(received.count == total)
            #expect(Support.digest(received) == Support.digest(data))
            try await writer.value
            try await link.peer.send([], final: true)
            #expect(try await link.client.read() == nil)
            await link.client.close()
            #expect(await link.finished() == nil)
        }
    }

    @Test("tailnet 쪽이 읽지 않으면 루프백 서버의 쓰기가 멈추고, 다시 읽으면 모두 온전히 온다")
    func slowTailnetStopsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            let total = BackpressureProbe.attempt
            let data = Support.pattern(total, seed: 6)
            let written = Mutex(0)
            let writer = Task {
                var offset = 0
                while offset < total {
                    let end = min(offset + 64 << 10, total)
                    try await link.peer.send(Array(data[offset..<end]), final: end == total)
                    offset = end
                    written.withLock { $0 = offset }
                }
            }
            let accepted = try await BackpressureProbe.stalled { written.withLock { $0 } }
            #expect(accepted < BackpressureProbe.bound, "\(accepted)바이트가 들어갔다")

            let received = try await Support.readToEnd(link.client)
            #expect(received.count == total)
            #expect(Support.digest(received) == Support.digest(data))
            try await writer.value
            await link.client.close()
            #expect(await link.finished() == nil)
        }
    }

    // MARK: 끊김(동작 B5, 첫 사용처 검토 결과 7)

    @Test("tailnet 쪽이 RST로 끊기면 루프백 서버의 읽기가 깨끗한 EOF가 아니라 오류로 끝난다")
    func tailnetResetResetsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1, 2, 3])
            #expect(await link.peer.read() == .bytes([1, 2, 3]))
            await link.client.abort()
            Self.expectReset(await link.peer.readToEnd())
            #expect(await link.finished() == nil)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil)
        }
    }

    @Test("주소의 주인이 바뀌어 연결이 peerRemoved로 끝나면 다리가 루프백을 RST로 끊고 표에서 지운다")
    func peerRemovedResetsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) != nil)

            await node.apply(try Support.netmap(selfAddresses: ["100.64.0.9/32"]))
            Self.expectReset(await link.peer.readToEnd())
            #expect(await link.finished() == nil)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil)
            #expect(await Support.error { try await link.client.read() } == .peerRemoved)
        }
    }

    @Test("노드가 멈추면 루프백을 오류로 끊고 돌아온다")
    func nodeStopResetsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, stop in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            await stop()
            Self.expectReset(await link.peer.readToEnd())
            #expect(await link.finished() == nil)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil)
        }
    }

    @Test("루프백 서버가 정상으로 닫으면 tailnet 쪽이 응답 뒤 EOF를 보고, 닫으면 다리가 돌아온다")
    func loopbackCloseFinishesTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send(Array("bye".utf8), final: true)
            link.peer.connection.cancel()
            #expect(try await Support.readToEnd(link.client) == Array("bye".utf8))
            await link.client.close()
            #expect(await link.finished() == nil)
        }
    }

    @Test("루프백 서버가 RST로 끊으면 tailnet 쪽이 reset으로 끊긴다")
    func loopbackResetResetsTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send([7], final: false)
            #expect(try await link.client.read() == [7])
            link.peer.connection.forceCancel()
            #expect(await Support.error { try await Support.readToEnd(link.client) } == .reset)
            #expect(await link.finished() == nil)
        }
    }

    /// 읽는 방향(루프백 → tailnet)이 FIN으로 이미 끝난 뒤 루프백이 끊기는 경우다. 쓰기 결과로만 알 수 있다.
    @Test("루프백 서버가 다 닫은 뒤 tailnet 쪽이 계속 쓰면 tailnet 쪽이 reset으로 끊긴다")
    func writesAfterLoopbackClosedResetTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send([], final: true)
            link.peer.connection.cancel()
            #expect(try await link.client.read() == nil)
            let chunk = [UInt8](repeating: 0xEE, count: 64 << 10)
            var outcome: ConnectionError?
            for _ in 0..<1_000 {
                outcome = await Support.error { try await link.client.write(chunk) }
                if outcome != nil { break }
                try await Task.sleep(for: .milliseconds(5))
            }
            #expect(outcome == .reset)
            #expect(await link.finished() == nil)
        }
    }

    @Test("forward를 부른 Task가 취소되면 두 연결을 RST로 끊고 cancelled를 던진다")
    func cancellingForwardResetsBoth() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            link.forwarding.cancel()
            #expect(await link.finished() == .cancelled)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil)
            Self.expectReset(await link.peer.readToEnd())
            #expect(await Support.error { try await link.client.read() } == .reset)
        }
    }

    // MARK: 잇기 전의 실패(동작 B1)

    @Test("듣는 쪽이 없는 포트와 포트 0은 loopbackUnavailable이고 tailnet 연결은 RST로 끊긴다")
    func noListener() async throws {
        try await Self.withBridge { node, bridge, _, _ in
            let closedPort = try await PlainLoopbackServer.unusedPort()
            for (index, port) in [closedPort, UInt16(0)].enumerated() {
                let pair = try await Support.connectedPair(node, port: 9_000 + UInt16(index))
                let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: port)
                guard case .loopbackUnavailable = await forwarding.value else {
                    Issue.record("loopbackUnavailable이 아니다: 포트 \(port)")
                    continue
                }
                #expect(await Support.error { try await pair.client.read() } == .reset)
            }
        }
    }

    @Test("신원을 찾지 못하면 unknownPeer이고 루프백으로 걸지 않으며 tailnet 연결은 RST로 끊긴다")
    func unknownPeer() async throws {
        try await Self.withBridge(try Support.netmap(withProfile: false)) { node, bridge, server, _ in
            let pair = try await Support.connectedPair(node)
            #expect(await node.whoIs(pair.server.remoteEndpoint.address) == nil)
            #expect(await Support.forward(pair.server, with: bridge, toLoopbackPort: server.port).value == .unknownPeer)
            #expect(await Support.error { try await pair.client.read() } == .reset)
            try await Task.sleep(for: .milliseconds(200))
            #expect(server.acceptedCount == 0)
        }
    }

    @Test("잇는 연결이 상한이면 limitReached이고 tailnet 연결은 RST로 끊긴다. 하나가 끝나면 다시 받는다")
    func limitReached() async throws {
        #expect(LoopbackBridge(node: try TailnetNode(configuration: Self.unusedConfiguration())).connectionLimit == 256)
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            let bridge = LoopbackBridge(node: node, connectionLimit: 2)
            let first = try await Support.bridge(node, bridge, to: server, port: 9_000)
            let second = try await Support.bridge(node, bridge, to: server, port: 9_001)

            let third = try await Support.connectedPair(node, port: 9_002)
            #expect(await Support.forward(third.server, with: bridge, toLoopbackPort: server.port).value == .limitReached)
            #expect(await Support.error { try await third.client.read() } == .reset)
            #expect(server.acceptedCount == 2)

            await first.client.abort()
            #expect(await first.finished() == nil)
            let fourth = try await Support.bridge(node, bridge, to: server, port: 9_003)
            await second.client.abort()
            await fourth.client.abort()
            #expect(await second.finished() == nil)
            #expect(await fourth.finished() == nil)
        }
    }

    // MARK: 도우미

    private static func expectReset(_ received: PeerConnection.Received, sourceLocation: SourceLocation = #_sourceLocation) {
        guard case .failed(_, let error) = received else {
            Issue.record("루프백 서버의 읽기가 오류로 끝나지 않았다: \(received)", sourceLocation: sourceLocation)
            return
        }
        #expect(error.contains("Connection reset"), "\(error)", sourceLocation: sourceLocation)
    }

    private static func unusedConfiguration() throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
    }
}

/// 역압 시험의 기준.
///
/// 다리가 쥐는 것은 방향당 64KiB이고, 그 밖에 들어갈 수 있는 곳은 tailnet 연결의 보내는 버퍼와 받는 창(256KiB씩),
/// `NWConnection`과 커널 루프백 TCP의 버퍼다. 역압이 없으면 보낸 것이 모두 들어간다. 2026-11 macOS에서 멈춘 양은
/// 1.2~1.7MiB였다.
enum BackpressureProbe {
    /// 보내려는 양. 멈추지 않으면 모두 들어간다.
    static let attempt = 16 << 20
    /// 멈췄을 때 들어간 양의 위쪽 끝.
    static let bound = 8 << 20

    /// `progress`가 300ms 동안 그대로이면 그 값을 돌려준다(쓰기가 멈췄다). 20초 안에 멈추지 않으면 그때의 값이다.
    static func stalled(_ progress: () -> Int) async throws -> Int {
        var last = -1
        var stableSince = ContinuousClock.now
        let deadline = ContinuousClock.now + .seconds(20)
        while ContinuousClock.now < deadline {
            let current = progress()
            if current != last {
                last = current
                stableSince = .now
            } else if ContinuousClock.now - stableSince >= .milliseconds(300) {
                return current
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        return progress()
    }
}
