import Foundation
import Network
import SwiftailBase
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// 출발 포트 표(계약 `docs/contracts/SwiftailHost.md` 동작 B1·B2·B6, 단위 시험 14).
@Suite("루프백 다리: 출발 포트 표", .timeLimit(.minutes(1)))
struct LoopbackOriginTableTests {
    private typealias Support = BridgeTestSupport

    @Test("잇는 동안에는 출발 포트로 상대 끝점과 whoIs의 신원을 찾고, 끝나면 찾지 못한다")
    func originWhileForwarding() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            let bridge = LoopbackBridge(node: node)
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))

            let origin = try #require(bridge.origin(forLoopbackSourcePort: link.peer.remotePort))
            #expect(origin.remoteEndpoint == link.server.remoteEndpoint)
            #expect(origin.remoteEndpoint.address == IPAddress("100.64.0.1"))
            #expect(origin.peer == Support.selfIdentity)

            await link.client.close()
            #expect(await link.peer.readToEnd() == .end([]))
            link.peer.connection.cancel()
            #expect(await link.finished() == nil)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil)
        }
    }

    /// 다리가 표에 적기 전에 복사를 시작하면, 서버가 첫 바이트를 받은 때 표에 없는 경우가 생긴다.
    @Test("서버가 첫 바이트를 받은 때에는 언제나 표에 있다")
    func originRecordedBeforeFirstByte() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            let bridge = LoopbackBridge(node: node)
            for round in 0..<20 {
                let pair = try await Support.connectedPair(node, port: 9_000 + UInt16(round))
                // 다리가 잇기 전에 보내 둔다. 다리는 잇자마자 그것을 루프백으로 나른다.
                try await pair.client.write([UInt8(round)])
                let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
                let peer = try await server.next()
                #expect(await peer.read() == .bytes([UInt8(round)]))
                #expect(bridge.origin(forLoopbackSourcePort: peer.remotePort) != nil, "\(round)번째")
                await pair.client.abort()
                _ = await forwarding.value
            }
        }
    }

    /// 다리가 루프백 소켓을 닫은 뒤에 지우면, 서버가 끝을 본 때 아직 표에 남아 있을 수 있다.
    @Test("서버가 연결의 끝(FIN·RST)을 본 때에는 이미 표에서 지워져 있다")
    func originForgottenBeforeClose() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            let bridge = LoopbackBridge(node: node)
            for round in 0..<20 {
                let link = try await Support.bridge(node, bridge, to: server, port: 9_000 + UInt16(round))
                try await link.client.write([1])
                #expect(await link.peer.read() == .bytes([1]))
                if round.isMultiple(of: 2) {
                    // 정상 끝: 루프백이 먼저 닫고 tailnet이 닫는다. 서버는 다리의 FIN을 본다.
                    try await link.peer.send([], final: true)
                    #expect(try await link.client.read() == nil)
                    await link.client.close()
                    #expect(await link.peer.readToEnd() == .end([]))
                } else {
                    await link.client.abort()
                    guard case .failed = await link.peer.readToEnd() else {
                        Issue.record("RST로 끝나지 않았다")
                        continue
                    }
                }
                #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) == nil, "\(round)번째")
                link.peer.connection.cancel()
                _ = await link.finished()
            }
        }
    }

    @Test("다리가 맺지 않은 루프백 연결의 출발 포트는 찾지 못한다")
    func directConnectionIsUnknown() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            let bridge = LoopbackBridge(node: node)
            let link = try await Support.bridge(node, bridge, to: server)

            let direct = NWConnection(host: .ipv4(.loopback), port: try #require(NWEndpoint.Port(rawValue: server.port)), using: .tcp)
            direct.start(queue: DispatchQueue(label: "test.direct"))
            defer { direct.cancel() }
            let stranger = try await server.next()
            #expect(stranger.remotePort != link.peer.remotePort)
            #expect(bridge.origin(forLoopbackSourcePort: stranger.remotePort) == nil)
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort) != nil)
            await link.client.abort()
            _ = await link.finished()
        }
    }

    @Test("잇기 시작할 때의 신원이 연결이 사는 동안 그대로다")
    func identityFixedAtStart() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            let bridge = LoopbackBridge(node: node)
            let link = try await Support.bridge(node, bridge, to: server)
            // 주인이 같은 채 프로필이 빠지면 whoIs는 nil이 되지만, 연결은 끊기지 않고 표의 신원도 그대로다.
            await node.apply(try Support.netmap(withProfile: false))
            #expect(await node.whoIs(link.server.remoteEndpoint.address) == nil)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            #expect(bridge.origin(forLoopbackSourcePort: link.peer.remotePort)?.peer == Support.selfIdentity)
            await link.client.abort()
            _ = await link.finished()
        }
    }
}
