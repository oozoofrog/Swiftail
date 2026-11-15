import Foundation
import Network
import SwiftailBase
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// 상대 찾기(계약 `docs/contracts/SwiftailHost.md` 동작 B1·B2·B6, 단위 시험 14).
@Suite("루프백 다리: 상대 찾기", .timeLimit(.minutes(1)))
struct LoopbackOriginTableTests {
    private typealias Support = BridgeTestSupport

    @Test("준비된 연결로 물으면 상대 끝점과 whoIs의 신원을 한 번 얻고, 두 번째는 nil이다")
    func originAnsweredOnce() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)

            let origin = try #require(bridge.origin(of: link.peer.connection))
            #expect(origin.remoteEndpoint == link.server.remoteEndpoint)
            #expect(origin.remoteEndpoint.address == IPAddress("100.64.0.1"))
            #expect(origin.peer == Support.selfIdentity)
            #expect(bridge.origin(of: link.peer.connection) == nil)

            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            await link.client.close()
            #expect(await link.peer.readToEnd() == .end([]))
            link.peer.connection.cancel()
            #expect(await link.finished() == nil)
        }
    }

    /// 허가는 framer가 연결을 준비 상태로 두기 전에 적힌다. 서버는 첫 바이트를 기다리지 않고 `.ready`에서 물어도 된다.
    @Test("서버가 .ready를 본 때에는 첫 바이트를 받기 전이라도 언제나 답이 있다")
    func originAnsweredAtReady() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            for round in 0..<20 {
                let pair = try await Support.connectedPair(node, port: 9_000 + UInt16(round))
                // 다리가 잇기 전에 보내 둔다. 다리는 토큰 바로 뒤에 그것을 나른다.
                try await pair.client.write([UInt8(round)])
                let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
                let peer = try await server.next()
                #expect(bridge.origin(of: peer.connection) != nil, "\(round)번째")
                #expect(await peer.read() == .bytes([UInt8(round)]))
                await pair.client.abort()
                _ = await forwarding.value
            }
        }
    }

    /// 루프백을 끝내는 길(정상 닫기, tailnet의 RST, 취소)마다 닫기 직전의 표를 본다. 거두기 전에 닫는 구현을 잡는다.
    /// 프로토콜이 없는 리스너를 써서 토큰이 소비되지 않고 남게 한다.
    @Test("루프백 연결을 닫는 순간에는 그 연결의 토큰이 이미 거둬져 있고, 토큰은 다른 바이트보다 먼저 갔다")
    func tokenWithdrawnBeforeLoopbackEnds() async throws {
        let ends = Mutex<[(LoopbackAdmissionTable.Key, LoopbackAdmissionTable.Snapshot)]>([])
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node, connectionLimit: 256) { key, snapshot in
                ends.withLock { $0.append((key, snapshot)) }
            }
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            for (round, ending) in ["close", "reset", "cancel"].enumerated() {
                let link = try await Support.bridge(node, bridge, to: server, port: 9_000 + UInt16(round))
                try await link.client.write([0xAB])
                var received: [UInt8] = []
                while received.count < LoopbackAdmissionTable.tokenLength + 1, case .bytes(let bytes) = await link.peer.read() {
                    received += bytes
                }
                #expect(received.count == LoopbackAdmissionTable.tokenLength + 1, "\(ending)")
                #expect(received.last == 0xAB, "\(ending)")
                #expect(bridge.admission.snapshot.expected.contains(
                    .init(sourcePort: link.peer.remotePort, listenerPort: server.port)), "\(ending)")
                switch ending {
                case "close":
                    try await link.peer.send([], final: true)
                    #expect(try await link.client.read() == nil)
                    await link.client.close()
                    #expect(await link.peer.readToEnd() == .end([]))
                    #expect(await link.finished() == nil)
                case "reset":
                    await link.client.abort()
                    #expect(await link.finished() == nil)
                default:
                    link.forwarding.cancel()
                    #expect(await link.finished() == .cancelled)
                }
                let recorded = ends.withLock { $0 }
                #expect(recorded.count == round + 1, "\(ending)")
                let (key, snapshot) = try #require(recorded.last)
                #expect(key == .init(sourcePort: link.peer.remotePort, listenerPort: server.port), "\(ending)")
                #expect(!snapshot.expected.contains(key), "\(ending): 닫기 전에 거두지 않았다")
                link.peer.connection.cancel()
            }
        }
    }

    /// 다리가 허가를 지우면, 같은 4-튜플을 다시 쓰는 다리의 새 연결이 그 자리에 들어가 늦게 온 조회가 다른 상대를 얻을 수 있다.
    @Test("서버가 묻지 않은 허가는 다리가 루프백을 닫아도 남고, 같은 열쇠로 새 토큰을 적지 못한다")
    func unclaimedAdmissionOutlivesLoopback() async throws {
        let ends = Mutex<[LoopbackAdmissionTable.Snapshot]>([])
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node, connectionLimit: 256) { _, snapshot in
                ends.withLock { $0.append(snapshot) }
            }
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            let key = LoopbackAdmissionTable.Key(sourcePort: link.peer.remotePort, listenerPort: server.port)
            await link.client.abort()
            #expect(await link.finished() == nil)
            #expect(try #require(ends.withLock { $0.last }).admitted.contains(key))
            #expect(bridge.admission.snapshot.admitted.contains(key))

            let origin = LoopbackBridge.Origin(remoteEndpoint: link.server.remoteEndpoint, peer: Support.selfIdentity)
            #expect(!bridge.admission.expect(LoopbackAdmissionTable.makeToken(), for: key, origin: origin))
            link.peer.connection.cancel()
        }
    }

    @Test("잇기 시작할 때의 신원이 연결이 사는 동안 그대로다")
    func identityFixedAtStart() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            // 주인이 같은 채 프로필이 빠지면 whoIs는 nil이 되지만, 연결은 끊기지 않고 신원도 그대로다.
            await node.apply(try Support.netmap(withProfile: false))
            #expect(await node.whoIs(link.server.remoteEndpoint.address) == nil)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            #expect(bridge.origin(of: link.peer.connection)?.peer == Support.selfIdentity)
            await link.client.abort()
            _ = await link.finished()
        }
    }
}
