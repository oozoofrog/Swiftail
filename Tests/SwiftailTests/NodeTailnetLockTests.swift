// 노드의 tailnet lock 표면: `NodeStatus.tailnetLock`과 `NodeEvent.tailnetLockChanged`.
// 계약 `docs/contracts/SwiftailTailnetLock.md` 2절 `Swiftail`, 결정 L4, 첫 사용처 검토 F2의 넷, 7절 단위 시험 22.
//
// netmap은 `ControlClient`가 거르고 lock 모습을 실어 낸 것처럼 `Netmap.tailnetLock`을 채워 `apply`에 넣는다.

import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

@Suite("노드: tailnet lock", .timeLimit(.minutes(1)))
struct NodeTailnetLockTests {
    static let head = String(repeating: "A", count: 52)
    static let request = TailnetLockStatus.SigningRequest(
        nodeKey: NodeTestSupport.nodeKey(0x11),
        lockKey: "tlpub:" + [UInt8](repeating: 0x33, count: 32).hex
    )
    /// 켜짐·서명을 기다림.
    static let locked = TailnetLockStatus(mode: .enforcing, head: head, filteredPeerCount: 1, signingRequest: request)
    /// 켜짐·이 노드 서명됨.
    static let signed = TailnetLockStatus(mode: .enforcing, head: head)
    /// 확인하지 못함: 서버가 알린 피어 하나를 올리지 않았다.
    static let unverified = TailnetLockStatus(mode: .unverified, filteredPeerCount: 1)

    static func netmap(_ lock: TailnetLockStatus, peerAddress: String? = nil) throws -> Netmap {
        var netmap = try NodeTestSupport.netmap(peerAddress: peerAddress)
        netmap.tailnetLock = lock
        return netmap
    }

    /// 사건 하나를 받고, 받은 순간의 `status`를 함께 돌려준다. 사건이 모자라면 기다리지 않도록 흐름을 끝낸 뒤 부른다.
    static func next(
        _ events: inout AsyncStream<NodeEvent>.Iterator, of node: TailnetNode
    ) async throws -> (NodeEvent, NodeStatus) {
        let event = try #require(await events.next())
        return (event, await node.status)
    }

    /// 끝낸 흐름에 남은 사건을 모두 읽는다.
    static func remaining(_ events: inout AsyncStream<NodeEvent>.Iterator) async -> [NodeEvent] {
        var rest: [NodeEvent] = []
        while let event = await events.next() { rest.append(event) }
        return rest
    }

    @Test("netmap 전에는 .disabled이고, lock 없는 netmap은 lock 사건을 내지 않는다")
    func disabledByDefault() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        #expect(await node.status.tailnetLock == TailnetLockStatus())
        #expect(await node.status.tailnetLock.mode == .disabled)

        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(TailnetLockStatus()))
        await node.apply(try Self.netmap(TailnetLockStatus()))
        await node.finishEventsForTesting()
        #expect(await NodeTestSupport.drain(node.events) == [.stateChanged(.running), .statusChanged])
        #expect(await node.status.tailnetLock.mode == .disabled)
    }

    @Test("F2 1·3: 잠긴 노드의 lock 사건은 .running보다 먼저이고, 어느 사건을 받을 때든 status에 서명 요청이 있다")
    func lockedBeforeRunning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        var events = node.events.makeAsyncIterator()
        // 홈 DERP가 먼저 서 있으면 첫 netmap 하나로 `.running`이 된다: 두 사건이 같은 netmap에서 나온다.
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(Self.locked))
        await node.finishEventsForTesting()

        let (first, firstStatus) = try await Self.next(&events, of: node)
        let (second, secondStatus) = try await Self.next(&events, of: node)
        #expect([first, second] == [.tailnetLockChanged(Self.locked), .stateChanged(.running)])
        for status in [firstStatus, secondStatus] {
            #expect(status.tailnetLock == Self.locked)
            #expect(status.tailnetLock.isLockedOut)
        }
        #expect(secondStatus.state == .running)
        // 서명 기기의 `tailscale lock sign`에 그대로 붙여 넣는 두 값.
        let request = try #require(secondStatus.tailnetLock.signingRequest)
        #expect(request.nodeKey.hasPrefix("nodekey:") && request.nodeKey.count == 8 + 64)
        #expect(request.lockKey.hasPrefix("tlpub:") && request.lockKey.count == 6 + 64)
        #expect(await Self.remaining(&events) == [.statusChanged])
    }

    @Test("F2 4: 서명 뒤의 netmap에서 다시 시작 없이 풀린다: lock 사건 하나만 오고 signingRequest가 nil이다")
    func unlocksAfterSigning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(Self.locked))
        #expect(await node.status.tailnetLock.isLockedOut)

        // 서명 기기가 서명한 뒤의 netmap: 이 노드가 풀리고 걸렀던 피어가 올라온다.
        await node.apply(try Self.netmap(Self.signed, peerAddress: "100.64.0.2/32"))
        let status = await node.status
        #expect(status.tailnetLock == Self.signed)
        #expect(status.tailnetLock.signingRequest == nil)
        #expect(!status.tailnetLock.isLockedOut)
        #expect(status.state == .running)
        #expect(status.peerCount == 1)
        await node.finishEventsForTesting()
        #expect(await NodeTestSupport.drain(node.events) == [
            .tailnetLockChanged(Self.locked), .stateChanged(.running), .tailnetLockChanged(Self.signed), .statusChanged,
        ])
    }

    @Test("lock 모습만 바뀐 netmap(피어 그대로)은 lock 사건과 statusChanged만 내고, 같은 lock 모습이 거듭 와도 사건은 한 번이다")
    func onlyLockChanges() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.markConnectedForTesting()
        let peer = "100.64.0.2/32"
        await node.apply(try Self.netmap(Self.signed, peerAddress: peer))
        await node.apply(try Self.netmap(Self.signed, peerAddress: peer))
        var oneFiltered = Self.signed
        oneFiltered.filteredPeerCount = 1
        await node.apply(try Self.netmap(oneFiltered, peerAddress: peer))
        await node.apply(try Self.netmap(oneFiltered, peerAddress: peer))
        await node.apply(try Self.netmap(oneFiltered, peerAddress: peer))
        await node.finishEventsForTesting()

        #expect(await NodeTestSupport.drain(node.events) == [
            .tailnetLockChanged(Self.signed), .stateChanged(.running), .tailnetLockChanged(oneFiltered), .statusChanged,
        ])
        #expect(await node.status.tailnetLock == oneFiltered)
        #expect(await node.status.peerCount == 1)
    }

    @Test("status.tailnetLock이 netmap을 따라가고, 바뀔 때만 사건이 나온다(.disabled로 돌아가는 것 포함)")
    func followsNetmap() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.markConnectedForTesting()
        let sequence = [Self.signed, Self.locked, Self.locked, Self.signed, TailnetLockStatus(), Self.unverified]
        for lock in sequence {
            await node.apply(try Self.netmap(lock))
            #expect(await node.status.tailnetLock == lock)
        }
        await node.finishEventsForTesting()

        #expect(await NodeTestSupport.drain(node.events) == [
            .tailnetLockChanged(Self.signed), .stateChanged(.running),
            .tailnetLockChanged(Self.locked), .tailnetLockChanged(Self.signed),
            .tailnetLockChanged(TailnetLockStatus()), .tailnetLockChanged(Self.unverified), .statusChanged,
        ])
    }

    @Test("F2 2: status 하나로 네 경우를 가른다", arguments: [
        (TailnetLockStatus(), TailnetLockStatus.Mode.disabled, false),
        (signed, .enforcing, false),
        (locked, .enforcing, true),
        (unverified, .unverified, false),
    ])
    // 모듈 이름을 붙인다. `Swiftail`의 별명과 `SwiftailControl`의 원래 이름이 함께 보이는 파일에서는 `@Test`가 만드는
    // `(TailnetLockStatus).self`가 모호하다(`ReexportedTypes.swift`).
    func fourCases(
        lock: SwiftailControl.TailnetLockStatus, mode: SwiftailControl.TailnetLockStatus.Mode, waitsForSignature: Bool
    ) async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(lock))
        let status = await node.status
        #expect(status.state == .running)
        #expect(status.tailnetLock.mode == mode)
        #expect((status.tailnetLock.signingRequest != nil) == waitsForSignature)
        #expect(status.tailnetLock.isLockedOut == waitsForSignature)
    }

    @Test(".unverified(피어 없음)에서도 노드는 .running까지 간다. 피어가 없을 뿐이다")
    func unverifiedRuns() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(Self.unverified))
        await node.finishEventsForTesting()

        #expect(await NodeTestSupport.drain(node.events) == [
            .tailnetLockChanged(Self.unverified), .stateChanged(.running), .statusChanged,
        ])
        let status = await node.status
        #expect(status.state == .running)
        #expect(status.peerCount == 0)
        #expect(status.tailnetLock.filteredPeerCount == 1)
        #expect(status.tailnetLock.signingRequest == nil)
    }

    @Test("run()이 끝나도 status.tailnetLock은 다른 필드처럼 마지막 netmap의 것이고, 다시 시작한 노드는 .disabled부터다")
    func afterRun() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let configuration = try NodeTestSupport.configuration(stateDirectory: directory)
            let node = try TailnetNode(configuration: configuration)
            await node.apply(try Self.netmap(Self.locked))
            let running = Task { try await node.run() }
            running.cancel()
            _ = await running.result
            let status = await node.status
            #expect(status.tailnetLock == Self.locked)
            #expect(!status.addresses.isEmpty)

            let restarted = try TailnetNode(configuration: configuration)
            #expect(await restarted.status.tailnetLock == TailnetLockStatus())
        }
    }
}

private extension TailnetNode {
    /// 홈 DERP 연결이 선 것처럼 상태 기계에 넣는다(netmap 뒤면 `.running`).
    func markConnectedForTesting() {
        announce(stateMachine.connected())
    }

    /// 사건 흐름을 끝내, 남은 사건을 끝까지 읽을 수 있게 한다.
    func finishEventsForTesting() {
        eventQueue.finish()
    }
}
