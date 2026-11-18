// The node's tailnet lock surface: `NodeStatus.tailnetLock` and `NodeEvent.tailnetLockChanged`.
// Contract `docs/contracts/SwiftailTailnetLock.md` §2 `Swiftail`, decision L4, the four cases in first adopter review F2, and §7 unit test 22.
//
// Fills `Netmap.tailnetLock` as if `ControlClient` had filtered the netmap and included the lock state, then passes it to `apply`.

import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

@Suite("Node tailnet lock", .timeLimit(.minutes(1)))
struct NodeTailnetLockTests {
    static let head = String(repeating: "A", count: 52)
    static let request = TailnetLockStatus.SigningRequest(
        nodeKey: NodeTestSupport.nodeKey(0x11),
        lockKey: "tlpub:" + [UInt8](repeating: 0x33, count: 32).hex
    )
    /// Enabled and awaiting a signature.
    static let locked = TailnetLockStatus(mode: .enforcing, head: head, filteredPeerCount: 1, signingRequest: request)
    /// Enabled and this node is signed.
    static let signed = TailnetLockStatus(mode: .enforcing, head: head)
    /// Unverified: one peer reported by the server was not admitted.
    static let unverified = TailnetLockStatus(mode: .unverified, filteredPeerCount: 1)

    static func netmap(_ lock: TailnetLockStatus, peerAddress: String? = nil) throws -> Netmap {
        var netmap = try NodeTestSupport.netmap(peerAddress: peerAddress)
        netmap.tailnetLock = lock
        return netmap
    }

    /// Receives one event and returns `status` at the time of receipt. Call after ending the stream to avoid waiting if there are too few events.
    static func next(
        _ events: inout AsyncStream<NodeEvent>.Iterator, of node: TailnetNode
    ) async throws -> (NodeEvent, NodeStatus) {
        let event = try #require(await events.next())
        return (event, await node.status)
    }

    /// Reads all remaining events from a finished stream.
    static func remaining(_ events: inout AsyncStream<NodeEvent>.Iterator) async -> [NodeEvent] {
        var rest: [NodeEvent] = []
        while let event = await events.next() { rest.append(event) }
        return rest
    }

    @Test("Before the netmap arrives the state is .disabled, and a netmap without a lock emits no lock event")
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

    @Test("F2 1·3: A locked node's lock event precedes .running, and status contains the signing request when either event is received")
    func lockedBeforeRunning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        var events = node.events.makeAsyncIterator()
        // If home DERP is already up, the first netmap alone yields `.running`. Both events come from the same netmap.
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
        // The two values to paste verbatim into `tailscale lock sign` on the signing device.
        let request = try #require(secondStatus.tailnetLock.signingRequest)
        #expect(request.nodeKey.hasPrefix("nodekey:") && request.nodeKey.count == 8 + 64)
        #expect(request.lockKey.hasPrefix("tlpub:") && request.lockKey.count == 6 + 64)
        #expect(await Self.remaining(&events) == [.statusChanged])
    }

    @Test("F2 4: The netmap after signing unlocks the node without a restart. One lock event arrives and signingRequest is nil")
    func unlocksAfterSigning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(Self.locked))
        #expect(await node.status.tailnetLock.isLockedOut)

        // The netmap after the signing device signs: this node is unlocked and the filtered peer is admitted.
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

    @Test("A netmap changing only the lock state (same peers) emits only the lock event and statusChanged. Repeating the same lock state still yields only one lock event")
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

    @Test("status.tailnetLock tracks the netmap and emits an event only on a change (including a return to .disabled)")
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

    @Test("F2 2: A single status distinguishes four cases", arguments: [
        (TailnetLockStatus(), TailnetLockStatus.Mode.disabled, false),
        (signed, .enforcing, false),
        (locked, .enforcing, true),
        (unverified, .unverified, false),
    ])
    // Qualify the module name. In a file where both the alias from `Swiftail` and the original name from `SwiftailControl` are visible,
    // `(TailnetLockStatus).self` generated by `@Test` is ambiguous (`ReexportedTypes.swift`).
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

    @Test("The node reaches .running even in .unverified (no peers). It simply has no peers")
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

    @Test("After run() ends, status.tailnetLock still reflects the last netmap like the other fields, and a restarted node begins at .disabled")
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
    /// Updates the state machine as if the home DERP connection came up (`.running` after the netmap).
    func markConnectedForTesting() {
        announce(stateMachine.connected())
    }

    /// Finishes the event stream so all remaining events can be read.
    func finishEventsForTesting() {
        eventQueue.finish()
    }
}
