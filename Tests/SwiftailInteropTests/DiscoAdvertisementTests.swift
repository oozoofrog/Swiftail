import Foundation
import Swiftail
import SwiftailBase
import SwiftailMagicsock
import Testing

// Interop gate for "TSMP disco Key Advertisement" in `docs/contracts/SwiftailMagicsock.md`. Change one side's disco key by restarting its node,
// suppress netmap updates to the other side (using `injectMapResponse` to suppress automatic maps), and check whether a direct path is established. The side with updates blocked can learn the new
// disco key only from the TSMP advertisement sent inside the tunnel when the WireGuard session is established.
//
// Most of the time is spent establishing the WireGuard session before the advertisement. The side that has been up longer trusts the pre-restart address for
// 6.5 seconds after the last Pong and sends handshake responses only to that dead address. The restarted side retries every 5 seconds (like Go), so
// the session comes up in about 10 seconds and both sides go direct within 0.1 seconds of receiving the advertisement. The 20-second timeout allows one more retry.

@Suite("TSMP disco key advertisement gate", .enabled(if: tailnetBinary != nil,
    "Skipping the TSMP advertisement gate tests because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(4)))
struct DiscoAdvertisementTests {
    @Test("① A direct path is established after restarting the Swift node with the Go peer's netmap updates blocked (Go uses Swiftail's advertisement)")
    func goUsesSwiftAdvertisement() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "swiftail-tsmp-\(UUID().uuidString)")
        let tool = GoTailnet(temporaryDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        var run: Task<Void, any Error>?
        do {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let ready = try await tool.start()
            let goPeer = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer"))
            let configuration = NodeConfiguration(stateDirectory: root.appending(path: "swift"), hostname: "rd-mac-1a2b3c4d",
                                                  controlURL: try #require(ready.controlURL))
            try FileManager.default.createDirectory(at: configuration.stateDirectory, withIntermediateDirectories: true)

            let first = try TailnetNode(configuration: configuration, device: .memory())
            run = Task { try await first.run() }
            let addresses = try await running(first)
            let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let local = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) })
            let localPeer = GatePeer(key: local.nodeKey, addresses: addresses)
            let goName = try #require(nodes.first { $0.nodeKey == goPeer.key }?.name)
            let before = try await directPath(tool, swift: first, local: localPeer, go: goPeer, goName: goName,
                                              stage: "① Setup: both sides direct with the original Swift node", from: .now)

            // Suppress automatic maps to the Go peer. An empty response does not change Go's netmap.
            try await tool.inject(MapInjection(), into: goPeer.key)
            run?.cancel()
            _ = await run?.result
            run = nil

            // Reuse the state directory. The node key stays the same, and the disco key and UDP port are new. Go knows only the old disco key.
            let second = try TailnetNode(configuration: configuration, device: .memory())
            run = Task { try await second.run() }
            #expect(try await running(second) == addresses)
            let restarted = ContinuousClock.now
            await tool.checkpoint("① Swift restarted, Go maps suppressed")
            let after = try await directPath(tool, swift: second, local: localPeer, go: goPeer, goName: goName,
                                             stage: "① Both sides direct with restarted Swift (Go maps suppressed)", from: restarted,
                                             notGoCurAddr: before.goCurAddr)
            #expect(after.goCurAddr != before.goCurAddr)
            run?.cancel()
            _ = await run?.result
            await tool.stop()
        } catch {
            run?.cancel()
            _ = await run?.result
            await tool.stop()
            throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
        }
    }

    @Test("② A direct path is established after restarting the Go peer with the Swift node's netmap updates blocked (Swiftail uses Go's advertisement)")
    func swiftUsesGoAdvertisement() async throws {
        try await withGate(direct: false) { gate in
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let goName = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
            let before = try await directPath(gate.tool, swift: gate.node, local: gate.local, go: gate.peer, goName: goName,
                                              stage: "② Setup: both sides direct", from: gate.runningAt)

            // Suppress automatic maps to the Swift node. The marker address confirms suppression.
            try await gate.inject(MapInjection(), marker: 1)
            let event = try await gate.tool.command(.init(cmd: "restartPeer", name: "go-peer-a"), expecting: "peer")
            #expect(event.nodeKey == gate.peer.key, "The restarted Go peer keeps the same node key")
            let restarted = ContinuousClock.now
            await gate.tool.checkpoint("② Go peer restarted, Swift maps suppressed")
            // The new Go instance has no session, so let Go send first to initiate the handshake.
            let after = try await directPath(gate.tool, swift: gate.node, local: gate.local, go: gate.peer, goName: goName,
                                             stage: "② Both sides direct with restarted Go (Swift maps suppressed)", from: restarted,
                                             notSwiftPath: before.swiftPath, goSends: true)
            #expect(after.swiftPath != before.swiftPath)
        }
    }

    @Test("Swift ↔ Swift: a direct path is established after restarting one side with the other side's netmap updates blocked")
    func swiftToSwift() async throws {
        try await withGate(direct: false) { gate in
            let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-tsmp-b-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: directory) }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let configuration = NodeConfiguration(stateDirectory: directory, hostname: "rd-mac-5e6f7a8b",
                                                  controlURL: try #require(gate.controlURL))
            var run: Task<Void, any Error>?
            do {
                let first = try TailnetNode(configuration: configuration, device: .memory())
                run = Task { try await first.run() }
                let addresses = try await running(first)
                let b = GatePeer(key: "", addresses: addresses)
                let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
                let aName = try #require(nodes.first { $0.nodeKey == gate.local.key }?.name)
                let bName = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) }?.name)
                let before = try await swiftDirect(gate.node, first, a: gate.local, b: b, aName: aName, bName: bName,
                                                   stage: "Swift ↔ Swift setup: both sides direct", from: .now)

                // Suppress automatic maps to A (the longer-running side) and restart B. A knows only B's old disco key and endpoints.
                try await gate.inject(MapInjection(), marker: 2)
                run?.cancel()
                _ = await run?.result
                run = nil
                let second = try TailnetNode(configuration: configuration, device: .memory())
                run = Task { try await second.run() }
                #expect(try await running(second) == addresses)
                let restarted = ContinuousClock.now
                await gate.tool.checkpoint("Swift ↔ Swift: B restarted, A maps suppressed")
                _ = try await swiftDirect(gate.node, second, a: gate.local, b: b, aName: aName, bName: bName,
                                          stage: "Swift ↔ Swift: both sides direct with restarted B (A maps suppressed)", from: restarted,
                                          notAPath: before)
                run?.cancel()
                _ = await run?.result
            } catch {
                run?.cancel()
                _ = await run?.result
                throw error
            }
        }
    }
}

/// Values observed when both sides are direct.
private struct DirectSnapshot {
    let swiftPath: PeerPath
    let goCurAddr: String
}

/// Sends UDP and waits up to 20 seconds for both Swift's path and Go's `curAddr` to become direct. Values equal to `notSwiftPath` or `notGoCurAddr`
/// (the paths before restarting) are excluded.
private func directPath(_ tool: GoTailnet, swift node: TailnetNode, local: GatePeer, go peer: GatePeer, goName: String,
                        stage: String, from start: ContinuousClock.Instant,
                        notSwiftPath: PeerPath? = nil, notGoCurAddr: String? = nil, goSends: Bool = false) async throws -> DirectSnapshot {
    let deadline = start + .seconds(20)
    let probe = Packets.udp(from: try local.address(), port: 43200, to: try peer.address(), payload: [0x54, 0x53])
    // If Swift was restarted, a burst of pre-session data can push its own TSMP advertisement out of the DERP queue.
    let swiftSendInterval: Duration = notGoCurAddr == nil ? .milliseconds(200) : .seconds(1)
    var nextSwiftSend = ContinuousClock.now
    var nextGoSend = nextSwiftSend
    while ContinuousClock.now <= deadline {
        if ContinuousClock.now >= nextSwiftSend {
            await node.send(probe)
            nextSwiftSend = .now + swiftSendInterval
        }
        if goSends, ContinuousClock.now >= nextGoSend {
            _ = try await tool.command(.init(cmd: "peerSend", name: "go-peer-a", to: try local.address().description,
                                             port: 43201, proto: "udp", payload: "5453"), expecting: "peerSend")
            nextGoSend += .seconds(1)
        }
        let status = try await tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
        let curAddr = status.peers?.first { $0.nodeKey == local.key }?.curAddr ?? ""
        if let path = await node.path(toPeerNamed: goName), case .direct = path, path != notSwiftPath,
           !curAddr.isEmpty, curAddr != notGoCurAddr {
            report(stage, since: start)
            return DirectSnapshot(swiftPath: path, goCurAddr: curAddr)
        }
        try await Task.sleep(for: .milliseconds(200))
    }
    let path = await node.path(toPeerNamed: goName)
    throw GateFailure("\(stage): both sides did not become direct within 20 seconds (Swift \(path.map { "\($0)" } ?? "nil"), same as pre-restart path: \(path == notSwiftPath))")
}

/// Waits up to 20 seconds total for both sides to go direct after B initiates the WireGuard session. Returns B's new direct path as seen by A.
///
/// If both sides initiate, their initiations can cancel each other out. Once B's UDP arrives at A, the session is established and A sends too.
/// A clears its send history when it learns the new disco key, so it must send again to start direct path discovery.
private func swiftDirect(_ a: TailnetNode, _ b: TailnetNode, a aPeer: GatePeer, b bPeer: GatePeer, aName: String, bName: String,
                         stage: String, from start: ContinuousClock.Instant, notAPath: PeerPath? = nil) async throws -> PeerPath {
    let deadline = start + .seconds(20)
    let aIP = try aPeer.address(), bIP = try bPeer.address()
    // Do not count pre-restart packets still in A's receive stream as evidence of this session.
    let payload: [UInt8] = notAPath == nil ? [1] : [2]
    let probe = Packets.udp(from: bIP, port: 43211, to: aIP, destinationPort: 43210, payload: payload)
    let received = try await withThrowingTaskGroup(of: Bool.self) { group in
        defer { group.cancelAll() }
        group.addTask {
            for await bytes in a.inboundPackets {
                if let packet = try? ReceivedPacket(bytes), packet.proto == 17,
                   packet.source == bIP, packet.destination == aIP, packet.sourcePort == 43211,
                   packet.destinationPort == 43210, packet.payload == payload { return true }
            }
            return false
        }
        group.addTask {
            // When releasing pre-session data at once, keep the batch containing the TSMP advertisement within DERP's 32-entry send queue.
            while ContinuousClock.now <= deadline {
                await b.send(probe)
                try await Task.sleep(for: .seconds(1))
            }
            return false
        }
        return try await group.next() ?? false
    }
    if received { report("\(stage): A received B's first UDP packet", since: start) }
    let reply = Packets.udp(from: aIP, port: 43210, to: bIP, destinationPort: 43211, payload: payload)
    while received, ContinuousClock.now <= deadline {
        await a.send(reply)
        await b.send(probe)
        if let aPath = await a.path(toPeerNamed: bName), case .direct = aPath, aPath != notAPath,
           case .direct = await b.path(toPeerNamed: aName) {
            report(stage, since: start)
            return aPath
        }
        try await Task.sleep(for: .milliseconds(200))
    }
    let aPath = await a.path(toPeerNamed: bName), bPath = await b.path(toPeerNamed: aName)
    throw GateFailure("\(stage): both sides did not become direct within 20 seconds (A \(aPath.map { "\($0)" } ?? "nil"), B \(bPath.map { "\($0)" } ?? "nil"), A same as pre-restart path: \(aPath == notAPath), received B's UDP: \(received))")
}

private func report(_ stage: String, since start: ContinuousClock.Instant) {
    let line = "[TSMP \(Date().ISO8601Format())] \(stage): +\(start.duration(to: .now))\n"
    try? FileHandle.standardOutput.write(contentsOf: Data(line.utf8))
}
