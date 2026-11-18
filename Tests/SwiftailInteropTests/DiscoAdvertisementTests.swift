import Foundation
import Swiftail
import SwiftailBase
import SwiftailMagicsock
import Testing

// `docs/contracts/SwiftailMagicsock.md` "TSMP disco 키 광고"의 상호 운용 관문. 한쪽의 disco 키를 바꾸고(노드를 다시 띄운다)
// 다른 쪽에게 가는 netmap 갱신을 막은 채(`injectMapResponse`의 자동 맵 억제) 직접 경로가 서는지 본다. 막힌 쪽이 새
// disco 키를 알 길은 WireGuard 세션이 설 때 터널 안으로 온 TSMP 광고뿐이다.
//
// 걸리는 시간의 대부분은 광고 전의 WireGuard 세션 수립이다. 오래 떠 있는 쪽은 다시 띄우기 전 주소를 마지막 Pong 뒤
// 6.5초 동안 믿어 핸드셰이크 응답을 그 죽은 주소로만 보내고, 다시 띄운 쪽은 5초마다 다시 시도한다(Go와 같다). 그래서
// 약 10초에 세션이 서고, 광고를 받은 뒤에는 0.1초 안에 양쪽이 직접이 된다. 제한은 재시도 한 번을 더 허용한 20초다.

@Suite("TSMP disco 키 광고 관문", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 TSMP 광고 관문 시험을 건너뜁니다"), .serialized, .timeLimit(.minutes(4)))
struct DiscoAdvertisementTests {
    @Test("① Swift 노드를 다시 띄우고 Go 피어의 netmap 갱신을 막아도 직접 경로가 선다(Go가 Swiftail의 광고를 쓴다)")
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
                                              stage: "① 준비: 처음 띄운 Swift와 양쪽 직접", from: .now)

            // Go 피어에게 가는 자동 맵을 막는다. 빈 응답은 Go의 netmap을 바꾸지 않는다.
            try await tool.inject(MapInjection(), into: goPeer.key)
            run?.cancel()
            _ = await run?.result
            run = nil

            // 같은 상태 폴더: node 키는 그대로, disco 키와 UDP 포트는 새것이다. Go는 옛 disco 키만 안다.
            let second = try TailnetNode(configuration: configuration, device: .memory())
            run = Task { try await second.run() }
            #expect(try await running(second) == addresses)
            let restarted = ContinuousClock.now
            await tool.checkpoint("①: Swift 다시 띄움, Go 맵 억제 중")
            let after = try await directPath(tool, swift: second, local: localPeer, go: goPeer, goName: goName,
                                             stage: "①: 다시 띄운 Swift와 양쪽 직접(Go 맵 억제)", from: restarted,
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

    @Test("② Go 피어를 다시 띄우고 Swift 노드의 netmap 갱신을 막아도 직접 경로가 선다(Swiftail이 Go의 광고를 쓴다)")
    func swiftUsesGoAdvertisement() async throws {
        try await withGate(direct: false) { gate in
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let goName = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
            let before = try await directPath(gate.tool, swift: gate.node, local: gate.local, go: gate.peer, goName: goName,
                                              stage: "② 준비: 양쪽 직접", from: gate.runningAt)

            // Swift 노드에게 가는 자동 맵을 막는다(표식 주소가 보이면 막힌 것이다).
            try await gate.inject(MapInjection(), marker: 1)
            let event = try await gate.tool.command(.init(cmd: "restartPeer", name: "go-peer-a"), expecting: "peer")
            #expect(event.nodeKey == gate.peer.key, "다시 띄운 Go 피어의 node 키는 그대로다")
            let restarted = ContinuousClock.now
            await gate.tool.checkpoint("②: Go 피어 다시 띄움, Swift 맵 억제 중")
            // 새 Go 인스턴스는 세션이 없으므로 Go가 먼저 보내 핸드셰이크를 시작하게 한다.
            let after = try await directPath(gate.tool, swift: gate.node, local: gate.local, go: gate.peer, goName: goName,
                                             stage: "②: 다시 띄운 Go와 양쪽 직접(Swift 맵 억제)", from: restarted,
                                             notSwiftPath: before.swiftPath, goSends: true)
            #expect(after.swiftPath != before.swiftPath)
        }
    }

    @Test("Swift ↔ Swift: 한쪽을 다시 띄우고 다른 쪽의 netmap 갱신을 막아도 직접 경로가 선다")
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
                                                   stage: "Swift ↔ Swift 준비: 양쪽 직접", from: .now)

                // A(오래 떠 있는 쪽)에게 가는 자동 맵을 막고 B를 다시 띄운다. A는 B의 옛 disco 키·엔드포인트만 안다.
                try await gate.inject(MapInjection(), marker: 2)
                run?.cancel()
                _ = await run?.result
                run = nil
                let second = try TailnetNode(configuration: configuration, device: .memory())
                run = Task { try await second.run() }
                #expect(try await running(second) == addresses)
                let restarted = ContinuousClock.now
                await gate.tool.checkpoint("Swift ↔ Swift: B 다시 띄움, A 맵 억제 중")
                _ = try await swiftDirect(gate.node, second, a: gate.local, b: b, aName: aName, bName: bName,
                                          stage: "Swift ↔ Swift: 다시 띄운 B와 양쪽 직접(A 맵 억제)", from: restarted,
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

/// 양쪽이 직접일 때 본 값.
private struct DirectSnapshot {
    let swiftPath: PeerPath
    let goCurAddr: String
}

/// UDP를 보내며 Swift의 경로와 Go의 `curAddr`가 모두 직접이 될 때까지 20초 기다린다. `notSwiftPath`·`notGoCurAddr`
/// 와 같은 값(다시 띄우기 전의 경로)은 인정하지 않는다.
private func directPath(_ tool: GoTailnet, swift node: TailnetNode, local: GatePeer, go peer: GatePeer, goName: String,
                        stage: String, from start: ContinuousClock.Instant,
                        notSwiftPath: PeerPath? = nil, notGoCurAddr: String? = nil, goSends: Bool = false) async throws -> DirectSnapshot {
    let deadline = start + .seconds(20)
    let probe = Packets.udp(from: try local.address(), port: 43200, to: try peer.address(), payload: [0x54, 0x53])
    // Swift를 다시 띄운 경우 세션 전 데이터가 몰려 나가며 DERP 큐에서 자신의 TSMP 광고를 밀어낼 수 있다.
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
    throw GateFailure("\(stage): 20초 안에 양쪽 직접이 되지 않음(Swift \(path.map { "\($0)" } ?? "nil"), 다시 띄우기 전 경로와 같음: \(path == notSwiftPath))")
}

/// B가 WireGuard 세션을 시작한 뒤 양쪽이 직접이 될 때까지 총 20초 기다린다. A가 본 B의 새 직접 경로를 돌려준다.
///
/// 양쪽에서 시작하면 initiation이 서로를 지울 수 있다. B의 UDP가 A에 도착하면 세션이 섰으므로 그때 A도 보낸다.
/// 새 disco 키를 배운 A는 송신 기록을 지우므로 다시 보내야 직접 경로 탐색을 시작한다.
private func swiftDirect(_ a: TailnetNode, _ b: TailnetNode, a aPeer: GatePeer, b bPeer: GatePeer, aName: String, bName: String,
                         stage: String, from start: ContinuousClock.Instant, notAPath: PeerPath? = nil) async throws -> PeerPath {
    let deadline = start + .seconds(20)
    let aIP = try aPeer.address(), bIP = try bPeer.address()
    // A의 수신 흐름에 남은 재시작 전 패킷을 이번 세션의 증거로 세지 않는다.
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
            // 세션 전의 데이터를 한꺼번에 내보낼 때 TSMP 광고를 포함한 묶음이 DERP의 32개 송신 큐를 넘지 않게 한다.
            while ContinuousClock.now <= deadline {
                await b.send(probe)
                try await Task.sleep(for: .seconds(1))
            }
            return false
        }
        return try await group.next() ?? false
    }
    if received { report("\(stage): B의 첫 UDP를 A에서 수신", since: start) }
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
    throw GateFailure("\(stage): 20초 안에 양쪽 직접이 되지 않음(A \(aPath.map { "\($0)" } ?? "nil"), B \(bPath.map { "\($0)" } ?? "nil"), A가 다시 띄우기 전 경로와 같음: \(aPath == notAPath), B의 UDP 수신: \(received))")
}

private func report(_ stage: String, since start: ContinuousClock.Instant) {
    let line = "[TSMP \(Date().ISO8601Format())] \(stage): +\(start.duration(to: .now))\n"
    try? FileHandle.standardOutput.write(contentsOf: Data(line.utf8))
}
