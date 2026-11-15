// Tailnet Lock 관문 (가)의 하네스(docs/contracts/SwiftailTailnetLock.md 7절): `tailnet` 도구(testcontrol 사본 + DERP + STUN),
// 서명 기기 노릇을 하는 Go 피어, 메모리 장치의 Swift 노드들. 기존 관문의 `withGate`와 같이 도구와 노드를 시험마다 새로 띄우고
// 성공·실패·취소에서 모두 회수한다(상태 디렉터리는 TMPDIR 아래).

import Foundation
import SwiftailBase
import SwiftailControl
import Synchronization
import Testing

@testable import Swiftail

/// 노드의 사건과 받은 패킷을 `run()` 내내 모은다.
///
/// 두 흐름은 구독자가 하나이고, 기다리던 읽기를 기한으로 취소하면 흐름이 끝나 버린다. 그래서 기다리는 쪽은 흐름을 직접 읽지
/// 않고 이 기록을 폴링한다.
final class NodeRecorder: Sendable {
    /// 사건 하나와 그 사건을 받은 직후에 읽은 `status`.
    struct Entry: Sendable {
        let event: NodeEvent
        let status: NodeStatus
    }

    private let entries = Mutex<[Entry]>([])
    private let received = Mutex<[ReceivedPacket]>([])

    func append(_ event: NodeEvent, _ status: NodeStatus) { entries.withLock { $0.append(.init(event: event, status: status)) } }
    func append(_ packet: ReceivedPacket) { received.withLock { $0.append(packet) } }

    var events: [Entry] { entries.withLock { $0 } }
    var packetCount: Int { received.withLock { $0.count } }

    /// `start` 번째부터 받은 패킷 가운데 `predicate`에 맞는 것이 있는가.
    func received(since start: Int, where predicate: (ReceivedPacket) -> Bool) -> Bool {
        received.withLock { $0.dropFirst(start).contains(where: predicate) }
    }

    /// 받은 `tailnetLockChanged`의 값들(받은 순서).
    var lockChanges: [TailnetLockStatus] {
        events.compactMap { if case let .tailnetLockChanged(lock) = $0.event { lock } else { nil } }
    }
}

/// 관문의 Swift 노드 하나. 메모리 장치라 UDP·TCP를 패킷으로 주고받는다(기존 관문 3·4와 같은 길).
final class LockNode: Sendable {
    let node: TailnetNode
    let directory: URL
    let recorder: NodeRecorder
    private let run: Task<Void, any Error>
    private let collectors: [Task<Void, Never>]

    init(directory: URL, hostname: String, controlURL: URL, authKey: String?) throws {
        let node = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: hostname,
                                                        controlURL: controlURL, authKey: authKey), device: .memory())
        let recorder = NodeRecorder()
        collectors = [
            Task {
                for await event in node.events { recorder.append(event, await node.status) }
            },
            Task {
                // 이 관문이 보내는 것은 UDP·TCP뿐이다. 다른 패킷(ICMP 등)은 해석하지 못하므로 건너뛴다.
                for await bytes in node.inboundPackets { if let packet = try? ReceivedPacket(bytes) { recorder.append(packet) } }
            },
        ]
        run = Task { try await node.run() }
        self.node = node
        self.directory = directory
        self.recorder = recorder
    }

    /// `run()`을 끝내고 회수한다. 끝난 까닭이 취소가 아니면 그 설명을 돌려준다.
    @discardableResult
    func stop() async -> String? {
        run.cancel()
        let result = await run.result
        for collector in collectors { await collector.value }
        if case .failure(let error) = result, !(error is CancellationError) { return redacted(String(describing: error)) }
        return nil
    }

    var status: NodeStatus { get async { await node.status } }

    /// Swift 노드의 netmap(걸러진 것)에 있는 피어의 node 키.
    var peerKeys: Set<String> { get async { Set(await node.lastNetmap?.peers.map(\.key.description) ?? []) } }

    /// 자기 node 키. netmap 전에는 nil.
    var selfKey: String? { get async { await node.lastNetmap?.selfNode.key.description } }

    var lockFile: URL { directory.appending(path: "tailnet-lock.cbor") }

    func address() async throws -> IPAddress {
        try #require(await status.addresses.first { $0.isIPv4 })
    }
}

/// 시험 하나의 lock 관문.
struct LockGate: Sendable {
    /// 안 되는 쪽(응답 없음)을 볼 때 기다리는 시간. 되는 쪽은 루프백의 DERP에서 첫 패킷이 보통 1초 안에 오지만(관측값은 각 단계의
    /// checkpoint에 남긴다), 첫 WireGuard 핸드셰이크와 재송신 간격(0.5초)을 넉넉히 덮는다.
    static let silence: Duration = .seconds(6)
    /// 되는 쪽을 기다리는 한도.
    static let reachable: Duration = .seconds(25)

    final class Registry: Sendable {
        struct State {
            var nodes: [LockNode] = []
            var names: [String: String] = [:]
            var nextPort: UInt16 = 43_100
        }
        let state = Mutex(State())
    }

    let tool: GoTailnet
    let controlURL: URL
    let root: URL
    let registry: Registry

    // MARK: 도구 명령

    func command(_ value: GoTailnet.Command, expecting kind: String) async throws -> GoTailnet.Event {
        try await tool.command(value, expecting: kind)
    }

    func addPeer(_ name: String, authKey: String? = nil) async throws -> GatePeer {
        let peer = try GatePeer(await command(.init(cmd: "addPeer", name: name, authKey: authKey), expecting: "peer"))
        self.name(peer.key, name)
        return peer
    }

    func lockStatus(_ name: String) async throws -> GoTailnet.Event {
        try await command(.init(cmd: "lockStatus", name: name), expecting: "lockStatus")
    }

    func registrations() async throws -> [GoTailnet.LockRegistration] {
        try #require(await command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
    }

    /// testcontrol이 받은 `/machine/tka/` 요청.
    func tkaRequests() async throws -> [GoTailnet.SetDNSRequest] {
        try #require(await command(.init(cmd: "lockRequests"), expecting: "lockRequests").requests)
    }

    /// `nodeKey`가 보낸 `/machine/tka/<kind>` 요청 수.
    func tkaRequestCount(_ kind: String, from nodeKey: String) async throws -> Int {
        try await tkaRequests().count { $0.path == "/machine/tka/\(kind)" && $0.nodeKey == nodeKey }
    }

    /// testcontrol의 등록 목록에 있는 모든 node 키.
    func registeredKeys() async throws -> Set<String> {
        Set(try #require(await command(.init(cmd: "nodes"), expecting: "nodes").nodes).map(\.nodeKey))
    }

    func setBootstrapFault(_ enabled: Bool) async throws {
        _ = try await command(.init(cmd: "setLockBootstrapFault", enabled: enabled), expecting: "lockBootstrapFault")
    }

    // MARK: 이름

    /// 보고에 키 대신 이름을 쓴다.
    func name(_ key: String, _ name: String) { registry.state.withLock { $0.names[key] = name } }

    func names(_ keys: Set<String>) -> String {
        let names = registry.state.withLock { state in keys.map { state.names[$0] ?? "이름 없는 노드" } }
        return "[" + names.sorted().joined(separator: ", ") + "]"
    }

    // MARK: Swift 노드

    func startNode(_ label: String, hostname: String = "rd-mac-1a2b3c4d", authKey: String? = nil) throws -> LockNode {
        let node = try LockNode(directory: root.appending(path: label), hostname: hostname,
                                controlURL: controlURL, authKey: authKey)
        registry.state.withLock { $0.nodes.append(node) }
        return node
    }

    /// Swift 노드의 `status`가 `predicate`를 만족할 때까지 기다려 그 값을 돌려준다.
    @discardableResult
    func wait(_ node: LockNode, _ stage: String, seconds: Int = 30,
              _ predicate: @Sendable (NodeStatus) -> Bool) async throws -> NodeStatus {
        var last: NodeStatus?
        do {
            try await netstackWait(stage, seconds: seconds) {
                let status = await node.status
                last = status
                return predicate(status)
            }
        } catch {
            throw GateFailure("\(error) — 마지막 상태: \(describe(last))")
        }
        return try #require(last)
    }

    /// `seconds` 동안 `predicate`가 계속 참인지 본다(바뀌지 않아야 하는 것).
    func holds(_ node: LockNode, _ stage: String, seconds: Int = 3,
               _ predicate: @Sendable (NodeStatus) -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(seconds)
        while ContinuousClock.now < deadline {
            let status = await node.status
            guard predicate(status) else { throw GateFailure("\(stage): 바뀌지 않아야 하는데 바뀜 — \(describe(status))") }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    func describe(_ status: NodeStatus?) -> String {
        guard let status else { return "없음" }
        let lock = status.tailnetLock
        return "state \(status.state), mode \(lock.mode), issue \(lock.issue.map { "\($0)" } ?? "없음"), "
            + "head \(lock.head.map { String($0.prefix(8)) } ?? "없음"), signingRequest \(lock.signingRequest == nil ? "없음" : "있음"), "
            + "peerCount \(status.peerCount), filteredPeerCount \(lock.filteredPeerCount)"
    }

    // MARK: 판정 견주기

    /// 같은 시점의 Go 피어 `goName`의 판정과 Swift 노드의 판정이 같아질 때까지 기다린다(계약 7절 관문 (가) 5).
    ///
    /// 견주는 것: 머리 텍스트, 보이는 피어(Go의 `visiblePeers`, 서명된 Go 피어 자신 포함)와 Swift netmap의 피어, 거른 피어(Go의
    /// `filteredPeers`, 서명 없는 Go 피어 자신 포함)와 Swift가 거른 피어(testcontrol의 등록 목록에서 Swift가 남긴 피어와 자기를
    /// 뺀 것)와 그 수(`filteredPeerCount`), Go가 Swift 노드를 거르는지와 Swift 노드의 자기 잠김(`signingRequest`). Swift 노드 자신은 Go 쪽 두 집합에서 뺀다. 이 서버는 `UnsignedPeerAPIOnly`를 주지 않는다.
    /// `controlHead`가 있으면(서버의 lock이 켜져 있으면) 머리가 그것과도 같아야 한다.
    func expectAgreement(_ node: LockNode, with goName: String, _ stage: String, seconds: Int = 30) async throws {
        var detail = ""
        do {
            try await netstackWait("\(stage): \(goName)와 Swift 노드의 판정", seconds: seconds) {
                let go = try await lockStatus(goName)
                let status = await node.status
                let swiftPeers = await node.peerKeys
                guard let selfKey = await node.selfKey, let goKey = go.nodeKey else { return false }
                let registered = try await registeredKeys()
                // Go 피어 자신은 자기 서명이 검증되면(`nodeKeySigned`) 보이는 쪽, 아니면 거른 쪽에 넣는다.
                let goSigned = go.nodeKeySigned == true
                let goVisible = Set(go.visiblePeers ?? []).union(goSigned ? [goKey] : []).subtracting([selfKey])
                let goFiltered = Set(go.filteredPeers ?? []).union(goSigned ? [] : [goKey]).subtracting([selfKey])
                // 자기 잠김: Go가 Swift 노드를 거르는 것과 Swift 노드가 스스로 잠겼다고 보는 것이 같다.
                let goFiltersSwift = go.filteredPeers?.contains(selfKey) == true
                let goSeesSwift = go.visiblePeers?.contains(selfKey) == true
                let swiftLocked = status.tailnetLock.signingRequest != nil
                let swiftFiltered = registered.subtracting(swiftPeers).subtracting([selfKey])
                let controlHead = go.controlHead ?? ""
                detail = "Go 보임 \(names(goVisible)) / Swift 보임 \(names(swiftPeers)); "
                    + "Go 거름 \(names(goFiltered)) / Swift 거름 \(names(swiftFiltered)) (filteredPeerCount \(status.tailnetLock.filteredPeerCount)); "
                    + "Swift 잠김 \(swiftLocked) / Go가 거름 \(goFiltersSwift)·봄 \(goSeesSwift); "
                    + "머리 일치 Go=\(status.tailnetLock.head == go.head) 서버=\(controlHead.isEmpty ? "서버 lock 꺼짐" : "\(status.tailnetLock.head == controlHead)")"
                return go.enabled == true && status.tailnetLock.mode == .enforcing
                    && status.tailnetLock.head != nil && status.tailnetLock.head == go.head
                    && (controlHead.isEmpty || controlHead == go.head)
                    && goVisible == swiftPeers && goFiltered == swiftFiltered
                    && swiftFiltered.count == status.tailnetLock.filteredPeerCount
                    && status.peerCount == swiftPeers.count
                    && goFiltersSwift == swiftLocked && goSeesSwift == !swiftLocked
            }
        } catch {
            Issue.record("\(stage): Go와 Swift의 판정이 다름 — \(detail)")
            throw error
        }
        await tool.checkpoint("\(stage): \(goName)와 같은 판정 — \(detail)")
    }

    // MARK: 데이터면

    private func nextPort() -> UInt16 {
        registry.state.withLock { state in
            defer { state.nextPort += 1 }
            return state.nextPort
        }
    }

    /// Swift 노드가 `peer`의 UDP 에코(포트 7)를 받기까지의 시간. `within` 안에 오지 않으면 nil.
    func udpEcho(from node: LockNode, to peer: GatePeer, within: Duration) async throws -> Duration? {
        let port = nextPort()
        let payload = Array("tl10-\(port)".utf8)
        let source = try await node.address(), destination = try peer.address()
        let packet = Packets.udp(from: source, port: port, to: destination, payload: payload)
        return try await exchange(node, within: within, send: { await node.node.send(packet) }) {
            $0.proto == 17 && $0.source == destination && $0.sourcePort == 7 && $0.destinationPort == port && $0.payload == payload
        }
    }

    /// Swift 노드가 보낸 SYN에 `peer`의 TCP 포트 7이 SYN-ACK로 답하기까지의 시간. 오지 않으면 nil.
    func tcpHandshake(from node: LockNode, to peer: GatePeer, within: Duration) async throws -> Duration? {
        let port = nextPort()
        let source = try await node.address(), destination = try peer.address()
        let syn = Packets.syn(from: source, port: port, to: destination, destinationPort: 7, sequence: UInt32(port) << 16)
        return try await exchange(node, within: within, send: { await node.node.send(syn) }) {
            $0.proto == 6 && $0.source == destination && $0.sourcePort == 7 && $0.destinationPort == port
                && $0.flags & 0x12 == 0x12 && $0.acknowledgement == UInt32(port) << 16 &+ 1
        }
    }

    /// Go 피어 `goName`이 Swift 노드에 보낸 UDP 데이터그램이나 TCP SYN이 Swift 노드의 장치에 닿기까지의 시간. 닿지 않으면 nil.
    ///
    /// 메모리 장치에서는 필터를 통과한 패킷만 `inboundPackets`로 나온다. 닿지 않으면 Swift 노드는 그 패킷에 답할 수도 없다.
    func goSend(_ goName: String, to node: LockNode, proto: String, within: Duration) async throws -> Duration? {
        let port = nextPort()
        let payload = Array("tl10-\(port)".utf8)
        let target = try await node.address().description
        return try await exchange(node, within: within, send: {
            // TCP는 도구가 2초 동안 연결을 시도한다(그사이 Go가 SYN을 재송신한다). 쓰기 결과는 수신을 보장하지 않으므로 보지 않는다.
            _ = try await command(.init(cmd: "peerSend", name: goName, to: target, port: port, proto: proto, payload: payload.hex),
                                  expecting: "peerSend")
        }) {
            $0.destinationPort == port && (proto == "udp" ? $0.proto == 17 && $0.payload == payload : $0.proto == 6 && $0.flags & 0x12 == 0x02)
        }
    }

    /// `send`를 0.5초마다 되풀이하며 기록에서 `predicate`에 맞는 패킷을 찾는다.
    private func exchange(_ node: LockNode, within: Duration, send: () async throws -> Void,
                          matching predicate: (ReceivedPacket) -> Bool) async throws -> Duration? {
        let start = ContinuousClock.now, mark = node.recorder.packetCount
        while start.duration(to: .now) < within {
            try await send()
            let resend = ContinuousClock.now + .milliseconds(500)
            while ContinuousClock.now < resend {
                if node.recorder.received(since: mark, where: predicate) { return start.duration(to: .now) }
                try await Task.sleep(for: .milliseconds(25))
            }
        }
        return node.recorder.received(since: mark, where: predicate) ? start.duration(to: .now) : nil
    }

    /// 되는 쪽: `within` 안에 와야 한다. 걸린 시간을 남긴다.
    func expectReachable(_ stage: String, _ probe: () async throws -> Duration?) async throws {
        guard let elapsed = try await probe() else { throw GateFailure("\(stage): \(Self.reachable) 안에 오지 않음") }
        await tool.checkpoint("\(stage): \(elapsed.formatted(.units(allowed: [.milliseconds])))")
    }

    /// 안 되는 쪽: `silence` 동안 오지 않아야 한다.
    func expectSilent(_ stage: String, _ probe: () async throws -> Duration?) async throws {
        if let elapsed = try await probe() {
            Issue.record("\(stage): 오지 않아야 하는데 \(elapsed.formatted(.units(allowed: [.milliseconds]))) 만에 옴")
        } else {
            await tool.checkpoint("\(stage): \(Self.silence) 동안 오지 않음")
        }
    }
}

/// lock 관문 하나를 띄우고 회수한다. `capability`면 첫 등록 전에 모든 노드의 CapMap에 `tailnet-lock`을 싣는다.
func withLockGate(capability: Bool = true, _ body: (LockGate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-tl10-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    let registry = LockGate.Registry()
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("lock 관문 상태 디렉터리 정리 실패: \(redacted(String(describing: error)))") }
        }
    }
    func stopNodes() async -> [String] {
        var failures: [String] = []
        for node in registry.state.withLock({ $0.nodes }) {
            if let failure = await node.stop() { failures.append(failure) }
        }
        return failures
    }
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        if capability {
            _ = try await tool.command(.init(cmd: "setLockCapability", enabled: true), expecting: "lockCapability")
        }
        let gate = LockGate(tool: tool, controlURL: try #require(ready.controlURL), root: directory, registry: registry)
        try await body(gate)
        let failures = await stopNodes()
        await tool.stop()
        if !failures.isEmpty { throw GateFailure("TailnetNode.run이 취소 전에 끝남: \(failures.joined(separator: "; "))") }
    } catch {
        let failures = await stopNodes()
        await tool.stop()
        var detail = redacted(String(describing: error))
        if !failures.isEmpty { detail += "\nTailnetNode.run: \(failures.joined(separator: "; "))" }
        throw GateFailure("\(detail)\n\(await tool.diagnostics())")
    }
}
