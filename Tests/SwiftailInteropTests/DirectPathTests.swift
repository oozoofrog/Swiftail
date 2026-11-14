import Foundation
import Swiftail
import SwiftailBase
import SwiftailMagicsock
import Testing

@Suite("M4 직접 경로 관문", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M4 관문 시험을 건너뜁니다"), .serialized, .timeLimit(.minutes(6)))
struct DirectPathTests {
    @Test("항목 1~4·8: 엔드포인트, Swift 선행, 양쪽 차단과 복귀, TSMP 소비")
    func pathSwitching() async throws {
        try await withGate(direct: false) { gate in
            let context = try await DirectContext.load(gate)
            note("항목 1: STUN 엔드포인트·Go selfAddrs", since: gate.runningAt)
            let initial = ContinuousClock.now
            try await observe(gate) { observations in
                try await wait("항목 2: 양쪽 직접 경로·direct 사건", from: initial, for: .seconds(15)) {
                    let direct = try await context.isDirect(gate, requiringLoopback: true)
                    let event = await observations.hasDirectPath(context.fqdn, since: initial)
                    return direct && event
                }
                try await observations.requireEchoes(since: initial)

                let blocked = ContinuousClock.now
                await gate.tool.checkpoint("항목 3: Swift 원격 UDP 포트 차단")
                await gate.node.setBlockedUDPPorts([context.goEndpoint.port])
                try await wait("항목 3: 양쪽 중계", from: blocked, for: .milliseconds(9500)) {
                    try await context.isRelayed(gate)
                }
                // 신뢰 기간의 유실만 허용하고, +9.5초 이후에는 단 한 번 보낸 에코를 모두 확인한다.
                let reliable = blocked + .milliseconds(9500)
                try await until(reliable + .seconds(4))
                try await observations.requireEchoes(since: reliable)
                let lost = await observations.missing(since: blocked, before: reliable)
                #expect(!lost.isEmpty, "항목 3: 차단 직후 UDP 단독 신뢰 기간에는 에코 유실이 있어야 한다")
                note("항목 3: 신뢰 기간 유실 \(lost.count)개, +9.5초 이후 에코 수신", since: blocked)

                let unblocked = ContinuousClock.now
                await gate.node.setBlockedUDPPorts([])
                do {
                    try await wait("항목 3: Swift 차단 해제 뒤 양쪽 직접", from: unblocked, for: .seconds(10)) {
                        try await context.isDirect(gate)
                    }
                } catch {
                    throw GateFailure("\(error)\n\(try await context.pathSummary(gate))")
                }
                try await observations.requireEchoes(since: reliable)

                let disabled = ContinuousClock.now
                let on = try await gate.tool.command(.init(cmd: "setNeverDirectUDP", enabled: true), expecting: "neverDirectUDP")
                #expect(on.enabled == true)
                try await wait("항목 4: Go 노브 뒤 양쪽 중계", from: disabled, for: .milliseconds(9500)) {
                    try await context.isRelayed(gate)
                }
                try await observations.requireEchoes(since: disabled)
                let enabled = ContinuousClock.now
                let off = try await gate.tool.command(.init(cmd: "setNeverDirectUDP", enabled: false), expecting: "neverDirectUDP")
                #expect(off.enabled == false)
                do {
                    try await wait("항목 4: Go 노브 해제 뒤 양쪽 직접", from: enabled, for: .seconds(10)) {
                        try await context.isDirect(gate)
                    }
                } catch {
                    throw GateFailure("\(error)\n\(try await context.pathSummary(gate))")
                }
                try await observations.requireEchoes(since: reliable)
                note("항목 8: 세션·전환 동안 inbound TSMP 0개", since: initial)
            }
        }
    }

    @Test("항목 6~8: 유휴·재개, 130초 직접 경로 유지·에코 무손실, TSMP 소비")
    func idleAndLongHold() async throws {
        try await withGate(direct: false) { gate in
            let context = try await DirectContext.load(gate)
            try await observe(gate) { observations in
                try await wait("항목 6 준비: 양쪽 직접", from: .now, for: .seconds(15)) {
                    try await context.isDirect(gate)
                }
                try await observations.requireEchoes(since: gate.runningAt)
                let idle = await observations.pause()
                await gate.tool.checkpoint("항목 6: 에코 송신 중지")
                // 유휴 경계를 기다리는 동안에도 Swift 조회와 사건을 계속 관측한다.
                var inactiveAt: ContinuousClock.Instant?
                var nilAt: ContinuousClock.Instant?
                var nilEventAt: ContinuousClock.Instant?
                try await wait("항목 6: 50초 이후 Go inactive·75초 이내 Swift nil 사건과 조회",
                               from: idle, for: .seconds(75)) {
                    if await gate.node.path(toPeerNamed: context.fqdn) == nil, nilAt == nil { nilAt = .now }
                    if await observations.hasNil(context.fqdn, since: idle), nilEventAt == nil { nilEventAt = .now }
                    let status = try await context.status(gate)
                    if status.active == false, inactiveAt == nil { inactiveAt = .now }
                    guard ContinuousClock.now >= idle + .seconds(50) else { return false }
                    guard let inactiveAt, inactiveAt <= idle + .seconds(50) else {
                        throw GateFailure("항목 6: 송신 중지 50초까지 Go inactive를 관측하지 못함")
                    }
                    return status.active == false && nilAt != nil && nilEventAt != nil
                }
                note("항목 6: Go inactive", since: idle, at: try #require(inactiveAt))
                note("항목 6: Swift nil 조회", since: idle, at: try #require(nilAt))
                note("항목 6: Swift nil 사건", since: idle, at: try #require(nilEventAt))
                let resumed = ContinuousClock.now
                await observations.resume()
                try await wait("항목 6: 재개 뒤 양쪽 직접·direct 사건", from: resumed, for: .seconds(15)) {
                    let direct = try await context.isDirect(gate)
                    let event = await observations.hasDirectPath(context.fqdn, since: resumed)
                    return direct && event
                }
                try await observations.requireEchoes(since: resumed)

                let maintained = ContinuousClock.now
                await gate.tool.checkpoint("항목 7: 130초 유지 시작")
                for tick in 1...13 {
                    try await until(maintained + .seconds(tick * 10))
                    let direct = try await context.isDirect(gate)
                    #expect(direct, "항목 7: \(tick * 10)초의 양쪽 경로가 직접이어야 한다")
                    try await observations.requireEchoes(since: maintained)
                    note("항목 7: \(tick * 10)초 양쪽 직접·에코 무손실", since: maintained)
                }
                #expect(maintained.duration(to: .now) >= .seconds(130))
                note("항목 8: 세션·유휴·rekey 동안 inbound TSMP 0개", since: maintained)
            }
        }
    }
    @Test("항목 5: running 뒤 더한 Go 피어가 먼저 보내 직접 경로를 만든다")
    func goPeerInitiates() async throws {
        try await withGate(direct: false) { gate in
            let original = try await DirectContext.load(gate)
            await gate.tool.checkpoint("항목 5: running 뒤 새 Go 피어 추가 직전")
            let event = try await gate.tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")
            let peer = try GatePeer(event)
            let fqdn: String = try #require(event.fqdn)
            let context = try await DirectContext.load(gate, name: "go-peer-b", fqdn: fqdn,
                                                       deadline: .now + .seconds(10))
            #expect(context.goEndpoint.port != original.goEndpoint.port)
            let started = ContinuousClock.now
            // 도구는 명령을 순서대로 처리하므로 송신과 status 조회도 한 Task에서 직렬화한다.
            var nextSend = started
            try await wait("항목 5: Go 선행 뒤 양쪽 직접", from: started, for: .seconds(15)) {
                if ContinuousClock.now >= nextSend {
                    await gate.tool.checkpoint("항목 5: Go peerSend 직전")
                    let sent = try await gate.tool.command(.init(cmd: "peerSend", name: "go-peer-b",
                        to: try gate.local.address().description, port: 42155, proto: "udp", payload: "4d34"), expecting: "peerSend")
                    #expect(sent.attempted == true && sent.sent == true && sent.error == "")
                    nextSend += .seconds(1)
                }
                return try await context.isDirect(gate, requiringLoopback: true)
            }
            let received = try await gate.packet("항목 5: 새 Go 피어의 UDP 수신") {
                $0.source == (try? peer.address()) && $0.proto == 17 && $0.destinationPort == 42155 && $0.payload == [0x4d, 0x34]
            }
            #expect(received.destination == (try gate.local.address()))
        }
    }
}

/// Go가 LAN 주소를 골라도 Swift가 실제 올린 엔드포인트인지 검사한다.
private struct DirectContext: Sendable {
    let name: String
    let fqdn: String
    let goEndpoint: IPEndpoint
    let swiftEndpoints: Set<IPEndpoint>

    static func load(_ gate: Gate, name: String = "go-peer-a", fqdn: String? = nil,
                     deadline: ContinuousClock.Instant? = nil) async throws -> Self {
        let deadline = deadline ?? gate.runningAt + .seconds(10)
        var result: Self?
        try await wait("항목 1: nodes STUN 엔드포인트·Go selfAddrs", deadline: deadline) {
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let local = try #require(nodes.first { $0.nodeKey == gate.local.key })
            let endpoints = Set((local.endpoints ?? []).compactMap(IPEndpoint.init))
            let status = try await gate.tool.command(.init(cmd: "peerStatus", name: name), expecting: "peerStatus")
            guard endpoints.contains(where: { $0.address.description == "127.0.0.1" && $0.port != 0 }),
                  let endpoint = status.selfAddrs?.compactMap(IPEndpoint.init).first(where: {
                      $0.address.description == "127.0.0.1" && $0.port != 0
                  }), let peerName = fqdn ?? nodes.first(where: { $0.nodeKey == gate.peer.key })?.name,
                  !peerName.isEmpty else { return false }
            result = Self(name: name, fqdn: peerName, goEndpoint: endpoint, swiftEndpoints: endpoints)
            return true
        }
        return try #require(result)
    }

    func status(_ gate: Gate) async throws -> GoTailnet.Event.Node {
        let event = try await gate.tool.command(.init(cmd: "peerStatus", name: name), expecting: "peerStatus")
        return try #require(event.peers?.first { $0.nodeKey == gate.local.key })
    }

    func isDirect(_ gate: Gate, requiringLoopback: Bool = false) async throws -> Bool {
        let status = try await status(gate)
        guard let text = status.curAddr, let endpoint = IPEndpoint(text), swiftEndpoints.contains(endpoint) else { return false }
        guard case .direct(let address) = await gate.node.path(toPeerNamed: fqdn) else { return false }
        // loopback 주소는 계약의 항목 2·5만 명시한다. 복귀·유지는 직접 경로 여부를 본다.
        return !requiringLoopback || address == goEndpoint
    }

    func isRelayed(_ gate: Gate) async throws -> Bool {
        let status = try await status(gate)
        return await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1) && status.curAddr == ""
    }

    /// 실제 인터페이스 주소를 노출하지 않고 계약의 어느 쪽 조건이 어긋났는지 남긴다.
    func pathSummary(_ gate: Gate) async throws -> String {
        let status = try await status(gate)
        let swift: String
        switch await gate.node.path(toPeerNamed: fqdn) {
        case .direct(let endpoint):
            swift = "direct(Go loopback 일치: \(endpoint == goEndpoint), Go 포트 일치: \(endpoint.port == goEndpoint.port))"
        case .relayed(let region): swift = "relayed(\(region))"
        case nil: swift = "nil"
        }
        let advertised = status.curAddr.flatMap(IPEndpoint.init).map { swiftEndpoints.contains($0) } ?? false
        return "Swift \(swift), Go curAddr 비어 있음: \(status.curAddr == ""), Swift 광고 주소 일치: \(advertised)"
    }
}

/// 한 구독으로 패킷·경로 사건을 모아 취소한 AsyncStream을 다시 구독하지 않는다.
private actor DirectObservations {
    private var paths: [(ContinuousClock.Instant, String, PeerPath?)] = []
    private var sent: [Int: ContinuousClock.Instant] = [:]
    private var received: Set<Int> = []
    private var paused = false
    private var lastSend = ContinuousClock.now

    func record(_ event: NodeEvent) {
        if case let .peerPathChanged(fqdn, path) = event { paths.append((.now, fqdn, path)) }
    }

    func record(_ bytes: [UInt8], gate: Gate) throws {
        // TSMP는 전송 머리가 없다. UDP·TCP 전용 ReceivedPacket 파서보다 먼저 본다.
        if bytes.count >= 20 && (bytes[0] >> 4 == 4 ? bytes[9] : bytes[6]) == 99 {
            throw GateFailure("항목 8: TSMP가 inboundPackets에 나타남")
        }
        let packet = try ReceivedPacket(bytes)
        guard packet.proto == 17 && packet.destinationPort == 43040 else { return }
        let source = try gate.peer.address(), destination = try gate.local.address()
        #expect(packet.source == source && packet.destination == destination)
        #expect(packet.sourcePort == 7)
        guard packet.payload.count == 6, packet.payload.prefix(2) == [0x4d, 0x34] else {
            throw GateFailure("M4 에코 payload 불일치")
        }
        let sequence = packet.payload.dropFirst(2).reduce(0) { $0 * 256 + Int($1) }
        #expect(sent[sequence] != nil, "보낸 적 없는 에코가 수신됨")
        received.insert(sequence)
    }

    func send(_ sequence: Int, gate: Gate) async throws {
        guard !paused else { return }
        let bytes = Packets.udp(from: try gate.local.address(), port: 43040, to: try gate.peer.address(),
                                payload: [0x4d, 0x34] + Packets.long(UInt32(sequence)))
        lastSend = .now
        sent[sequence] = lastSend
        await gate.node.send(bytes)
    }

    func pause() -> ContinuousClock.Instant { paused = true; return lastSend }
    func resume() { paused = false }

    func hasDirectPath(_ fqdn: String, since: ContinuousClock.Instant) -> Bool {
        paths.contains { time, name, path in
            guard time >= since && normalized(name) == normalized(fqdn) else { return false }
            if case .direct = path { return true }
            return false
        }
    }

    func hasNil(_ fqdn: String, since: ContinuousClock.Instant) -> Bool {
        paths.contains { $0.0 >= since && normalized($0.1) == normalized(fqdn) && $0.2 == nil }
    }

    func missing(since: ContinuousClock.Instant, before: ContinuousClock.Instant) -> [Int] {
        sent.filter { $0.value >= since && $0.value < before && !received.contains($0.key) }.map(\.key).sorted()
    }

    func requireEchoes(since: ContinuousClock.Instant) async throws {
        let through = ContinuousClock.now
        try await wait("단발 UDP 에코의 모든 회신", from: through, for: .seconds(3)) {
            self.missing(since: since, before: through).isEmpty
        }
        #expect(sent.values.contains { $0 >= since && $0 < through }, "검사 구간에 실제 송신한 에코가 있어야 한다")
    }

    private func normalized(_ name: String) -> String {
        (name.hasSuffix(".") ? String(name.dropLast()) : name).lowercased()
    }
}

private func observe(_ gate: Gate, _ body: @escaping @Sendable (DirectObservations) async throws -> Void) async throws {
    let observations = DirectObservations()
    try await withThrowingTaskGroup(of: Void.self) { group in
        defer { group.cancelAll() }
        group.addTask {
            for await bytes in gate.node.inboundPackets { try await observations.record(bytes, gate: gate) }
            try Task.checkCancellation()
            throw GateFailure("M4 관측 중 inboundPackets가 종료됨")
        }
        group.addTask {
            for await event in gate.node.events { await observations.record(event) }
            try Task.checkCancellation()
            throw GateFailure("M4 관측 중 events가 종료됨")
        }
        group.addTask {
            let started = ContinuousClock.now
            var sequence = 0
            while true {
                try Task.checkCancellation()
                try await observations.send(sequence, gate: gate)
                sequence += 1
                try await until(started + .seconds(sequence))
            }
        }
        group.addTask { try await body(observations) }
        // 관측 Task의 실패도 즉시 전파해 TSMP 누출을 놓치지 않는다.
        _ = try await group.next()
    }
}

private func wait(_ stage: String, from start: ContinuousClock.Instant, for duration: Duration,
                  isolation: isolated (any Actor)? = #isolation,
                  _ condition: () async throws -> Bool) async throws {
    try await wait(stage, deadline: start + duration, condition)
    note(stage, since: start)
}

private func wait(_ stage: String, deadline: ContinuousClock.Instant,
                  isolation: isolated (any Actor)? = #isolation,
                  _ condition: () async throws -> Bool) async throws {
    while ContinuousClock.now <= deadline {
        if try await condition(), ContinuousClock.now <= deadline { return }
        try await Task.sleep(for: .milliseconds(100))
    }
    throw GateFailure("\(stage): 조건 대기 제한 초과")
}

private func until(_ instant: ContinuousClock.Instant) async throws {
    try await Task.sleep(until: instant, clock: .continuous)
}

private func note(_ stage: String, since start: ContinuousClock.Instant, at end: ContinuousClock.Instant = .now) {
    let line = "[M4 \(Date().ISO8601Format())] \(stage): +\(start.duration(to: end))\n"
    try? FileHandle.standardOutput.write(contentsOf: Data(line.utf8))
}
