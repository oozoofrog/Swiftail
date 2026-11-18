import Foundation
import Swiftail
import SwiftailBase
import SwiftailMagicsock
import Testing

@Suite("M4 direct path gate", .enabled(if: tailnetBinary != nil,
    "Skipping M4 gate tests because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(6)))
struct DirectPathTests {
    @Test("Items 1–4 and 8: endpoints, Swift sends first, blocking and recovery on both sides, and TSMP consumption")
    func pathSwitching() async throws {
        try await withGate(direct: false) { gate in
            let context = try await DirectContext.load(gate)
            note("Item 1: STUN endpoints and Go selfAddrs", since: gate.runningAt)
            let initial = ContinuousClock.now
            try await observe(gate) { observations in
                try await wait("Item 2: direct paths on both sides and a direct event", from: initial, for: .seconds(15)) {
                    let direct = try await context.isDirect(gate, requiringLoopback: true)
                    let event = await observations.hasDirectPath(context.fqdn, since: initial)
                    return direct && event
                }
                try await observations.requireEchoes(since: initial)

                let (probe, blocked) = try await observations.blockAndSend(gate, context: context)
                await gate.tool.checkpoint("Item 3: block the Swift remote UDP port and send one echo over the direct path")
                try await wait("Item 3: both sides relayed", from: blocked, for: .milliseconds(9500)) {
                    try await context.isRelayed(gate)
                }
                // Allow loss only during the trust period and verify every echo sent exactly once after +9.5 seconds.
                let reliable = blocked + .milliseconds(9500)
                try await until(reliable + .seconds(4))
                try await observations.requireEchoes(since: reliable)
                let lost = await observations.missing(since: blocked, before: reliable)
                #expect(lost.contains(probe), "Item 3: the echo sent while blocking a still-trusted direct path must be lost")
                note("Item 3: \(lost.count) lost during the trust period, echoes received after +9.5 seconds", since: blocked)

                let unblocked = ContinuousClock.now
                await gate.node.setBlockedUDPPorts([])
                do {
                    try await wait("Item 3: both sides direct after lifting the Swift block", from: unblocked, for: .seconds(10)) {
                        try await context.isDirect(gate)
                    }
                } catch {
                    throw GateFailure("\(error)\n\(try await context.pathSummary(gate))")
                }
                try await observations.requireEchoes(since: reliable)

                let disabled = ContinuousClock.now
                let on = try await gate.tool.command(.init(cmd: "setNeverDirectUDP", enabled: true), expecting: "neverDirectUDP")
                #expect(on.enabled == true)
                try await wait("Item 4: both sides relayed after setting the Go knob", from: disabled, for: .milliseconds(9500)) {
                    try await context.isRelayed(gate)
                }
                try await observations.requireEchoes(since: disabled)
                let enabled = ContinuousClock.now
                let off = try await gate.tool.command(.init(cmd: "setNeverDirectUDP", enabled: false), expecting: "neverDirectUDP")
                #expect(off.enabled == false)
                do {
                    try await wait("Item 4: both sides direct after clearing the Go knob", from: enabled, for: .seconds(10)) {
                        try await context.isDirect(gate)
                    }
                } catch {
                    throw GateFailure("\(error)\n\(try await context.pathSummary(gate))")
                }
                try await observations.requireEchoes(since: reliable)
                note("Item 8: 0 inbound TSMP packets during the session and transition", since: initial)
            }
        }
    }

    @Test("Items 6–8: idle and resume, direct path for 130 seconds with no echo loss, and TSMP consumption")
    func idleAndLongHold() async throws {
        try await withGate(direct: false) { gate in
            let context = try await DirectContext.load(gate)
            try await observe(gate) { observations in
                try await wait("Item 6 setup: both sides direct", from: .now, for: .seconds(15)) {
                    try await context.isDirect(gate)
                }
                try await observations.requireEchoes(since: gate.runningAt)
                let idle = await observations.pause()
                await gate.tool.checkpoint("Item 6: stop sending echoes")
                // Continue observing Swift queries and events while waiting for the idle boundary.
                var inactiveAt: ContinuousClock.Instant?
                var nilAt: ContinuousClock.Instant?
                var nilEventAt: ContinuousClock.Instant?
                try await wait("Item 6: Go inactive after 50 seconds and Swift nil event and query result within 75 seconds",
                               from: idle, for: .seconds(75)) {
                    if await gate.node.path(toPeerNamed: context.fqdn) == nil, nilAt == nil { nilAt = .now }
                    if await observations.hasNil(context.fqdn, since: idle), nilEventAt == nil { nilEventAt = .now }
                    let status = try await context.status(gate)
                    if status.active == false, inactiveAt == nil { inactiveAt = .now }
                    guard ContinuousClock.now >= idle + .seconds(50) else { return false }
                    guard let inactiveAt, inactiveAt <= idle + .seconds(50) else {
                        throw GateFailure("Item 6: Go inactive not observed by 50 seconds after stopping sends")
                    }
                    return status.active == false && nilAt != nil && nilEventAt != nil
                }
                note("Item 6: Go inactive", since: idle, at: try #require(inactiveAt))
                note("Item 6: Swift nil query result", since: idle, at: try #require(nilAt))
                note("Item 6: Swift nil event", since: idle, at: try #require(nilEventAt))
                let resumed = ContinuousClock.now
                await observations.resume()
                try await wait("Item 6: both sides direct and a direct event after resuming", from: resumed, for: .seconds(15)) {
                    let direct = try await context.isDirect(gate)
                    let event = await observations.hasDirectPath(context.fqdn, since: resumed)
                    return direct && event
                }
                try await observations.requireEchoes(since: resumed)

                let maintained = ContinuousClock.now
                await gate.tool.checkpoint("Item 7: start the 130-second hold")
                for tick in 1...13 {
                    try await until(maintained + .seconds(tick * 10))
                    let direct = try await context.isDirect(gate)
                    #expect(direct, "Item 7: both paths must be direct at \(tick * 10) seconds")
                    try await observations.requireEchoes(since: maintained)
                    note("Item 7: both sides direct and no echoes lost at \(tick * 10) seconds", since: maintained)
                }
                #expect(maintained.duration(to: .now) >= .seconds(130))
                note("Item 8: 0 inbound TSMP packets during the session, idle time, and rekey", since: maintained)
            }
        }
    }
    @Test("Item 5: a Go peer added after running sends first to establish a direct path")
    func goPeerInitiates() async throws {
        try await withGate(direct: false) { gate in
            let original = try await DirectContext.load(gate)
            await gate.tool.checkpoint("Item 5: immediately before adding a new Go peer after running")
            let event = try await gate.tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")
            let peer = try GatePeer(event)
            let fqdn: String = try #require(event.fqdn)
            let context = try await DirectContext.load(gate, name: "go-peer-b", fqdn: fqdn,
                                                       deadline: .now + .seconds(10))
            #expect(context.goEndpoint.port != original.goEndpoint.port)
            let started = ContinuousClock.now
            // The tool processes commands in order, so serialize sending and status queries in one Task as well.
            var nextSend = started
            try await wait("Item 5: both sides direct after Go sends first", from: started, for: .seconds(15)) {
                if ContinuousClock.now >= nextSend {
                    await gate.tool.checkpoint("Item 5: immediately before Go peerSend")
                    let sent = try await gate.tool.command(.init(cmd: "peerSend", name: "go-peer-b",
                        to: try gate.local.address().description, port: 42155, proto: "udp", payload: "4d34"), expecting: "peerSend")
                    #expect(sent.attempted == true && sent.sent == true && sent.error == "")
                    nextSend += .seconds(1)
                }
                return try await context.isDirect(gate, requiringLoopback: true)
            }
            let received = try await gate.packet("Item 5: UDP reception by the new Go peer") {
                $0.source == (try? peer.address()) && $0.proto == 17 && $0.destinationPort == 42155 && $0.payload == [0x4d, 0x34]
            }
            #expect(received.destination == (try gate.local.address()))
        }
    }
}

/// Checks that the endpoint is one Swift actually advertised, even if Go chose a LAN address.
private struct DirectContext: Sendable {
    let name: String
    let fqdn: String
    let goEndpoint: IPEndpoint
    let swiftEndpoints: Set<IPEndpoint>

    static func load(_ gate: Gate, name: String = "go-peer-a", fqdn: String? = nil,
                     deadline: ContinuousClock.Instant? = nil) async throws -> Self {
        let deadline = deadline ?? gate.runningAt + .seconds(10)
        var result: Self?
        try await wait("Item 1: nodes STUN endpoints and Go selfAddrs", deadline: deadline) {
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
        // Only items 2 and 5 of the contract specify a loopback address. Recovery and persistence check whether the path is direct.
        return !requiringLoopback || address == goEndpoint
    }

    func isRelayed(_ gate: Gate) async throws -> Bool {
        let status = try await status(gate)
        return await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1) && status.curAddr == ""
    }

    /// Records which side of the contract's condition failed without exposing actual interface addresses.
    func pathSummary(_ gate: Gate) async throws -> String {
        let status = try await status(gate)
        let swift: String
        switch await gate.node.path(toPeerNamed: fqdn) {
        case .direct(let endpoint):
            swift = "direct(Go loopback matches: \(endpoint == goEndpoint), Go port matches: \(endpoint.port == goEndpoint.port))"
        case .relayed(let region): swift = "relayed(\(region))"
        case nil: swift = "nil"
        }
        let advertised = status.curAddr.flatMap(IPEndpoint.init).map { swiftEndpoints.contains($0) } ?? false
        return "Swift \(swift), Go curAddr empty: \(status.curAddr == ""), matches a Swift-advertised address: \(advertised)"
    }
}

/// Collects packets and path events with one subscription to avoid resubscribing to a canceled AsyncStream.
private actor DirectObservations {
    private var paths: [(ContinuousClock.Instant, String, PeerPath?)] = []
    private var sent: [Int: ContinuousClock.Instant] = [:]
    private var received: Set<Int> = []
    private var nextSequence = 0
    private var paused = false
    private var lastSend = ContinuousClock.now

    func record(_ event: NodeEvent) {
        if case let .peerPathChanged(fqdn, path) = event { paths.append((.now, fqdn, path)) }
    }

    func record(_ bytes: [UInt8], gate: Gate) throws {
        // TSMP has no transport header. Check it before the UDP- and TCP-only ReceivedPacket parser.
        if bytes.count >= 20 && (bytes[0] >> 4 == 4 ? bytes[9] : bytes[6]) == 99 {
            throw GateFailure("Item 8: TSMP appeared in inboundPackets")
        }
        let packet = try ReceivedPacket(bytes)
        guard packet.proto == 17 && packet.destinationPort == 43040 else { return }
        let source = try gate.peer.address(), destination = try gate.local.address()
        #expect(packet.source == source && packet.destination == destination)
        #expect(packet.sourcePort == 7)
        guard packet.payload.count == 6, packet.payload.prefix(2) == [0x4d, 0x34] else {
            throw GateFailure("M4 echo payload mismatch")
        }
        let sequence = packet.payload.dropFirst(2).reduce(0) { $0 * 256 + Int($1) }
        #expect(sent[sequence] != nil, "Received an echo that was never sent")
        received.insert(sequence)
    }

    func send(gate: Gate) async throws {
        guard !paused else { return }
        let (sequence, bytes) = try makeEcho(gate)
        lastSend = .now
        sent[sequence] = lastSend
        await gate.node.send(bytes)
    }

    /// Sends one echo over the still-trusted path even if the periodic send task does not wake on time.
    func blockAndSend(_ gate: Gate, context: DirectContext) async throws -> (sequence: Int, at: ContinuousClock.Instant) {
        let (sequence, packet) = try makeEcho(gate)
        sent[sequence] = .now
        var blockedAt: ContinuousClock.Instant?
        try await wait("Item 3: direct path to block", deadline: .now + .seconds(10)) {
            blockedAt = await Self.blockAndSend(gate.node, context: context, packet: packet)
            return blockedAt != nil
        }
        let blocked = try #require(blockedAt)
        sent[sequence] = blocked
        return (sequence, blocked)
    }

    private static func blockAndSend(_ node: isolated TailnetNode, context: DirectContext,
                                     packet: [UInt8]) -> ContinuousClock.Instant? {
        guard case .direct(let endpoint) = node.path(toPeerNamed: context.fqdn),
              endpoint.port == context.goEndpoint.port else { return nil }
        // Keep node timers or other sends from intervening between observing the path, blocking it, and sending.
        node.setBlockedUDPPorts([endpoint.port])
        let blocked = ContinuousClock.now
        node.send(packet)
        return blocked
    }

    private func makeEcho(_ gate: Gate) throws -> (sequence: Int, packet: [UInt8]) {
        let sequence = nextSequence
        nextSequence += 1
        return (sequence, Packets.udp(from: try gate.local.address(), port: 43040, to: try gate.peer.address(),
                                      payload: [0x4d, 0x34] + Packets.long(UInt32(sequence))))
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
        try await wait("All replies to one-shot UDP echoes", from: through, for: .seconds(3)) {
            self.missing(since: since, before: through).isEmpty
        }
        #expect(sent.values.contains { $0 >= since && $0 < through }, "At least one echo must have been sent during the observation window")
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
            throw GateFailure("inboundPackets ended during M4 observation")
        }
        group.addTask {
            for await event in gate.node.events { await observations.record(event) }
            try Task.checkCancellation()
            throw GateFailure("events ended during M4 observation")
        }
        group.addTask {
            let started = ContinuousClock.now
            var tick = 0
            while true {
                try Task.checkCancellation()
                try await observations.send(gate: gate)
                tick += 1
                try await until(started + .seconds(tick))
            }
        }
        group.addTask { try await body(observations) }
        // Propagate observation Task failures immediately so TSMP leakage is caught.
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
    throw GateFailure("\(stage): timed out waiting for the condition")
}

private func until(_ instant: ContinuousClock.Instant) async throws {
    try await Task.sleep(until: instant, clock: .continuous)
}

private func note(_ stage: String, since start: ContinuousClock.Instant, at end: ContinuousClock.Instant = .now) {
    let line = "[M4 \(Date().ISO8601Format())] \(stage): +\(start.duration(to: end))\n"
    try? FileHandle.standardOutput.write(contentsOf: Data(line.utf8))
}
