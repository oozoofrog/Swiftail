import Foundation
import Network
import Swiftail
import SwiftailBase
import struct SwiftailBase.IPAddress
import SwiftailEngine
import Testing

@Suite("M5 in-memory tunnel gate", .enabled(if: tailnetBinary != nil,
    "Skipping M5 gate tests because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(4)))
struct TunnelTests {
    @Test("Test DNS parser covers compression, truncation, and cycles")
    func dnsDecoderBoundaries() throws {
        var response = try TunnelDNS.query(id: 0x3500, name: "peer.tail0001.test.", type: 1)
        response[2] = 0x85
        response[7] = 1
        response += [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 100, 64, 0, 2]
        let decoded = try TunnelDNS(response)
        #expect(decoded.answers.first?.data == [100, 64, 0, 2])
        for length in 0..<response.count {
            #expect(throws: GateFailure.self) { try TunnelDNS(Array(response.prefix(length))) }
        }
        var loop: [UInt8] = [0x35, 0, 0x85, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        loop += [0xc0, 0x0c, 0, 1, 0, 1]
        #expect(throws: GateFailure.self) { try TunnelDNS(loop) }
    }

    @Test("Settings, UDP, TCP, MagicDNS, and local handling of service IPs")
    func dataPathAndLocalServices() async throws {
        try await withTunnelGate { gate in
            let started = ContinuousClock.now
            let settings = try await nextEvent(gate.node.networkSettings, waitingFor: "M5 initial settings")
            let status = await gate.node.status
            let source = try gate.local.address(), destination = try gate.peer.address()
            #expect(settings.addresses.contains { $0.address == source && $0.length == 32 })
            #expect(settings.routes.contains { $0.address == destination && $0.length == 32 })
            #expect(settings.dnsServers.first == IPAddress("100.100.100.100"))
            #expect(settings.dnsMatchDomains.contains("tail0001.test"))
            #expect(settings.dnsMatchDomains.allSatisfy { !$0.hasSuffix(".") })
            #expect(settings.mtu == 1280 && status.networkSettings == settings && status.peerCount >= 1)
            await gate.tool.checkpoint("M5 network-settings observed: \(settings.addresses.count) addresses, \(settings.routes.count) routes, \(settings.dnsServers.count) DNS servers, \(settings.dnsMatchDomains.count) match domains, MTU \(settings.mtu)")

            try await gate.echo(port: 43500, payload: [0x4d, 0x35, 0x01])
            let syn = Packets.syn(from: source, port: 43501, to: destination, destinationPort: 7, sequence: 0x12345678)
            let tcp = try await gate.packet("M5 TCP SYN-ACK", retransmitting: syn) { $0.proto == 6 && $0.destinationPort == 43501 }
            #expect(tcp.flags & 0x16 == 0x12 && tcp.acknowledgement == 0x12345679)
            #expect(tcp.source == destination && tcp.destination == source && tcp.sourcePort == 7)
            await gate.tool.checkpoint("M5 udp and tcp: verified echo payload and SYN-ACK")

            _ = try await gate.tool.command(.init(cmd: "startCapture", name: "go-peer-a"), expecting: "captureStarted")
            // First verify that the capture sees normal UDP, so zero service IP packets is meaningful evidence.
            try await gate.echo(port: 43502, payload: [0x4d, 0x35, 0x02])
            try await waitForTunnel("capture positive control") {
                let capture = try await gate.tool.command(.init(cmd: "captureStatus", name: "go-peer-a", port: 43502), expecting: "captureStatus")
                return (capture.observedPackets ?? 0) > 0
            }
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let fqdn = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
            let reverse = destination.bytes.reversed().map(String.init).joined(separator: ".") + ".in-addr.arpa."
            for ipv4 in [true, false] {
                let service = try #require(IPAddress(ipv4 ? "100.100.100.100" : "fd7a:115c:a1e0::53"))
                let local = try gate.local.address(ipv4: ipv4)
                for (index, name, type, rcode) in [
                    (0, fqdn, UInt16(1), UInt16(0)),
                    (1, fqdn, UInt16(28), UInt16(0)),
                    (2, reverse, UInt16(12), UInt16(0)),
                    (3, "unknown-m5.tail0001.test.", UInt16(1), UInt16(3)),
                    (4, "example.com.", UInt16(1), UInt16(2))
                ] {
                    let id = UInt16(0x3500 + index + (ipv4 ? 0 : 16))
                    let port = UInt16(43510 + index + (ipv4 ? 0 : 16))
                    let query = try TunnelDNS.query(id: id, name: name, type: type)
                    let bytes = Packets.udp(from: local, port: port, to: service, destinationPort: 53, payload: query)
                    let reply = try await gate.packet("M5 DNS \(ipv4 ? "IPv4" : "IPv6") type \(type), item \(index)", retransmitting: bytes) {
                        $0.proto == 17 && $0.destinationPort == port
                    }
                    #expect(reply.source == service && reply.destination == local && reply.sourcePort == 53)
                    let dns = try TunnelDNS(reply.payload)
                    #expect(dns.id == id && dns.flags & 0x8000 != 0)
                    #expect(dns.flags & 15 == rcode, "Address family \(ipv4 ? 4 : 6), DNS item \(index)")
                    await gate.tool.checkpoint("M5 DNS family \(ipv4 ? 4 : 6), type \(type): rcode \(dns.flags & 15), \(dns.answers.count) answers, authority types \(dns.authorities.map(\.type)), TTL \(dns.authorities.map(\.ttl))")
                    #expect(dns.questionName.lowercased() == normalizedDNSName(name) && dns.questionType == type)
                    switch index {
                    case 0:
                        #expect(dns.answers.count == 1)
                        #expect(dns.answers.first?.type == 1 && dns.answers.first?.data == destination.bytes)
                        #expect(dns.answers.first?.ttl == 5)
                    case 1:
                        #expect(dns.answers.isEmpty && dns.authorities.contains { $0.type == 6 && $0.ttl == 10 })
                    case 2:
                        #expect(dns.answers.count == 1 && dns.answers.first?.type == 12)
                        #expect(dns.answers.first?.nameData?.lowercased() == normalizedDNSName(fqdn))
                    case 3:
                        #expect(dns.answers.isEmpty && dns.authorities.contains { $0.type == 6 })
                    default: #expect(dns.answers.isEmpty)
                    }
                }
                try await checkLocalEcho(gate.node, source: local, service: service)
                let reset = try await gate.packet("M5 service TCP 53 RST", retransmitting:
                    Packets.syn(from: local, port: 43540, to: service, destinationPort: 53, sequence: 0xffffffff)) {
                        $0.proto == 6 && $0.destinationPort == 43540
                    }
                #expect(reset.source == service && reset.destination == local && reset.sourcePort == 53)
                #expect(reset.flags == 0x14 && reset.sequence == 0 && reset.acknowledgement == 0)
            }
            // Confirm that the capture read through the subsequent normal packet before checking for absence across the whole capture.
            try await gate.echo(port: 43503, payload: [0x4d, 0x35, 0x03])
            try await waitForTunnel("capture follow-up boundary") {
                let capture = try await gate.tool.command(.init(cmd: "captureStatus", name: "go-peer-a", port: 43503), expecting: "captureStatus")
                #expect(capture.servicePackets == 0, "Service IP packets must not reach the Go peer")
                return (capture.observedPackets ?? 0) > 0
            }
            await gate.tool.checkpoint("M5 magicdns observation complete: 10 queries across both families, ICMP and RST, 0 Go service packets, elapsed \(started.duration(to: .now))")
        }
    }

    @Test("Cancellation and device closure: run result, all three streams end, and no sends after stop", arguments: [false, true])
    func termination(deviceFailure: Bool) async throws {
        try await withTunnelLab { tool, root, control in
            _ = try await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer")
            try await withTunnelRun(root.appending(path: "node"), control: control) { node, run in
                let addresses = try await running(node)
                let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
                let local = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) })
                let peer = try #require(nodes.first { $0.nodeKey != local.nodeKey })
                let gate = Gate(tool: tool, node: node, local: .init(key: local.nodeKey, addresses: addresses),
                    peer: .init(key: peer.nodeKey, addresses: try peer.addresses.map { try #require(IPAddress($0)) }), witness: nil, runningAt: .now)
                try await gate.echo(port: 43550, payload: [0x35, 0x50])
                let streams = TunnelStreamEnds()
                let readers = [
                    Task { for await _ in node.events { await streams.received() }; await streams.ended() },
                    Task { for await _ in node.networkSettings { await streams.received() }; await streams.ended() },
                    Task { for await _ in node.inboundPackets { await streams.received() }; await streams.ended() }
                ]
                let stopped = ContinuousClock.now
                if deviceFailure { await node.failMemoryDevice() } else { run.task.cancel() }
                let result = try await nextEvent(run.completion, waitingFor: "M5 run completion", timeout: .seconds(10))
                switch result {
                case .success: #expect(!deviceFailure, "Device closure must yield tunnelDeviceClosed")
                case .failure(.tunnelDeviceClosed(let message)):
                    #expect(deviceFailure && message == "test")
                case .failure: Issue.record("Unexpected run failure type")
                }
                try await waitForTunnel("M5 all three streams ending", timeout: .seconds(5)) { await streams.endCount == 3 }
                for reader in readers { await reader.value }
                let count = await streams.valueCount
                let before = try await lastWrite(tool, key: local.nodeKey)
                let finalSettings = await node.status.networkSettings
                let until = ContinuousClock.now + .seconds(2)
                while ContinuousClock.now < until {
                    await node.send(Packets.udp(from: try gate.local.address(), port: 43551, to: try gate.peer.address(), payload: [0x35, 0x51]))
                    await node.startInteractiveLogin()
                    #expect(try await lastWrite(tool, key: local.nodeKey) == before)
                    #expect(await streams.valueCount == count)
                    #expect(await streams.endCount == 3)
                    #expect(await node.status.networkSettings == finalSettings)
                    try await Task.sleep(for: .milliseconds(100))
                }
                await tool.checkpoint("M5 \(deviceFailure ? "engine-death tunnelDeviceClosed(test)" : "stop returned normally"): three streams ended, lastWrite unchanged for 2 seconds, 0 additional events, elapsed \(stopped.duration(to: .now))")
            }
        }
    }

    @Test("Identity with the same, new, and moved directories, and release of exclusive ownership")
    func restartAndDirectoryClaims() async throws {
        try await withTunnelLab { tool, root, control in
            let original = root.appending(path: "original"), fresh = root.appending(path: "fresh"), moved = root.appending(path: "moved")
            var originalAddresses: [IPAddress] = []
            var stableID: String?
            try await withTunnelRun(original, control: control) { first, _ in
                originalAddresses = try await running(first)
                stableID = await first.status.stableID
                #expect(stableID != nil)
                #expect(FileManager.default.fileExists(atPath: original.appending(path: "identity.json").path))
                try await withTunnelRun(original, control: control) { _, second in
                    let result = try await nextEvent(second.completion, waitingFor: "M5 duplicate state directory", timeout: .seconds(5))
                    guard case .failure(.stateDirectoryInUse) = result else {
                        throw GateFailure("M5 did not reject the same directory with stateDirectoryInUse")
                    }
                }
                try await withTunnelRun(fresh, control: control) { other, _ in
                    let different = try await running(other)
                    #expect(Set(different).isDisjoint(with: originalAddresses))
                }
            }
            try await withTunnelRun(original, control: control) { restarted, _ in
                let addresses = try await running(restarted)
                #expect(Set(addresses) == Set(originalAddresses))
                #expect(await restarted.status.stableID == stableID)
            }
            try FileManager.default.moveItem(at: original, to: moved)
            try await withTunnelRun(moved, control: control) { relocated, _ in
                let addresses = try await running(relocated)
                #expect(Set(addresses) == Set(originalAddresses))
                #expect(await relocated.status.stableID == stableID)
            }
            await tool.checkpoint("M5 restart and in-use: identity.json created, address and StableID retained for the same and moved directories, new address distinct, duplicate rejected, ownership released after stop, 0 needsLogin")
        }
    }

    @Test("Invalid utun and MTU are rejected in init without creating a state file")
    func invalidConfiguration() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "swiftail-m5-invalid-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let pipe = Pipe()
        defer { try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close() }
        let devices: [TunnelDevice] = [.utun(fileDescriptor: -1), .utun(fileDescriptor: pipe.fileHandleForReading.fileDescriptor)]
            + [1, 1000, 1279, 1421, 1500, 9000, -1280].map { .memory(mtu: $0) }
        for (index, device) in devices.enumerated() {
            let directory = root.appending(path: "case-\(index)")
            do {
                _ = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d"), device: device)
                Issue.record("Invalid device or MTU passed init: item \(index)")
            } catch .invalidConfiguration(let message) {
                if index >= 2 { #expect(message.localizedCaseInsensitiveContains("MTU")) }
            } catch { Issue.record("Invalid configuration returned an error other than invalidConfiguration") }
            #expect(!FileManager.default.fileExists(atPath: directory.path))
            #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
        }
    }

    @Test("Starts with MTU 1280, 1420, and the default, and reports each in settings")
    func mtuBounds() async throws {
        try await withTunnelLab { tool, root, control in
            for (index, device, mtu) in [(0, TunnelDevice.memory(mtu: 1280), 1280), (1, .memory(mtu: 1420), 1420), (2, .memory(), 1280)] {
                try await withTunnelRun(root.appending(path: "mtu-\(index)"), control: control, device: device) { node, _ in
                    _ = try await running(node)
                    let settings = try await nextEvent(node.networkSettings, waitingFor: "M5 MTU settings")
                    #expect(settings.mtu == mtu)
                    #expect(await node.status.networkSettings?.mtu == mtu)
                }
            }
            await tool.checkpoint("M5 mtu-bounds: 1280, 1420, and default 1280 started and matched settings")
        }
    }

    @Test("Rebinding to a real interface and reevaluating the same interface")
    func defaultInterfaceAndReevaluation() async throws {
        let monitor = NWPathMonitor()
        let (interfaces, continuation) = AsyncStream.makeStream(of: NWInterface.self, bufferingPolicy: .bufferingNewest(1))
        monitor.pathUpdateHandler = { path in
            if path.status == .satisfied, let interface = path.availableInterfaces.first(where: { path.usesInterfaceType($0.type) }) {
                continuation.yield(interface)
            }
        }
        monitor.start(queue: DispatchQueue(label: "swiftail.m5.path"))
        defer { monitor.cancel(); continuation.finish() }
        let interface = try await nextEvent(interfaces, waitingFor: "real interface with a satisfied path", timeout: .seconds(10))
        try await withGate { gate in
            let beforeEndpoints = try await tunnelEndpoints(gate)
            let ports = Set(beforeEndpoints.map(\.port))
            let before = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            let started = ContinuousClock.now
            await gate.node.setDefaultInterface(interface)
            try await waitForTunnel("M5 interface control and DERP reconnections, and STUN", timeout: .seconds(15)) {
                let after = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                return (after.controlConnections ?? 0) > (before.controlConnections ?? 0)
                    && (after.derpConnections ?? 0) > (before.derpConnections ?? 0)
                    && (after.stunRequests ?? 0) > (before.stunRequests ?? 0)
            }
            // An echo must still arrive with UDP blocked to demonstrate data-plane recovery through the new DERP connection.
            let peerStatus = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
            let peerPorts = Set((peerStatus.selfAddrs ?? []).compactMap(IPEndpoint.init).map(\.port))
            #expect(!peerPorts.isEmpty)
            await gate.node.setBlockedUDPPorts(peerPorts)
            try await gate.echo(port: 43560, payload: [0x35, 0x60])
            await gate.node.setBlockedUDPPorts([])
            try await waitForTunnel("M5 direct paths on both sides after rebinding", timeout: .seconds(15)) {
                try await gate.echo(port: 43561, payload: [0x35, 0x61])
                return try await tunnelIsDirect(gate, ports: ports)
            }
            #expect(Set(try await tunnelEndpoints(gate).map(\.port)) == ports, "UDP ports must be preserved")
            await gate.tool.checkpoint("M5 setDefaultInterface: ports preserved, endpoints observed, control and DERP connections increased, STUN increased, relayed echo, both sides direct again, elapsed \(started.duration(to: .now))")
            let settled = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            let repeated = ContinuousClock.now
            await gate.node.setDefaultInterface(interface)
            try await waitForTunnel("M5 STUN reevaluation on the same interface", timeout: .seconds(15)) {
                let after = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                return (after.stunRequests ?? 0) > (settled.stunRequests ?? 0)
            }
            try await gate.echo(port: 43562, payload: [0x35, 0x62])
            #expect(try await tunnelIsDirect(gate, ports: ports))
            let reevaluated = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            #expect(reevaluated.controlConnections == settled.controlConnections)
            #expect(reevaluated.derpConnections == settled.derpConnections)
            await gate.tool.checkpoint("M5 reevaluates: STUN increased on the same interface, no control or DERP reconnection, ports preserved, direct echo, elapsed \(repeated.duration(to: .now))")
        }
    }

    @Test("Recovers to starting and running after completing the interactive authentication URL")
    func interactiveLogin() async throws {
        try await withTunnelLab { tool, root, control in
            _ = try await tool.command(.init(cmd: "setAuth", requireAuth: true), expecting: "auth")
            try await withTunnelRun(root.appending(path: "login"), control: control) { node, _ in
                let started = ContinuousClock.now
                let url: URL = try await withThrowingTaskGroup(of: URL.self) { group in
                    defer { group.cancelAll() }
                    group.addTask {
                        for await event in node.events {
                            if case .stateChanged(.needsLogin(let url)) = event { return url }
                            if case .stateChanged(.running) = event { throw GateFailure("Reached running before authentication completed") }
                        }
                        throw GateFailure("Event stream ended before needsLogin")
                    }
                    group.addTask { try await Task.sleep(for: .seconds(25)); throw GateFailure("Timed out after 25 seconds waiting for needsLogin") }
                    return try #require(try await group.next())
                }
                #expect(await node.status.state == .needsLogin(url))
                _ = try await tool.command(.init(cmd: "setAuth", authURL: url), expecting: "auth")
                var states: [NodeState] = []
                let deadline = ContinuousClock.now + .seconds(25)
                while states.last != .running {
                    let event = try await nextEvent(node.events, waitingFor: "state after login completion", timeout: ContinuousClock.now.duration(to: deadline))
                    if case .stateChanged(let state) = event { states.append(state) }
                }
                #expect(states == [.starting, .running])
                #expect(await node.status.addresses.isEmpty == false)
                await tool.checkpoint("M5 interactive-login: needsLogin(URL) → starting → running, URL omitted from logs, elapsed \(started.duration(to: .now))")
            }
        }
    }
}

private func waitForTunnel(_ stage: String, timeout: Duration = .seconds(10),
                           condition: () async throws -> Bool) async throws {
    let started = ContinuousClock.now
    let deadline = started + timeout
    while true {
        let matched = try await condition()
        guard ContinuousClock.now <= deadline else { throw GateFailure("\(stage): timeout \(timeout), observed for \(started.duration(to: .now))") }
        if matched { return }
        try await Task.sleep(for: .milliseconds(50))
    }
}

private struct TunnelRun: Sendable {
    let task: Task<Void, Never>
    let completion: AsyncStream<Result<Void, NodeError>>

    init(_ node: TailnetNode) {
        let (completion, continuation) = AsyncStream.makeStream(of: Result<Void, NodeError>.self)
        self.completion = completion
        task = Task {
            do throws(NodeError) { try await node.run(); continuation.yield(.success(())) }
            catch { continuation.yield(.failure(error)) }
            continuation.finish()
        }
    }
}

private func withTunnelRun(_ directory: URL, control: URL, device: TunnelDevice = .memory(),
                           body: (TailnetNode, TunnelRun) async throws -> Void) async throws {
    let node = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: control), device: device)
    let run = TunnelRun(node)
    do { try await body(node, run) }
    catch { run.task.cancel(); await run.task.value; throw error }
    run.task.cancel()
    await run.task.value
}

private func withTunnelLab(_ body: (GoTailnet, URL, URL) async throws -> Void) async throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "swiftail-m5-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let tool = GoTailnet(temporaryDirectory: root)
    defer {
        do { try FileManager.default.removeItem(at: root) }
        catch { Issue.record("Could not clean up M5 temporary state") }
    }
    do {
        let ready = try await tool.start()
        try await body(tool, root, try #require(ready.controlURL))
        await tool.stop()
    } catch {
        await tool.stop()
        throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
    }
}


/// Starts with a DNS-enabled control map. The tool's name suffix alone does not create DNSConfig.
private func withTunnelGate(_ body: (Gate) async throws -> Void) async throws {
    try await withTunnelLab { tool, root, control in
        _ = try await tool.command(.init(cmd: "setMagicDNS", enabled: true), expecting: "magicDNS")
        let peer = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer"))
        try await withTunnelRun(root.appending(path: "node"), control: control) { node, _ in
            let addresses = try await running(node)
            let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let local = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) })
            let gate = Gate(tool: tool, node: node, local: .init(key: local.nodeKey, addresses: addresses),
                peer: peer, witness: nil, runningAt: .now)
            try await gate.prepareDirectPath()
            try await body(gate)
        }
    }
}

private actor TunnelStreamEnds {
    var valueCount = 0
    var endCount = 0
    func received() { valueCount += 1 }
    func ended() { endCount += 1 }
}

private func lastWrite(_ tool: GoTailnet, key: String) async throws -> String {
    let status = try await tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
    return try #require(status.peers?.first { $0.nodeKey == key }?.lastWrite)
}

private func tunnelEndpoints(_ gate: Gate) async throws -> Set<IPEndpoint> {
    let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
    let local = try #require(nodes.first { $0.nodeKey == gate.local.key })
    let endpoints = Set((local.endpoints ?? []).compactMap(IPEndpoint.init))
    guard !endpoints.isEmpty else { throw GateFailure("M5 nodes returned no local endpoints") }
    return endpoints
}

private func tunnelIsDirect(_ gate: Gate, ports: Set<UInt16>) async throws -> Bool {
    let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
    let fqdn = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
    let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
    guard let peer = status.peers?.first(where: { $0.nodeKey == gate.local.key }),
          let endpoint = peer.curAddr.flatMap(IPEndpoint.init), ports.contains(endpoint.port),
          let loopback = status.selfAddrs?.compactMap(IPEndpoint.init).first(where: { $0.address == IPAddress("127.0.0.1") }),
          case .direct(let swiftEndpoint) = await gate.node.path(toPeerNamed: fqdn), swiftEndpoint == loopback else { return false }
    return try await tunnelEndpoints(gate).contains(endpoint)
}

private func checkLocalEcho(_ node: TailnetNode, source: IPAddress, service: IPAddress) async throws {
    let ipv4 = source.isIPv4
    var transport: [UInt8] = [ipv4 ? 8 : 128, 0, 0, 0, 0x12, 0x34, 0, 7, 0x4d, 0x35, 0xff]
    let pseudo = ipv4 ? [] : Packets.pseudoHeader(source, service, 58, transport.count)
    transport.replaceSubrange(2..<4, with: Packets.word(Packets.checksum(pseudo + transport)))
    let request: [UInt8]
    if ipv4 {
        var header: [UInt8] = [0x45, 0] + Packets.word(UInt16(20 + transport.count)) + [0, 0, 0, 0, 64, 1, 0, 0] + source.bytes + service.bytes
        header.replaceSubrange(10..<12, with: Packets.word(Packets.checksum(header)))
        request = header + transport
    } else {
        request = [0x60, 0, 0, 0] + Packets.word(UInt16(transport.count)) + [58, 64] + source.bytes + service.bytes + transport
    }
    await node.send(request)
    let reply = try await nextEvent(node.inboundPackets, waitingFor: "M5 service ICMP echo reply")
    let offset = ipv4 ? 20 : 40
    guard reply.count == offset + transport.count else { throw GateFailure("M5 ICMP response length mismatch") }
    #expect(reply[0] >> 4 == (ipv4 ? 4 : 6) && reply[ipv4 ? 9 : 6] == (ipv4 ? 1 : 58))
    #expect(reply[ipv4 ? 8 : 7] == 64)
    #expect(Array(reply[(ipv4 ? 12 : 8)..<(ipv4 ? 16 : 24)]) == service.bytes)
    #expect(Array(reply[(ipv4 ? 16 : 24)..<offset]) == source.bytes)
    let body = Array(reply[offset...])
    #expect(body[0] == (ipv4 ? 0 : 129) && body[1] == 0 && body.dropFirst(4) == transport.dropFirst(4))
    #expect(Packets.checksum((ipv4 ? [] : Packets.pseudoHeader(service, source, 58, body.count)) + body) == 0)
    if ipv4 { #expect(Packets.checksum(Array(reply[..<offset])) == 0) }
}

private func normalizedDNSName(_ name: String) -> String {
    (name.hasSuffix(".") ? name : name + ".").lowercased()
}

/// Reads RFC 1035 header, question, and RR boundaries independently. Does not use the library's DNS codec.
private struct TunnelDNS {
    struct Record {
        let type: UInt16
        let ttl: UInt32
        let data: [UInt8]
        let nameData: String?
    }
    let id: UInt16
    let flags: UInt16
    let questionName: String
    let questionType: UInt16
    let answers: [Record]
    let authorities: [Record]

    static func query(id: UInt16, name: String, type: UInt16) throws -> [UInt8] {
        let labels = normalizedDNSName(name).dropLast().split(separator: ".")
        guard !labels.isEmpty, labels.allSatisfy({ (1...63).contains($0.utf8.count) }) else { throw GateFailure("Invalid test DNS name boundaries") }
        var encoded: [UInt8] = []
        for label in labels { encoded.append(UInt8(label.utf8.count)); encoded.append(contentsOf: label.utf8) }
        encoded.append(0)
        guard encoded.count <= 255 else { throw GateFailure("Test DNS name exceeds the length limit") }
        let header: [UInt8] = Packets.word(id) + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        return header + encoded + Packets.word(type) + [0, 1]
    }

    init(_ bytes: [UInt8]) throws {
        var reader = DNSReader(bytes: bytes)
        id = try reader.word(); flags = try reader.word()
        let questions = try reader.word(), answerCount = try reader.word(), authorityCount = try reader.word(), additionalCount = try reader.word()
        guard questions == 1 else { throw GateFailure("DNS question count is not 1") }
        questionName = try reader.name(); questionType = try reader.word()
        guard try reader.word() == 1 else { throw GateFailure("DNS question class is not IN") }
        answers = try (0..<Int(answerCount)).map { _ in try reader.record() }
        authorities = try (0..<Int(authorityCount)).map { _ in try reader.record() }
        for _ in 0..<Int(additionalCount) { _ = try reader.record() }
        guard reader.offset == bytes.count else { throw GateFailure("Unparsed bytes after the DNS message") }
    }
}

private struct DNSReader {
    let bytes: [UInt8]
    var offset = 0

    mutating func take(_ count: Int) throws -> [UInt8] {
        guard count >= 0, offset <= bytes.count, count <= bytes.count - offset else { throw GateFailure("Truncated DNS field") }
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }
    mutating func word() throws -> UInt16 {
        let data = try take(2)
        return UInt16(data[0]) << 8 | UInt16(data[1])
    }
    mutating func name() throws -> String {
        var cursor = offset, end: Int?, labels: [String] = [], visited: Set<Int> = []
        var wireLength = 1
        while true {
            guard cursor < bytes.count, visited.insert(cursor).inserted else { throw GateFailure("DNS name out of bounds or pointer cycle") }
            let count = Int(bytes[cursor])
            if count == 0 { offset = end ?? cursor + 1; return labels.joined(separator: ".") + "." }
            if count & 0xc0 == 0xc0 {
                guard cursor + 1 < bytes.count, visited.count <= 128 else { throw GateFailure("DNS pointer exceeds bounds") }
                end = end ?? cursor + 2
                cursor = (count & 0x3f) << 8 | Int(bytes[cursor + 1])
                continue
            }
            guard count <= 63, cursor + 1 + count <= bytes.count else { throw GateFailure("Invalid DNS label boundaries") }
            wireLength += count + 1
            guard wireLength <= 255, let label = String(bytes: bytes[(cursor + 1)..<(cursor + 1 + count)], encoding: .ascii) else {
                throw GateFailure("Invalid DNS label length or ASCII")
            }
            labels.append(label); cursor += count + 1
        }
    }
    mutating func record() throws -> TunnelDNS.Record {
        _ = try name()
        let type = try word(), recordClass = try word(), high = try word(), low = try word(), length = Int(try word())
        guard recordClass == 1 else { throw GateFailure("DNS RR class is not IN") }
        let start = offset
        let data = try take(length)
        var nameData: String?
        if type == 12 {
            var rdata = DNSReader(bytes: bytes, offset: start)
            nameData = try rdata.name()
            guard rdata.offset == offset else { throw GateFailure("PTR RDATA length mismatch") }
        }
        return .init(type: type, ttl: UInt32(high) << 16 | UInt32(low), data: data, nameData: nameData)
    }
}
