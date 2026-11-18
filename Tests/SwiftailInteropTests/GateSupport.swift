// Origin of testcontrol address and ID rules: tailscale.com v1.104.6, tstest/integration/testcontrol/testcontrol.go.
// Copyright (c) Tailscale Inc & contributors; SPDX-License-Identifier: BSD-3-Clause.
import Foundation
import SwiftailBase
import Swiftail
import Testing

let tailnetBinary = ProcessInfo.processInfo.environment["SWIFTAIL_TAILNET"].flatMap { $0.isEmpty ? nil : $0 }

struct GateFailure: Error, Sendable, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Races an event against a deadline. A timeout ends the test, so the canceled subscription is not reused.
func nextEvent<T: Sendable>(
    _ stream: AsyncStream<T>, waitingFor description: String, timeout: Duration = .seconds(20)
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        defer { group.cancelAll() }
        group.addTask {
            for await event in stream { return event }
            throw GateFailure("Event stream ended while waiting for \(description)")
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw GateFailure("Timed out waiting for \(description) (\(timeout))")
        }
        guard let event = try await group.next() else { throw GateFailure("No event for \(description)") }
        return event
    }
}

/// Keeps private keys, auth keys, and user paths out of the report even if they appear in external tool diagnostics.
func redacted(_ text: String) -> String {
    var result = text
    for pattern in [#"(?:privkey|nodekey|discokey|mkey):[0-9a-fA-F]+"#, #"tskey-[A-Za-z0-9_-]+"#,
                    #"/Users/[^\s\"']+"#, #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#] {
        result = result.replacingOccurrences(of: pattern, with: "<redacted>", options: .regularExpression)
    }
    return result
}

/// Node contains only the fields needed to verify an injection through public state (`status.addresses`).
struct MapInjection: Encodable, Sendable {
    struct Node: Encodable, Sendable {
        let ID: Int64
        let Key: String
        let Name: String
        let Addresses: [String]
        let AllowedIPs: [String]
        let HomeDERP: Int64
        var MachineAuthorized = true
    }
    struct Rule: Encodable, Sendable {
        struct Destination: Encodable, Sendable {
            struct Ports: Encodable, Sendable { let First: UInt16; let Last: UInt16 }
            let IP: String
            let Ports: Ports
        }
        let SrcIPs: [String]
        let IPProto: [Int]
        let DstPorts: [Destination]
    }
    var Node: Node? = nil
    var PeersChanged: [Node]? = nil
    var PeersRemoved: [Int64]? = nil
    var PacketFilter: [Rule]? = nil
    var PacketFilters: [String: [Rule]]? = nil
}

struct GatePeer: Sendable {
    let key: String
    let addresses: [IPAddress]

    init(key: String, addresses: [IPAddress]) {
        self.key = key
        self.addresses = addresses
    }

    init(_ event: GoTailnet.Event) throws {
        self.init(key: try #require(event.nodeKey),
                  addresses: try #require(event.addresses).map { try #require(IPAddress($0)) })
        #expect(addresses.count == 2)
    }

    func address(ipv4: Bool = true) throws -> IPAddress {
        try #require(addresses.first { $0.isIPv4 == ipv4 })
    }

    /// The registration code in testcontrol.go assigns 100.64.(n>>8).n to ID n (v1.104.6).
    /// The existing nodes command does not return IDs, so this rule goes here only and is specific to this test server.
    var mapNode: MapInjection.Node {
        get throws {
            let ip = try address()
            guard ip.bytes[0] == 100, ip.bytes[1] == 64 else { throw GateFailure("testcontrol address assignment rule changed") }
            let prefixes = addresses.map { "\($0)/\($0.isIPv4 ? 32 : 128)" }
            return .init(ID: Int64(ip.bytes[2]) << 8 | Int64(ip.bytes[3]), Key: key,
                         Name: "rd-mac-1a2b3c4d.tail0001.test.", Addresses: prefixes, AllowedIPs: prefixes, HomeDERP: 1)
        }
    }
}

struct Gate: Sendable {
    let tool: GoTailnet
    let node: TailnetNode
    let local: GatePeer
    let peer: GatePeer
    let witness: GatePeer?
    let runningAt: ContinuousClock.Instant
    var controlURL: URL? = nil

    /// Uses the existing M3 tests as an M4 regression gate by starting their bodies after the direct path is established.
    func prepareDirectPath() async throws {
        let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
        let fqdn = try #require(nodes.first { $0.nodeKey == peer.key }?.name)
        let deadline = ContinuousClock.now + .seconds(15)
        while ContinuousClock.now < deadline {
            try await echo(payload: [0x4d, 0x33])
            let status = try await tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
            if case .direct = await node.path(toPeerNamed: fqdn),
               status.peers?.first(where: { $0.nodeKey == local.key })?.curAddr?.isEmpty == false {
                // The path queried by stable ID must match the path queried by name.
                let stableID = try #require(await node.whoIs(try peer.address())?.stableID)
                #expect(await node.path(toPeerWithStableID: stableID) == node.path(toPeerNamed: fqdn))
                #expect(await node.path(toPeerWithStableID: stableID + "-없는-피어") == nil)
                await tool.checkpoint("Item 9: verified direct paths on both sides before starting the M3 body")
                return
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw GateFailure("Item 9: 15-second timeout for direct paths before starting the M3 body")
    }

    /// Includes a local address marker in the same response to verify that the ACL and peer deltas have been applied.
    /// Preserves the original test addresses, and data packets do not use the marker address.
    func inject(_ response: MapInjection, marker: UInt8) async throws {
        var response = response
        let original = try local.mapNode
        let markerAddress = try #require(IPAddress("100.64.254.\(marker)"))
        response.Node = .init(ID: original.ID, Key: original.Key, Name: original.Name,
                              Addresses: original.Addresses + ["\(markerAddress)/32"],
                              AllowedIPs: original.AllowedIPs + ["\(markerAddress)/32"], HomeDERP: 1)
        try await tool.inject(response, into: local.key)
        _ = try await running(node, containing: markerAddress)
    }

    func sendFromGo(proto: String, port: UInt16, payload: [UInt8]) async throws {
        let event = try await tool.command(.init(cmd: "peerSend", name: "go-peer-a",
            to: try local.address().description, port: port, proto: proto, payload: payload.hex), expecting: "peerSend")
        #expect(event.attempted == true)
        if proto == "udp" {
            guard event.sent == true, event.error == "" else {
                throw GateFailure("Go UDP write failed: \(redacted(event.error ?? "no error"))")
            }
        } else {
            #expect(event.sent == false, "Swift has no TCP stack, so the connection must not be established")
            #expect(event.error?.isEmpty == false, "A TCP timeout or connection error must occur")
        }
    }

    func echo(ipv4: Bool = true, port: UInt16 = 43000, payload: [UInt8], peer target: GatePeer? = nil,
              rejecting forbidden: @escaping @Sendable (ReceivedPacket) -> Bool = { _ in false }) async throws {
        let target = target ?? peer
        let source = try local.address(ipv4: ipv4), destination = try target.address(ipv4: ipv4)
        let bytes = Packets.udp(from: source, port: port, to: destination, payload: payload)
        let reply = try await packet("\(ipv4 ? "IPv4" : "IPv6") UDP echo (destination port 7, reply port \(port))",
            retransmitting: bytes, rejecting: forbidden) {
                $0.proto == 17 && $0.destinationPort == port && $0.payload == payload
            }
        #expect(reply.source == destination && reply.destination == source, "The echo addresses must be reversed")
        #expect(reply.sourcePort == 7 && reply.destinationPort == port, "The echo ports must be reversed")
        #expect(reply.payload == payload)
    }

    /// Waits with one subscription. The retransmission timer does not cancel observation, allowing for initial DERP loss.
    func packet(_ stage: String, retransmitting bytes: [UInt8]? = nil,
                rejecting forbidden: @escaping @Sendable (ReceivedPacket) -> Bool = { _ in false },
                matching predicate: @escaping @Sendable (ReceivedPacket) -> Bool) async throws -> ReceivedPacket {
        try await withThrowingTaskGroup(of: ReceivedPacket.self) { group in
            defer { group.cancelAll() }
            group.addTask {
                for await bytes in node.inboundPackets {
                    let packet = try ReceivedPacket(bytes)
                    if forbidden(packet) {
                        throw GateFailure("\(stage): forbidden packet arrived in inboundPackets (protocol \(packet.proto), destination port \(packet.destinationPort))")
                    }
                    if predicate(packet) { return packet }
                }
                throw GateFailure("\(stage): inboundPackets ended")
            }
            group.addTask {
                try await Task.sleep(for: .seconds(25))
                throw GateFailure("\(stage): timed out after 25 seconds waiting for a packet")
            }
            if let bytes {
                group.addTask {
                    while true {
                        try Task.checkCancellation()
                        await node.send(bytes)
                        try await Task.sleep(for: .seconds(1))
                    }
                }
            }
            return try #require(try await group.next())
        }
    }
}

/// Waits for the first running state and returns the node's addresses. If `marker` is supplied, waits for it to appear among those addresses.
///
/// Starting with M5, addresses are read from `status` instead of carried by the event (`NodeEvent.stateChanged`). Injecting a map into an already running node
/// does not change state, so poll `status.addresses` at short intervals for the marker.
func running(_ node: TailnetNode, containing marker: IPAddress? = nil) async throws -> [IPAddress] {
    let deadline = ContinuousClock.now + .seconds(25)
    if let marker {
        while true {
            let addresses = await node.status.addresses
            if addresses.contains(marker) { return addresses }
            guard ContinuousClock.now < deadline else { throw GateFailure("Timed out waiting for the injected map's address marker (25 seconds)") }
            try await Task.sleep(for: .milliseconds(50))
        }
    }
    while true {
        let event = try await nextEvent(node.events, waitingFor: "first running state and local addresses",
                                        timeout: ContinuousClock.now.duration(to: deadline))
        switch event {
        case .stateChanged(.running): return await node.status.addresses
        case .stateChanged(.needsLogin): throw GateFailure("Received needsLogin from the auto-approval server")
        case .stateChanged, .peerPathChanged, .tailnetLockChanged, .statusChanged: continue
        }
    }
}

/// Isolates each test's tool, nodes, and state, then cleans them up on success, failure, or cancellation.
///
/// - Parameter derpCertificate: If provided, sends it as the `mode` for `setDERPCertificate` (`pinned`, `wrongPin`) before the first control request.
func withGate(witness: Bool = false, direct: Bool = true, device: TunnelDevice = .memory(), derpCertificate: String? = nil,
              _ body: (Gate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m3-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("Could not clean up the M3 state directory: \(redacted(String(describing: error)))") }
        }
    }
    var run: Task<Void, any Error>?
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        if let derpCertificate {
            _ = try await tool.command(.init(cmd: "setDERPCertificate", mode: derpCertificate), expecting: "derpCertificate")
        }
        let peer = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer"))
        let other: GatePeer?
        if witness { other = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")) }
        else { other = nil }
        let node = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d",
                                                      controlURL: try #require(ready.controlURL)), device: device)
        run = Task { try await node.run() }
        let addresses = try await running(node)
        let runningAt = ContinuousClock.now
        let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
        let local = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) })
        // Read only the public key from the public list. Do not access identity files or private keys.
        let localPeer = GatePeer(key: local.nodeKey, addresses: addresses)
        let gate = Gate(tool: tool, node: node, local: localPeer, peer: peer, witness: other,
                        runningAt: runningAt, controlURL: ready.controlURL)
        if direct { try await gate.prepareDirectPath() }
        try await body(gate)
        run?.cancel()
        await tool.stop()
        _ = await run?.result
    } catch {
        run?.cancel()
        await tool.stop()
        let result = await run?.result
        var detail = redacted(String(describing: error))
        if case .failure(let failure) = result { detail += "\nTailnetNode.run: \(redacted(String(describing: failure)))" }
        throw GateFailure("\(detail)\n\(await tool.diagnostics())")
    }
}
