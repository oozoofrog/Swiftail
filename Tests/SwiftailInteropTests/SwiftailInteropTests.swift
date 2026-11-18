import Foundation
import SwiftailBase
import Testing

@Suite("M3 public TailnetNode Go interop", .enabled(if: tailnetBinary != nil,
    "Skipping M3 gate tests because SWIFTAIL_TAILNET is missing"), .timeLimit(.minutes(4)))
struct SwiftailInteropTests {
    // M4: The Swift node opens a UDP socket and advertises endpoints, so Go now sees a direct path (magicsock contract
    // "M4 Gate" 2(a)). M3's "curAddr is empty" no longer holds. Go chooses among the endpoints Swift advertises (loopback, LAN)
    // based on lower latency, so this test does not check which address it picks.
    @Test("Gate 1: after registration and running, Go sees a direct UDP path (M4)")
    func registrationAndDirectPath() async throws {
        try await withGate { gate in
            // Check the path after actual traffic. Presence in the peer list alone is insufficient.
            try await gate.echo(payload: [0x01, 0x02, 0x03])
            let deadline = ContinuousClock.now + .seconds(20)
            while true {
                let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
                if let peer = status.peers?.first(where: { $0.nodeKey == gate.local.key }),
                   peer.relay?.isEmpty == false, peer.curAddr?.isEmpty == false {
                    #expect(Set(peer.addresses) == Set(gate.local.addresses.map(\.description)))
                    return
                }
                guard ContinuousClock.now < deadline else {
                    throw GateFailure("peerStatus: no direct path (curAddr) for the Swift peer within 20 seconds")
                }
                await Task.yield()
            }
        }
    }

    @Test("Gate 2: IPv4 and IPv6 UDP echo addresses, ports, and payload", arguments: [true, false])
    func udpEcho(ipv4: Bool) async throws {
        try await withGate { gate in
            try await gate.echo(ipv4: ipv4, payload: [0x00, 0x7f, 0x80, 0xff, 0x42])
        }
    }

    @Test("Gate 3: SYN-ACK on TCP port 7 and RST on closed ports", arguments: [true, false])
    func tcpResponse(ipv4: Bool) async throws {
        try await withGate { gate in
            try await gate.echo(ipv4: ipv4, payload: [0x03])
            let source = try gate.local.address(ipv4: ipv4), destination = try gate.peer.address(ipv4: ipv4)
            for (remotePort, localPort, sequence): (UInt16, UInt16, UInt32) in [(7, 43100, 0x10203040), (42099, 43101, 0xfffffffe)] {
                let syn = Packets.syn(from: source, port: localPort, to: destination, destinationPort: remotePort, sequence: sequence)
                let reply = try await gate.packet("\(remotePort == 7 ? "SYN-ACK" : "RST") on TCP port \(remotePort)",
                    retransmitting: syn) { $0.proto == 6 && $0.destinationPort == localPort }
                #expect(reply.source == destination && reply.destination == source)
                #expect(reply.sourcePort == remotePort)
                if remotePort == 7 {
                    #expect(reply.flags & 0x16 == 0x12, "SYN and ACK must be set and RST must be clear")
                } else {
                    #expect(reply.flags & 0x14 == 0x14, "ACK and RST must be set")
                }
                #expect(reply.acknowledgement == sequence &+ 1, "Must acknowledge seq+1 of the transmitted SYN")
            }
        }
    }

    @Test("Gate 4: receives only allowed ports and sees no closed-port packet through the next allowed packet", arguments: ["udp", "tcp"])
    func packetFilter(proto: String) async throws {
        try await withGate { gate in
            try await gate.echo(payload: [0x04])
            let open: UInt16 = 42001, closed: UInt16 = 42002
            let number = proto == "udp" ? 17 : 6
            let rule = MapInjection.Rule(SrcIPs: [try gate.peer.address().description], IPProto: [number],
                DstPorts: [.init(IP: try gate.local.address().description, Ports: .init(First: open, Last: open))])
            try await gate.inject(.init(PacketFilter: [rule]), marker: 1)
            let forbidden: @Sendable (ReceivedPacket) -> Bool = {
                $0.proto == number && $0.destinationPort == closed && (proto == "udp" || $0.flags & 0x12 == 2)
            }
            // Observe an allowed packet first to verify that the path works in both directions.
            try await gate.sendFromGo(proto: proto, port: open, payload: [0x40])
            let first = try await gate.packet("\(proto) first allowed packet after applying the filter") {
                $0.proto == number && $0.destinationPort == open && (proto == "tcp" ? $0.flags & 0x12 == 2 : $0.payload == [0x40])
            }
            try await gate.sendFromGo(proto: proto, port: closed, payload: [0x41])
            try await gate.sendFromGo(proto: proto, port: open, payload: [0x42])
            let last = try await gate.packet("\(proto) allowed packet after the blocked attempt", rejecting: forbidden) {
                $0.proto == number && $0.destinationPort == open && (proto == "tcp"
                    ? $0.flags & 0x12 == 2 && ($0.sourcePort != first.sourcePort || $0.sequence != first.sequence)
                    : $0.payload == [0x42])
            }
            let expectedSource = try gate.peer.address(), expectedDestination = try gate.local.address()
            #expect(last.source == expectedSource && last.destination == expectedDestination)
            if proto == "tcp" { #expect(last.flags & 0x12 == 2) }
            // Go TCP retransmissions can follow, so use another UDP response as a receive boundary.
            try await gate.echo(port: 43004, payload: [0x43], rejecting: forbidden)
        }
    }

    @Test("Gate 5: even with an all-closed filter, a reply to outbound UDP gets through")
    func closedFilterUdpResponse() async throws {
        try await withGate { gate in
            try await gate.echo(payload: [0x50])
            // PacketFilter [] in Go MapResponse is dropped by omitempty.
            // Actually send an empty filter with PacketFilters.base=[], which is equivalent under the tailcfg.go rules.
            try await gate.inject(.init(PacketFilters: ["base": []]), marker: 1)
            try await gate.sendFromGo(proto: "udp", port: 42005, payload: [0x51])
            // Use a different source port from the previous flow to verify a new send record as well. IPv6 must also get through the closed filter.
            for ipv4 in [true, false] {
                try await gate.echo(ipv4: ipv4, port: 43005, payload: [0x52, 0x53, 0x54], rejecting: {
                    $0.proto == 17 && $0.destinationPort == 42005
                })
            }
        }
    }

    @Test("Gate 6: echoes disappear after PeersRemoved and return when the same peer is added again")
    func peerRemovalAndRecovery() async throws {
        try await withGate(witness: true) { gate in
            let witness = try #require(gate.witness)
            try await gate.echo(payload: [0x60])
            try await gate.echo(port: 43061, payload: [0x61], peer: witness)
            let removedPeer = try gate.peer.mapNode
            try await gate.inject(.init(PeersRemoved: [removedPeer.ID]), marker: 1)
            let forbidden: @Sendable (ReceivedPacket) -> Bool = {
                $0.proto == 17 && $0.destinationPort == 43062 && $0.payload == [0x62]
            }
            let bytes = Packets.udp(from: try gate.local.address(), port: 43062,
                                    to: try gate.peer.address(), payload: [0x62])
            await gate.node.send(bytes)
            // Use an echo from a separate Go peer as a receive boundary so absence is not decided by time alone.
            try await gate.echo(port: 43063, payload: [0x63], peer: witness, rejecting: forbidden)
            try await gate.inject(.init(PeersChanged: [removedPeer]), marker: 2)
            try await gate.echo(port: 43064, payload: [0x64], rejecting: forbidden)
        }
    }

    @Test("Gate 7: sends every 10 seconds for 130 seconds and receives echoes after rekey and KeepAlive", .timeLimit(.minutes(5)))
    func rekeyAndKeepAlive() async throws {
        try await withGate { gate in
            try await gate.echo(payload: [0x70])
            let start = ContinuousClock.now
            for tick in 1...13 {
                // Wait to cross the time boundary. Use an actual echo to determine success each time.
                try await Task.sleep(until: start + .seconds(tick * 10), clock: .continuous)
                try await gate.echo(port: 43007, payload: [0x71, UInt8(tick)])
            }
            #expect(start.duration(to: .now) >= .seconds(130))
        }
    }
}
