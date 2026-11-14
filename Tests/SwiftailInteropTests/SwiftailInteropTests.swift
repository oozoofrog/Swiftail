import Foundation
import SwiftailBase
import Testing

@Suite("M3 공개 TailnetNode Go 상호 운용", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M3 관문 시험을 건너뜁니다"), .timeLimit(.minutes(4)))
struct SwiftailInteropTests {
    @Test("관문 1: 등록·running 뒤 Go가 보는 경로는 DERP다")
    func 등록과DERP경로() async throws {
        try await withGate { gate in
            // 실제 트래픽 뒤의 경로를 확인한다. 단순한 피어 목록 등재만으로 통과시키지 않는다.
            try await gate.echo(payload: [0x01, 0x02, 0x03])
            let deadline = ContinuousClock.now + .seconds(20)
            while true {
                let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
                if let peer = status.peers?.first(where: { $0.nodeKey == gate.local.key }),
                   peer.relay?.isEmpty == false {
                    #expect(peer.curAddr == "", "직접 UDP 주소가 없어야 한다")
                    #expect(Set(peer.addresses) == Set(gate.local.addresses.map(\.description)))
                    return
                }
                guard ContinuousClock.now < deadline else {
                    throw GateFailure("peerStatus: 20초 안에 Swift 피어의 비어 있지 않은 relay를 보지 못함")
                }
                await Task.yield()
            }
        }
    }

    @Test("관문 2: IPv4·IPv6 UDP 에코의 주소·포트·payload", arguments: [true, false])
    func UDP에코(ipv4: Bool) async throws {
        try await withGate { gate in
            try await gate.echo(ipv4: ipv4, payload: [0x00, 0x7f, 0x80, 0xff, 0x42])
        }
    }

    @Test("관문 3: TCP 포트 7의 SYN-ACK와 닫힌 포트의 RST", arguments: [true, false])
    func TCP응답(ipv4: Bool) async throws {
        try await withGate { gate in
            try await gate.echo(ipv4: ipv4, payload: [0x03])
            let source = try gate.local.address(ipv4: ipv4), destination = try gate.peer.address(ipv4: ipv4)
            for (remotePort, localPort, sequence): (UInt16, UInt16, UInt32) in [(7, 43100, 0x10203040), (42099, 43101, 0xfffffffe)] {
                let syn = Packets.syn(from: source, port: localPort, to: destination, destinationPort: remotePort, sequence: sequence)
                let reply = try await gate.packet("TCP 포트 \(remotePort)의 \(remotePort == 7 ? "SYN-ACK" : "RST")",
                    retransmitting: syn) { $0.proto == 6 && $0.destinationPort == localPort }
                #expect(reply.source == destination && reply.destination == source)
                #expect(reply.sourcePort == remotePort)
                if remotePort == 7 {
                    #expect(reply.flags & 0x16 == 0x12, "SYN·ACK가 켜지고 RST는 꺼져야 한다")
                } else {
                    #expect(reply.flags & 0x14 == 0x14, "ACK·RST가 켜져야 한다")
                }
                #expect(reply.acknowledgement == sequence &+ 1, "보낸 SYN의 seq+1을 확인해야 한다")
            }
        }
    }

    @Test("관문 4: 허용 포트만 수신하며 닫힌 포트는 후속 허용 패킷까지 나오지 않는다", arguments: ["udp", "tcp"])
    func 패킷필터(proto: String) async throws {
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
            // 먼저 허용 패킷을 관측해 양방향 경로가 살아 있음을 확인한다.
            try await gate.sendFromGo(proto: proto, port: open, payload: [0x40])
            let first = try await gate.packet("\(proto) 필터 적용 뒤 첫 허용 패킷") {
                $0.proto == number && $0.destinationPort == open && (proto == "tcp" ? $0.flags & 0x12 == 2 : $0.payload == [0x40])
            }
            try await gate.sendFromGo(proto: proto, port: closed, payload: [0x41])
            try await gate.sendFromGo(proto: proto, port: open, payload: [0x42])
            let last = try await gate.packet("\(proto) 차단 시도 뒤 허용 패킷", rejecting: forbidden) {
                $0.proto == number && $0.destinationPort == open && (proto == "tcp"
                    ? $0.flags & 0x12 == 2 && ($0.sourcePort != first.sourcePort || $0.sequence != first.sequence)
                    : $0.payload == [0x42])
            }
            let expectedSource = try gate.peer.address(), expectedDestination = try gate.local.address()
            #expect(last.source == expectedSource && last.destination == expectedDestination)
            if proto == "tcp" { #expect(last.flags & 0x12 == 2) }
            // Go TCP 재전송도 뒤따를 수 있으므로 UDP 응답을 한 번 더 수신 경계로 둔다.
            try await gate.echo(port: 43004, payload: [0x43], rejecting: forbidden)
        }
    }

    @Test("관문 5: 모두 닫힌 필터에서도 먼저 보낸 UDP의 응답은 돌아온다")
    func 닫힌필터의UDP응답() async throws {
        try await withGate { gate in
            try await gate.echo(payload: [0x50])
            // Go MapResponse의 PacketFilter []는 omitempty로 사라진다.
            // tailcfg.go 규약상 같은 뜻인 PacketFilters.base=[]로 빈 필터를 실제 전송한다.
            try await gate.inject(.init(PacketFilters: ["base": []]), marker: 1)
            try await gate.sendFromGo(proto: "udp", port: 42005, payload: [0x51])
            // 이전 흐름과 다른 출발 포트로 새 송신 기록도 확인한다. IPv6도 필터 닫힘을 통과해야 한다.
            for ipv4 in [true, false] {
                try await gate.echo(ipv4: ipv4, port: 43005, payload: [0x52, 0x53, 0x54], rejecting: {
                    $0.proto == 17 && $0.destinationPort == 42005
                })
            }
        }
    }

    @Test("관문 6: PeersRemoved 뒤 에코가 사라지고 같은 피어를 다시 더하면 돌아온다")
    func 피어제거와복귀() async throws {
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
            // 별도 Go 피어의 에코를 수신 경계로 삼아 시간만으로 부재를 판정하지 않는다.
            try await gate.echo(port: 43063, payload: [0x63], peer: witness, rejecting: forbidden)
            try await gate.inject(.init(PeersChanged: [removedPeer]), marker: 2)
            try await gate.echo(port: 43064, payload: [0x64], rejecting: forbidden)
        }
    }

    @Test("관문 7: 130초 동안 10초마다 쓰고 rekey·KeepAlive 뒤에도 에코된다", .timeLimit(.minutes(5)))
    func 재키잉과KeepAlive() async throws {
        try await withGate { gate in
            try await gate.echo(payload: [0x70])
            let start = ContinuousClock.now
            for tick in 1...13 {
                // 기다림의 목적은 시간 경계를 넘기는 것이다. 성공 판정은 매번 실제 에코로 한다.
                try await Task.sleep(until: start + .seconds(tick * 10), clock: .continuous)
                try await gate.echo(port: 43007, payload: [0x71, UInt8(tick)])
            }
            #expect(start.duration(to: .now) >= .seconds(130))
        }
    }
}
