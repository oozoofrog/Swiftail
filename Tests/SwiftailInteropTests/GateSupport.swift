// testcontrol 주소·ID 규칙 출처: tailscale.com v1.104.6, tstest/integration/testcontrol/testcontrol.go.
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

/// 사건과 마감 시각을 경쟁시킨다. 시간 초과는 시험을 끝내므로 취소된 구독을 재사용하지 않는다.
func nextEvent<T: Sendable>(
    _ stream: AsyncStream<T>, waitingFor description: String, timeout: Duration = .seconds(20)
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        defer { group.cancelAll() }
        group.addTask {
            for await event in stream { return event }
            throw GateFailure("\(description) 대기 중 사건 흐름 종료")
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw GateFailure("\(description) 제한 시간 초과 (\(timeout))")
        }
        guard let event = try await group.next() else { throw GateFailure("\(description) 사건 없음") }
        return event
    }
}

/// 개인 키·인증 키·사용자 경로가 외부 도구의 진단에 섞여도 보고에 남기지 않는다.
func redacted(_ text: String) -> String {
    var result = text
    for pattern in [#"(?:privkey|nodekey|discokey|mkey):[0-9a-fA-F]+"#, #"tskey-[A-Za-z0-9_-]+"#,
                    #"/Users/[^\s\"']+"#, #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#] {
        result = result.replacingOccurrences(of: pattern, with: "<가림>", options: .regularExpression)
    }
    return result
}

/// Node는 주입 적용을 공개 running 사건으로 확인할 때 필요한 필드만 갖는다.
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

    /// testcontrol.go의 등록 코드: ID n에 100.64.(n>>8).n을 배정한다(v1.104.6).
    /// 기존 nodes 명령이 ID를 내놓지 않아, 이 시험 서버에 한정된 규칙을 여기만 쓴다.
    var mapNode: MapInjection.Node {
        get throws {
            let ip = try address()
            guard ip.bytes[0] == 100, ip.bytes[1] == 64 else { throw GateFailure("testcontrol 주소 배정 규칙 변경") }
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

    /// 자기 주소 표식을 같은 응답에 넣어 ACL·피어 증분 적용 이후임을 확인한다.
    /// 원래 시험 주소는 유지하며, 데이터 패킷은 표식 주소를 사용하지 않는다.
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
                throw GateFailure("Go UDP 쓰기 실패: \(redacted(event.error ?? "오류 없음"))")
            }
        } else {
            #expect(event.sent == false, "Swift에는 TCP 스택이 없어 연결이 성립하면 안 된다")
            #expect(event.error?.isEmpty == false, "TCP 제한 시간 또는 연결 오류가 있어야 한다")
        }
    }

    func echo(ipv4: Bool = true, port: UInt16 = 43000, payload: [UInt8], peer target: GatePeer? = nil,
              rejecting forbidden: @escaping @Sendable (ReceivedPacket) -> Bool = { _ in false }) async throws {
        let target = target ?? peer
        let source = try local.address(ipv4: ipv4), destination = try target.address(ipv4: ipv4)
        let bytes = Packets.udp(from: source, port: port, to: destination, payload: payload)
        let reply = try await packet("\(ipv4 ? "IPv4" : "IPv6") UDP 에코 (목적 포트 7, 회신 포트 \(port))",
            retransmitting: bytes, rejecting: forbidden) {
                $0.proto == 17 && $0.destinationPort == port && $0.payload == payload
            }
        #expect(reply.source == destination && reply.destination == source, "에코 주소가 뒤바뀌어야 한다")
        #expect(reply.sourcePort == 7 && reply.destinationPort == port, "에코 포트가 뒤바뀌어야 한다")
        #expect(reply.payload == payload)
    }

    /// 한 구독을 유지하며 기다린다. 재송신 타이머는 관측을 취소하지 않으므로 첫 DERP 손실을 허용한다.
    func packet(_ stage: String, retransmitting bytes: [UInt8]? = nil,
                rejecting forbidden: @escaping @Sendable (ReceivedPacket) -> Bool = { _ in false },
                matching predicate: @escaping @Sendable (ReceivedPacket) -> Bool) async throws -> ReceivedPacket {
        try await withThrowingTaskGroup(of: ReceivedPacket.self) { group in
            defer { group.cancelAll() }
            group.addTask {
                for await bytes in node.inboundPackets {
                    let packet = try ReceivedPacket(bytes)
                    if forbidden(packet) {
                        throw GateFailure("\(stage): 금지 패킷이 inboundPackets에 도착 (프로토콜 \(packet.proto), 목적 포트 \(packet.destinationPort))")
                    }
                    if predicate(packet) { return packet }
                }
                throw GateFailure("\(stage): inboundPackets 종료")
            }
            group.addTask {
                try await Task.sleep(for: .seconds(25))
                throw GateFailure("\(stage): 패킷 대기 25초 제한 초과")
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

func running(_ node: TailnetNode, containing marker: IPAddress? = nil) async throws -> [IPAddress] {
    let deadline = ContinuousClock.now + .seconds(25)
    while true {
        let event = try await nextEvent(node.events, waitingFor: marker == nil ? "첫 running·자기 주소" : "주입 맵의 주소 표식 running",
                                        timeout: ContinuousClock.now.duration(to: deadline))
        switch event {
        case .running(let addresses):
            if marker == nil || addresses.contains(where: { $0 == marker }) { return addresses }
        case .reconnecting, .peerPathChanged: continue
        case .loginRequired: throw GateFailure("자동 승인 서버에서 loginRequired 수신")
        }
    }
}

/// 매 시험의 도구·노드·상태를 격리하고 성공·실패·취소에서 모두 회수한다.
func withGate(witness: Bool = false, _ body: (Gate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m3-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("M3 상태 디렉터리 정리 실패: \(redacted(String(describing: error)))") }
        }
    }
    var run: Task<Void, any Error>?
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        let peer = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer"))
        let other: GatePeer?
        if witness { other = try GatePeer(await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")) }
        else { other = nil }
        let node = TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d",
                                                  controlURL: try #require(ready.controlURL)))
        run = Task { try await node.run() }
        let addresses = try await running(node)
        let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
        let local = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) })
        // 공개 목록에서 공개 키만 읽는다. 신원 파일·개인 키에는 접근하지 않는다.
        let localPeer = GatePeer(key: local.nodeKey, addresses: addresses)
        try await body(Gate(tool: tool, node: node, local: localPeer, peer: peer, witness: other))
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
