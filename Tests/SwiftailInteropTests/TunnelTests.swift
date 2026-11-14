import Foundation
import Network
import Swiftail
import SwiftailBase
import struct SwiftailBase.IPAddress
import SwiftailEngine
import Testing

@Suite("M5 메모리 터널 관문", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M5 관문 시험을 건너뜁니다"), .serialized, .timeLimit(.minutes(4)))
struct TunnelTests {
    @Test("시험 DNS 해석기의 압축·잘림·순환 경계")
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

    @Test("설정·UDP·TCP·MagicDNS·서비스 IP의 로컬 처리")
    func dataPathAndLocalServices() async throws {
        try await withTunnelGate { gate in
            let started = ContinuousClock.now
            let settings = try await nextEvent(gate.node.networkSettings, waitingFor: "M5 첫 설정")
            let status = await gate.node.status
            let source = try gate.local.address(), destination = try gate.peer.address()
            #expect(settings.addresses.contains { $0.address == source && $0.length == 32 })
            #expect(settings.routes.contains { $0.address == destination && $0.length == 32 })
            #expect(settings.dnsServers.first == IPAddress("100.100.100.100"))
            #expect(settings.dnsMatchDomains.contains("tail0001.test"))
            #expect(settings.dnsMatchDomains.allSatisfy { !$0.hasSuffix(".") })
            #expect(settings.mtu == 1280 && status.networkSettings == settings && status.peerCount >= 1)
            await gate.tool.checkpoint("M5 network-settings 관측: 주소 \(settings.addresses.count)개·경로 \(settings.routes.count)개·DNS 서버 \(settings.dnsServers.count)개·match 도메인 \(settings.dnsMatchDomains.count)개·MTU \(settings.mtu)")

            try await gate.echo(port: 43500, payload: [0x4d, 0x35, 0x01])
            let syn = Packets.syn(from: source, port: 43501, to: destination, destinationPort: 7, sequence: 0x12345678)
            let tcp = try await gate.packet("M5 TCP SYN-ACK", retransmitting: syn) { $0.proto == 6 && $0.destinationPort == 43501 }
            #expect(tcp.flags & 0x16 == 0x12 && tcp.acknowledgement == 0x12345679)
            #expect(tcp.source == destination && tcp.destination == source && tcp.sourcePort == 7)
            await gate.tool.checkpoint("M5 udp·tcp: 에코 payload·SYN-ACK 확인")

            _ = try await gate.tool.command(.init(cmd: "startCapture", name: "go-peer-a"), expecting: "captureStarted")
            // 관측기가 정상 UDP를 보는지 먼저 확인해야 서비스 IP 0개가 증거가 된다.
            try await gate.echo(port: 43502, payload: [0x4d, 0x35, 0x02])
            try await waitForTunnel("capture 양성 대조") {
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
                    let reply = try await gate.packet("M5 DNS \(ipv4 ? "IPv4" : "IPv6") 유형 \(type) 항목 \(index)", retransmitting: bytes) {
                        $0.proto == 17 && $0.destinationPort == port
                    }
                    #expect(reply.source == service && reply.destination == local && reply.sourcePort == 53)
                    let dns = try TunnelDNS(reply.payload)
                    #expect(dns.id == id && dns.flags & 0x8000 != 0)
                    #expect(dns.flags & 15 == rcode, "주소 계열 \(ipv4 ? 4 : 6), DNS 항목 \(index)")
                    await gate.tool.checkpoint("M5 DNS 계열 \(ipv4 ? 4 : 6)·유형 \(type): rcode \(dns.flags & 15)·답변 \(dns.answers.count)개·권한 유형 \(dns.authorities.map(\.type))·TTL \(dns.authorities.map(\.ttl))")
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
                let reset = try await gate.packet("M5 서비스 TCP 53 RST", retransmitting:
                    Packets.syn(from: local, port: 43540, to: service, destinationPort: 53, sequence: 0xffffffff)) {
                        $0.proto == 6 && $0.destinationPort == 43540
                    }
                #expect(reset.source == service && reset.destination == local && reset.sourcePort == 53)
                #expect(reset.flags == 0x14 && reset.sequence == 0 && reset.acknowledgement == 0)
            }
            // 후속 정상 패킷까지 capture가 읽은 것을 확인한 뒤 누적 부재를 판정한다.
            try await gate.echo(port: 43503, payload: [0x4d, 0x35, 0x03])
            try await waitForTunnel("capture 후속 경계") {
                let capture = try await gate.tool.command(.init(cmd: "captureStatus", name: "go-peer-a", port: 43503), expecting: "captureStatus")
                #expect(capture.servicePackets == 0, "서비스 IP 패킷이 Go 피어에 도착하면 안 된다")
                return (capture.observedPackets ?? 0) > 0
            }
            await gate.tool.checkpoint("M5 magicdns 관측 완료: 양 계열 10개 질의·ICMP·RST, Go 서비스 패킷 0개, 경과 \(started.duration(to: .now))")
        }
    }

    @Test("취소·장치 종료: run 결과·세 흐름 종료·정지 뒤 송신 없음", arguments: [false, true])
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
                let result = try await nextEvent(run.completion, waitingFor: "M5 run 종료", timeout: .seconds(10))
                switch result {
                case .success: #expect(!deviceFailure, "장치 종료는 tunnelDeviceClosed여야 한다")
                case .failure(.tunnelDeviceClosed(let message)):
                    #expect(deviceFailure && message == "test")
                case .failure: Issue.record("기대하지 않은 run 실패 종류")
                }
                try await waitForTunnel("M5 세 흐름 종료", timeout: .seconds(5)) { await streams.endCount == 3 }
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
                await tool.checkpoint("M5 \(deviceFailure ? "engine-death tunnelDeviceClosed(test)" : "stop 정상 반환"): 세 흐름 종료·2초 lastWrite 불변·추가 사건 0, 경과 \(stopped.duration(to: .now))")
            }
        }
    }

    @Test("신원: 같은·새·옮긴 디렉터리와 중복 점유 해제")
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
                    let result = try await nextEvent(second.completion, waitingFor: "M5 중복 상태 디렉터리", timeout: .seconds(5))
                    guard case .failure(.stateDirectoryInUse) = result else {
                        throw GateFailure("M5 같은 디렉터리를 stateDirectoryInUse로 거절하지 않음")
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
            await tool.checkpoint("M5 restart·in-use: identity.json 생성·동일/이동 주소와 StableID 유지·새 주소 분리·중복 거절·정지 뒤 점유 해제·needsLogin 0")
        }
    }

    @Test("잘못된 utun·MTU는 init에서 거절하고 상태 파일을 만들지 않는다")
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
                Issue.record("잘못된 장치 또는 MTU가 init을 통과함: 항목 \(index)")
            } catch .invalidConfiguration(let message) {
                if index >= 2 { #expect(message.localizedCaseInsensitiveContains("MTU")) }
            } catch { Issue.record("잘못된 설정에서 invalidConfiguration 외 오류") }
            #expect(!FileManager.default.fileExists(atPath: directory.path))
            #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
        }
    }

    @Test("MTU 1280·1420·기본값이 시작되어 설정으로 나온다")
    func mtuBounds() async throws {
        try await withTunnelLab { tool, root, control in
            for (index, device, mtu) in [(0, TunnelDevice.memory(mtu: 1280), 1280), (1, .memory(mtu: 1420), 1420), (2, .memory(), 1280)] {
                try await withTunnelRun(root.appending(path: "mtu-\(index)"), control: control, device: device) { node, _ in
                    _ = try await running(node)
                    let settings = try await nextEvent(node.networkSettings, waitingFor: "M5 MTU 설정")
                    #expect(settings.mtu == mtu)
                    #expect(await node.status.networkSettings?.mtu == mtu)
                }
            }
            await tool.checkpoint("M5 mtu-bounds: 1280·1420·기본 1280 시작·설정 일치")
        }
    }

    @Test("실제 인터페이스 재결속·같은 인터페이스 재평가")
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
        let interface = try await nextEvent(interfaces, waitingFor: "만족된 실제 경로 인터페이스", timeout: .seconds(10))
        try await withGate { gate in
            let beforeEndpoints = try await tunnelEndpoints(gate)
            let ports = Set(beforeEndpoints.map(\.port))
            let before = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            let started = ContinuousClock.now
            await gate.node.setDefaultInterface(interface)
            try await waitForTunnel("M5 인터페이스 제어·DERP 재연결·STUN", timeout: .seconds(15)) {
                let after = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                return (after.controlConnections ?? 0) > (before.controlConnections ?? 0)
                    && (after.derpConnections ?? 0) > (before.derpConnections ?? 0)
                    && (after.stunRequests ?? 0) > (before.stunRequests ?? 0)
            }
            // UDP가 막혀도 에코되어야 새 DERP 연결을 통한 데이터면 복구의 증거가 된다.
            let peerStatus = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
            let peerPorts = Set((peerStatus.selfAddrs ?? []).compactMap(IPEndpoint.init).map(\.port))
            #expect(!peerPorts.isEmpty)
            await gate.node.setBlockedUDPPorts(peerPorts)
            try await gate.echo(port: 43560, payload: [0x35, 0x60])
            await gate.node.setBlockedUDPPorts([])
            try await waitForTunnel("M5 재결속 뒤 양쪽 직접 경로", timeout: .seconds(15)) {
                try await gate.echo(port: 43561, payload: [0x35, 0x61])
                return try await tunnelIsDirect(gate, ports: ports)
            }
            #expect(Set(try await tunnelEndpoints(gate).map(\.port)) == ports, "UDP 포트를 유지해야 한다")
            await gate.tool.checkpoint("M5 setDefaultInterface: 포트 유지·endpoints 관측·제어/DERP 연결 증가·STUN 증가·중계 에코·양쪽 직접 복귀, 경과 \(started.duration(to: .now))")
            let settled = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            let repeated = ContinuousClock.now
            await gate.node.setDefaultInterface(interface)
            try await waitForTunnel("M5 같은 인터페이스 STUN 재평가", timeout: .seconds(15)) {
                let after = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                return (after.stunRequests ?? 0) > (settled.stunRequests ?? 0)
            }
            try await gate.echo(port: 43562, payload: [0x35, 0x62])
            #expect(try await tunnelIsDirect(gate, ports: ports))
            let reevaluated = try await gate.tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            #expect(reevaluated.controlConnections == settled.controlConnections)
            #expect(reevaluated.derpConnections == settled.derpConnections)
            await gate.tool.checkpoint("M5 reevaluates: 같은 인터페이스 STUN 증가·제어/DERP 재연결 없음·포트 유지·직접 에코, 경과 \(repeated.duration(to: .now))")
        }
    }

    @Test("대화형 인증 URL 완료 뒤 starting·running으로 회복")
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
                            if case .stateChanged(.running) = event { throw GateFailure("인증 완료 전에 running") }
                        }
                        throw GateFailure("needsLogin 전 사건 흐름 종료")
                    }
                    group.addTask { try await Task.sleep(for: .seconds(25)); throw GateFailure("needsLogin 25초 제한 초과") }
                    return try #require(try await group.next())
                }
                #expect(await node.status.state == .needsLogin(url))
                _ = try await tool.command(.init(cmd: "setAuth", authURL: url), expecting: "auth")
                var states: [NodeState] = []
                let deadline = ContinuousClock.now + .seconds(25)
                while states.last != .running {
                    let event = try await nextEvent(node.events, waitingFor: "로그인 완료 뒤 상태", timeout: ContinuousClock.now.duration(to: deadline))
                    if case .stateChanged(let state) = event { states.append(state) }
                }
                #expect(states == [.starting, .running])
                #expect(await node.status.addresses.isEmpty == false)
                await tool.checkpoint("M5 interactive-login: needsLogin(URL) → starting → running, URL 비기록, 경과 \(started.duration(to: .now))")
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
        guard ContinuousClock.now <= deadline else { throw GateFailure("\(stage): 제한 \(timeout), 관찰 \(started.duration(to: .now))") }
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
        catch { Issue.record("M5 임시 상태 정리 실패") }
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


/// DNS가 켜진 제어 맵으로 시작한다. 도구의 이름 접미사만으로는 DNSConfig가 생기지 않는다.
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
    guard !endpoints.isEmpty else { throw GateFailure("M5 nodes의 로컬 endpoints가 비어 있음") }
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
    let reply = try await nextEvent(node.inboundPackets, waitingFor: "M5 서비스 ICMP echo reply")
    let offset = ipv4 ? 20 : 40
    guard reply.count == offset + transport.count else { throw GateFailure("M5 ICMP 응답 길이 불일치") }
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

/// RFC 1035 머리·질문·RR의 경계를 독립적으로 읽는다. 라이브러리의 DNS 코덱은 쓰지 않는다.
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
        guard !labels.isEmpty, labels.allSatisfy({ (1...63).contains($0.utf8.count) }) else { throw GateFailure("시험 DNS 이름 경계 오류") }
        var encoded: [UInt8] = []
        for label in labels { encoded.append(UInt8(label.utf8.count)); encoded.append(contentsOf: label.utf8) }
        encoded.append(0)
        guard encoded.count <= 255 else { throw GateFailure("시험 DNS 이름 길이 초과") }
        let header: [UInt8] = Packets.word(id) + [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        return header + encoded + Packets.word(type) + [0, 1]
    }

    init(_ bytes: [UInt8]) throws {
        var reader = DNSReader(bytes: bytes)
        id = try reader.word(); flags = try reader.word()
        let questions = try reader.word(), answerCount = try reader.word(), authorityCount = try reader.word(), additionalCount = try reader.word()
        guard questions == 1 else { throw GateFailure("DNS 질문 수가 1이 아님") }
        questionName = try reader.name(); questionType = try reader.word()
        guard try reader.word() == 1 else { throw GateFailure("DNS 질문 class가 IN이 아님") }
        answers = try (0..<Int(answerCount)).map { _ in try reader.record() }
        authorities = try (0..<Int(authorityCount)).map { _ in try reader.record() }
        for _ in 0..<Int(additionalCount) { _ = try reader.record() }
        guard reader.offset == bytes.count else { throw GateFailure("DNS 뒤에 해석되지 않은 바이트") }
    }
}

private struct DNSReader {
    let bytes: [UInt8]
    var offset = 0

    mutating func take(_ count: Int) throws -> [UInt8] {
        guard count >= 0, offset <= bytes.count, count <= bytes.count - offset else { throw GateFailure("짧은 DNS 경계") }
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
            guard cursor < bytes.count, visited.insert(cursor).inserted else { throw GateFailure("DNS 이름 경계·포인터 순환") }
            let count = Int(bytes[cursor])
            if count == 0 { offset = end ?? cursor + 1; return labels.joined(separator: ".") + "." }
            if count & 0xc0 == 0xc0 {
                guard cursor + 1 < bytes.count, visited.count <= 128 else { throw GateFailure("DNS 포인터 경계 초과") }
                end = end ?? cursor + 2
                cursor = (count & 0x3f) << 8 | Int(bytes[cursor + 1])
                continue
            }
            guard count <= 63, cursor + 1 + count <= bytes.count else { throw GateFailure("DNS label 경계 오류") }
            wireLength += count + 1
            guard wireLength <= 255, let label = String(bytes: bytes[(cursor + 1)..<(cursor + 1 + count)], encoding: .ascii) else {
                throw GateFailure("DNS label 길이·ASCII 오류")
            }
            labels.append(label); cursor += count + 1
        }
    }
    mutating func record() throws -> TunnelDNS.Record {
        _ = try name()
        let type = try word(), recordClass = try word(), high = try word(), low = try word(), length = Int(try word())
        guard recordClass == 1 else { throw GateFailure("DNS RR class가 IN이 아님") }
        let start = offset
        let data = try take(length)
        var nameData: String?
        if type == 12 {
            var rdata = DNSReader(bytes: bytes, offset: start)
            nameData = try rdata.name()
            guard rdata.offset == offset else { throw GateFailure("PTR RDATA 길이 불일치") }
        }
        return .init(type: type, ttl: UInt32(high) << 16 | UInt32(low), data: data, nameData: nameData)
    }
}
