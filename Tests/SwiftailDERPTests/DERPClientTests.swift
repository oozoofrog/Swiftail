import Foundation
import Network
import SwiftailBase
import Synchronization
import Testing

@testable import SwiftailDERP

/// `DERPClient`의 메모리 상한과 사건 버퍼. 루프백의 가짜 서버(평문)에 붙는다.
@Suite("DERP 클라이언트의 상한")
struct DERPClientTests {
    private static let packet = [UInt8](repeating: 0x5A, count: DERPConnection.maximumPacketSize)

    private static func client(port: UInt16, writeTimeout: Duration, interface: NWInterface? = nil) throws -> DERPClient {
        let server = DERPServer(hostName: "127.0.0.1", address: IPAddress("127.0.0.1"), port: port, verification: .noneForTests)
        return DERPClient(
            servers: [server], privateKey: try DERPFixtures.privateKey(seed: DERPFixtures.clientSeed), isPreferred: true,
            interface: interface, writeTimeout: writeTimeout, plaintextForTests: true
        )
    }

    /// 패킷 사건. 본문이 `size`바이트이고 첫 바이트가 `tag`다.
    private static func packetEvent(_ tag: UInt8, size: Int, from peer: NodePublicKey) -> DERPClient.Event {
        .packet([tag] + [UInt8](repeating: 0, count: size - 1), from: peer)
    }

    private static func drain(_ queue: DERPClient.EventQueue) async -> [String] {
        queue.finish()
        var seen: [String] = []
        while let event = await queue.next() { seen.append(EventLog.name(event)) }
        return seen
    }

    /// 고치기 전에는 연결된 동안 패킷을 곧바로 소켓에 넘겼고 소켓이 기다리지 않아, 쓰기가 막혀도 끊기지 않고 메모리만 늘었다.
    @Test("읽지 않는 서버에 계속 보내면 쥔 패킷은 32개를 넘지 않고, 쓰기 기한이 지나면 끊고 다시 잇는다")
    func blockedWritesAreBoundedAndReconnect() async throws {
        let server = try FakeDERPServer(.silent)
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .milliseconds(300))
        let log = EventLog()
        let peer = try DERPFixtures.nodeKey(7)
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))
            group.addTask {
                while !Task.isCancelled {
                    await client.send(Self.packet, to: peer)
                    let held = await client.queuedPackets
                    #expect(held.count <= DERPClient.queuedPacketLimit)
                    #expect(held.reduce(0) { $0 + $1.packet.count } <= DERPClient.queuedPacketLimit * DERPConnection.maximumPacketSize)
                    try await Task.sleep(for: .milliseconds(1))
                }
            }
            try await log.wait(for: ["connected", "disconnected", "connected"], within: .seconds(20))
        }
        #expect(server.acceptedCount >= 2)
    }

    // MARK: 쓰기 묶기와 쓰기 감시

    @Test("한 덩어리에는 첫 패킷을 늘 넣고, 패킷 프레임의 합이 64KiB를 넘기 전까지 더 넣는다")
    func packetsPerWrite() {
        let frameOverhead = DERPFrame.headerSize + DERPFrame.keySize
        #expect(DERPClient.packetCountForNextWrite([]) == 0)
        // 흔한 WireGuard 데이터그램 32개(큐 한도)는 한 덩어리에 다 들어간다.
        #expect(DERPClient.packetCountForNextWrite(Array(repeating: 1_400, count: DERPClient.queuedPacketLimit)) == 32)
        // 가장 큰 패킷은 혼자서 한도를 넘어도 한 덩어리가 된다.
        let largest = DERPConnection.maximumPacketSize
        #expect(DERPClient.packetCountForNextWrite([largest, largest, 1]) == 1)
        #expect(DERPClient.packetCountForNextWrite([1, largest]) == 1)
        // 합이 한도와 같으면 넣고, 1바이트라도 넘으면 다음 덩어리로 미룬다.
        let half = DERPClient.maximumWriteBytes / 2 - frameOverhead
        #expect(DERPClient.packetCountForNextWrite([half, half, 0]) == 2)
        #expect(DERPClient.packetCountForNextWrite([half, half + 1]) == 1)
    }

    /// 묶어 쓰더라도 프레임은 `send`를 부른 순서대로 빠짐없이 나간다. 큐가 넘치지 않게 덩어리마다 비기를 기다린다.
    @Test("묶어 쓴 패킷은 보낸 순서대로 빠짐없이 서버에 닿는다")
    func batchedWritesKeepOrder() async throws {
        let server = try FakeDERPServer(.reading(keep: true))
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(5))
        let log = EventLog()
        let peer = try DERPFixtures.nodeKey(7)
        let total = 3_000
        var rng = SplitMix64(state: 1)
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))
            var index = 0
            while index < total {
                let burst = min(Int.random(in: 1...DERPClient.queuedPacketLimit, using: &rng), total - index)
                for _ in 0..<burst {
                    let size = Int.random(in: 4...3_000, using: &rng)
                    await client.send(Self.indexed(index, size: size), to: peer)
                    index += 1
                }
                while await !client.queuedPackets.isEmpty { await Task.yield() }
            }
            let deadline = ContinuousClock.now + .seconds(10)
            while server.sentPacketIndices().count < total, ContinuousClock.now < deadline {
                try await Task.sleep(for: .milliseconds(20))
            }
        }
        #expect(server.sentPacketIndices() == Array(0..<total))
    }

    /// 고치기 전에는 쓰기마다 `withTimeout`을 걸어, 쓰기가 곧 끝나도 기한 쪽 Task와 타이머가 기한까지 남았다(쓰기
    /// 하나에 약 700바이트). 기한을 60초로 두면 이 시험 동안 하나도 풀리지 않으므로 남는 것이 모두 쌓인다.
    @Test("곧 끝나는 쓰기를 수없이 해도 메모리가 쌓이지 않는다")
    func manyQuickWritesDoNotAccumulate() async throws {
        let server = try FakeDERPServer(.reading(keep: false))
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(60))
        let log = EventLog()
        let peer = try DERPFixtures.nodeKey(7)
        let packet = [UInt8](repeating: 0x5A, count: 100)
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))
            let before = try #require(Self.footprint())
            let started = ContinuousClock.now
            var writes = 0
            // 패킷 하나를 보내고 큐가 비기를 기다리므로 덩어리 하나에 패킷 하나, 곧 쓰기 하나다.
            while ContinuousClock.now - started < .seconds(4) {
                await client.send(packet, to: peer)
                while await !client.queuedPackets.isEmpty { await Task.yield() }
                writes += 1
            }
            let growth = try #require(Self.footprint()) - before
            // 다른 시험이 같은 프로세스에서 함께 돌므로 여유를 크게 둔다.
            #expect(writes > 10_000, "쓰기가 너무 적어 남는 것을 가려내지 못한다: \(writes)")
            #expect(growth < 16 << 20, "쓰기 \(writes)번 뒤 phys_footprint가 \(growth)바이트 늘었다")
            #expect(server.acceptedCount == 1)
        }
    }

    /// 쓰기 감시는 연결의 TaskGroup 자식이다. 기한이 60초여도 연결이 끊기면 다음 연결로 넘어가고, 취소하면 곧바로 멈춘다.
    @Test("연결이 끊기면 다시 잇고, 취소하면 쓰기 감시와 함께 run()이 곧 돌아온다")
    func watchStopsWithConnection() async throws {
        let server = try FakeDERPServer(.reading(keep: false))
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(60))
        let log = EventLog()
        let running = Task { await client.run() }
        let recording = Task { await log.record(client.events) }
        try await log.wait(for: ["connected"], within: .seconds(10))
        await client.send([1, 2, 3], to: try DERPFixtures.nodeKey(7))
        server.dropConnections()
        try await log.wait(for: ["connected", "disconnected", "connected"], within: .seconds(15))
        let cancelled = ContinuousClock.now
        running.cancel()
        await running.value
        await recording.value
        #expect(ContinuousClock.now - cancelled < .seconds(2))
    }

    /// 이 프로세스의 `phys_footprint`(바이트). 읽지 못하면 nil.
    ///
    /// `task_info`는 C 구조체를 포인터로 채우는 호출이라 포인터를 이 함수 안에만 가둔다.
    private static func footprint() -> Int? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int(info.phys_footprint) : nil
    }

    /// 앞 4바이트에 빅엔디언 번호를 담은 `size`바이트 패킷.
    private static func indexed(_ index: Int, size: Int) -> [UInt8] {
        let value = UInt32(index)
        return [UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8),
                UInt8(truncatingIfNeeded: value)] + [UInt8](repeating: 0, count: size - 4)
    }

    /// 고치기 전에는 읽을 때마다 Pong을 꺼내 기다리지 않는 소켓에 넘겨, 쓰기가 막혀도 대기 한도(64KiB)가 걸리지 않고
    /// `NWConnection`의 버퍼만 자랐다.
    @Test("쓰기가 막힌 동안 서버가 Ping을 계속 보내면 Pong이 한도를 넘게 밀려 연결 오류로 끊긴다")
    func pingFloodEndsConnection() async throws {
        let server = try FakeDERPServer(.pingFlood)
        defer { server.close() }
        // 쓰기 기한으로 끊기지 않게 길게 둔다. 끊긴다면 Pong 적체 때문이다.
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(120))
        let log = EventLog()
        let peer = try DERPFixtures.nodeKey(7)
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))
            // 서버가 읽지 않으므로 Ping이 오기 전(1초)에 쓰기가 막힌다.
            group.addTask {
                while !Task.isCancelled {
                    await client.send(Self.packet, to: peer)
                    try await Task.sleep(for: .milliseconds(1))
                }
            }
            try await log.wait(for: ["connected", "disconnected"], within: .seconds(15))
        }
    }

    /// 고치기 전에는 `AsyncStream`의 버퍼가 종류를 가리지 않고 오래된 사건을 버려, 패킷에 밀린 `connected`가 사라졌다.
    @Test("소비가 늦어 패킷이 넘쳐도 connected는 남고, 패킷은 가장 새 것 256개가 남는다", .timeLimit(.minutes(1)))
    func connectedSurvivesPacketOverflow() async throws {
        let sent = 300
        let server = try FakeDERPServer(.packets(sent))
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(5))
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            // 서버가 보낸 패킷이 모두 사건이 될 때까지 읽지 않는다.
            try await Task.sleep(for: .seconds(1))
            var events: [DERPClient.Event] = []
            var packetCount = 0
            for await event in client.events {
                events.append(event)
                if case .packet = event { packetCount += 1 }
                if packetCount == DERPClient.eventBufferLimit { break }
            }
            guard case .connected = events.first else {
                Issue.record("첫 사건이 connected가 아니다: \(String(describing: events.first))")
                return
            }
            let indices = events.dropFirst().compactMap { event -> Int? in
                guard case let .packet(bytes, from: _) = event else { return nil }
                return bytes.count == 2 ? Int(bytes[0]) << 8 | Int(bytes[1]) : nil
            }
            #expect(indices == Array((sent - DERPClient.eventBufferLimit)..<sent))
        }
    }

    @Test("읽지 않은 연결 상태 사건은 가장 새 것 하나만 남고, 패킷 사이의 순서는 지킨다")
    func linkStateKeepsOnlyLatest() async throws {
        let queue = DERPClient.EventQueue()
        let peer = try DERPFixtures.nodeKey(1)
        queue.push(.connected)
        queue.push(.packet([1], from: peer))
        queue.push(.disconnected)
        queue.push(.connected)
        queue.push(.packet([2], from: peer))
        queue.finish()
        var seen: [String] = []
        while let event = await queue.next() { seen.append(EventLog.name(event)) }
        #expect(seen == ["packet 1", "connected", "packet 2"])
    }

    // MARK: 바이트 한도

    /// 고치기 전에는 개수 한도(256)만 있어, 큰 패킷 256개(최악 16MiB)를 쥐었다.
    @Test("읽지 않은 패킷의 바이트 합은 1MiB까지만 쥐고, 한도에 딱 맞는 16개는 모두 남고 17번째가 가장 오래된 것을 민다")
    func packetBytesAreBounded() async throws {
        #expect(DERPClient.eventBufferByteLimit == 1 << 20)
        let size = DERPConnection.maximumPacketSize
        #expect(DERPClient.eventBufferByteLimit % size == 0)
        let fits = DERPClient.eventBufferByteLimit / size
        let peer = try DERPFixtures.nodeKey(1)

        let exact = DERPClient.EventQueue()
        for tag in 0..<fits { exact.push(Self.packetEvent(UInt8(tag), size: size, from: peer)) }
        #expect(await Self.drain(exact) == (0..<fits).map { "packet \($0)" })

        let over = DERPClient.EventQueue()
        for tag in 0...fits { over.push(Self.packetEvent(UInt8(tag), size: size, from: peer)) }
        #expect(await Self.drain(over) == (1...fits).map { "packet \($0)" })
    }

    @Test("바이트 한도를 넘기려면 작은 패킷은 가장 오래된 것부터 필요한 만큼만 민다")
    func smallPacketsAreEvictedOnlyAsNeeded() async throws {
        let peer = try DERPFixtures.nodeKey(1)
        let limit = DERPClient.eventBufferByteLimit
        let queue = DERPClient.EventQueue()
        // 한도 바로 아래까지 채운다: 0번은 한도에서 1바이트가 빠진 크기, 1번은 1바이트.
        queue.push(Self.packetEvent(0, size: limit - 1, from: peer))
        queue.push(Self.packetEvent(1, size: 1, from: peer))
        // 합이 한도에 딱 맞으면 밀지 않는다(방금 1번이 들어가 합이 한도).
        // 2번(1바이트)이 들어오면 0번을 밀어야 한도 안에 든다. 1번은 남는다.
        queue.push(Self.packetEvent(2, size: 1, from: peer))
        #expect(await Self.drain(queue) == ["packet 1", "packet 2"])
    }

    @Test("바이트 때문에 패킷을 밀어도 연결 상태 사건과 peerGone은 남는다")
    func linkStateAndPeerGoneSurviveByteEviction() async throws {
        let peer = try DERPFixtures.nodeKey(1)
        let size = DERPConnection.maximumPacketSize
        let queue = DERPClient.EventQueue()
        queue.push(.connected)
        queue.push(.peerGone(peer))
        for tag in 0..<20 { queue.push(Self.packetEvent(UInt8(tag), size: size, from: peer)) }
        queue.push(.disconnected)
        let seen = await Self.drain(queue)
        #expect(seen.first == "peerGone")
        #expect(seen.last == "disconnected")
        #expect(seen.filter { $0 == "connected" }.isEmpty, "읽지 않은 연결 상태는 가장 새 것 하나만 남는다")
        #expect(seen.count(where: { $0.hasPrefix("packet") }) == DERPClient.eventBufferByteLimit / size)
    }

    @Test("읽어 간 패킷은 바이트 합에서 빠지고, 작은 패킷은 개수 한도 256개가 먼저 걸린다")
    func byteAccountingFollowsConsumption() async throws {
        let peer = try DERPFixtures.nodeKey(1)
        let size = DERPConnection.maximumPacketSize
        let fits = DERPClient.eventBufferByteLimit / size
        let queue = DERPClient.EventQueue()
        for tag in 0..<fits { queue.push(Self.packetEvent(UInt8(tag), size: size, from: peer)) }
        // 둘을 읽어 가면 그만큼 자리가 난다. 둘을 더 넣어도 아무것도 밀리지 않는다.
        _ = await queue.next()
        _ = await queue.next()
        for tag in fits..<fits + 2 { queue.push(Self.packetEvent(UInt8(tag), size: size, from: peer)) }
        #expect(await Self.drain(queue) == (2..<fits + 2).map { "packet \($0)" })

        let small = DERPClient.EventQueue()
        for tag in 0..<DERPClient.eventBufferLimit + 1 { small.push(.packet([UInt8(tag % 256)], from: peer)) }
        let kept = await Self.drain(small)
        #expect(kept.count == DERPClient.eventBufferLimit)
        #expect(kept.first == "packet 1")
    }

    // MARK: 인터페이스

    /// 서버가 루프백이면 묶지 않으므로, 어떤 인터페이스를 주어도 루프백의 가짜 서버에 붙는다. 인터페이스를 준 클라이언트의
    /// 연결 경로(묶는 쪽)가 실제로 돈다. 묶음 자체는 `SwiftailIOTests`가 확인한다.
    @Test("인터페이스를 준 클라이언트도 루프백 서버에는 묶지 않고 붙는다")
    func connectsToLoopbackServerWithInterface() async throws {
        let server = try FakeDERPServer(.silent)
        defer { server.close() }
        let monitor = NWPathMonitor()
        defer { monitor.cancel() }
        var wrongInterface: NWInterface?
        for await path in monitor {
            wrongInterface = path.availableInterfaces.first { $0.type != .loopback }
            break
        }
        let interface = try #require(wrongInterface, "루프백이 아닌 인터페이스가 없다")
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(5), interface: interface)
        let log = EventLog()
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))
        }
    }
}

/// 사건을 받아 이름으로 적어 두고, 기대한 순서가 나타날 때까지 기다린다.
private final class EventLog: Sendable {
    private let names = Mutex<[String]>([])

    static func name(_ event: DERPClient.Event) -> String {
        switch event {
        case .connected: "connected"
        case .disconnected: "disconnected"
        case let .packet(bytes, from: _): "packet \(bytes.first ?? 0)"
        case .peerGone: "peerGone"
        }
    }

    func record(_ events: AsyncStream<DERPClient.Event>) async {
        for await event in events {
            names.withLock { $0.append(Self.name(event)) }
        }
    }

    /// 연결 상태 사건만 보아 `expected`가 앞에서부터 차례로 나타날 때까지 기다린다.
    func wait(for expected: [String], within duration: Duration) async throws {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            let states = names.withLock { $0.filter { !$0.hasPrefix("packet") } }
            if states.starts(with: expected) { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        let states = names.withLock { $0.filter { !$0.hasPrefix("packet") } }
        Issue.record("\(duration) 안에 \(expected)가 나오지 않았다: \(states)")
        throw CancellationError()
    }
}

/// 루프백의 가짜 DERP 서버(평문). 받아들인 연결마다 101 응답, ServerKey, ServerInfo를 보낸 뒤 `behavior`대로 한다.
/// `reading`이 아니면 클라이언트가 보낸 바이트는 읽지 않는다.
private final class FakeDERPServer: Sendable {
    enum Behavior: Sendable {
        /// 핸드셰이크 뒤 아무것도 하지 않는다.
        case silent
        /// 핸드셰이크 뒤 2바이트 번호(0부터)를 담은 RecvPacket을 이만큼 보낸다.
        case packets(Int)
        /// 핸드셰이크 뒤 클라이언트가 보낸 바이트를 끝까지 읽는다. `keep`이면 `received`에 모은다.
        case reading(keep: Bool)
        /// 핸드셰이크 뒤 1초를 기다렸다가 Ping을 끝없이 보낸다. 100개(1,300바이트)씩 5ms 간격으로 보내, 한 번 읽은 조각에서
        /// 나오는 Pong은 한도(64KiB)에 한참 못 미친다. 한도를 넘는다면 쓰지 못한 Pong이 쌓였기 때문이다.
        case pingFlood
    }

    private let listener: NWListener
    private let accepted = Accepted()

    private final class Accepted: Sendable {
        let connections = Mutex<[NWConnection]>([])
        let floods = Mutex<[Task<Void, Never>]>([])
        let received = Mutex<[UInt8]>([])
    }

    var acceptedCount: Int { accepted.connections.withLock { $0.count } }

    init(_ behavior: Behavior) throws {
        let handshake = DERPFixtures.Server.upgradeResponse + (try DERPFixtures.Server.serverKeyFrame()) + (try DERPFixtures.Server.serverInfoFrame())
        let sender = try DERPFixtures.nodeKey(9)
        let pings = (0..<100).flatMap { _ in DERPFixtures.Server.frame(0x12, [1, 2, 3, 4, 5, 6, 7, 8]) }
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [accepted] connection in
            connection.start(queue: .global())
            accepted.connections.withLock { $0.append(connection) }
            switch behavior {
            case .silent:
                connection.send(content: Data(handshake), completion: .contentProcessed { _ in })
            case .packets(let count):
                let frames = (0..<count).flatMap { index in
                    DERPFixtures.Server.recvPacket(from: sender, [UInt8(index >> 8), UInt8(index & 0xFF)])
                }
                connection.send(content: Data(handshake + frames), completion: .contentProcessed { _ in })
            case .reading(let keep):
                connection.send(content: Data(handshake), completion: .contentProcessed { _ in })
                Self.read(from: connection, keep: keep, into: accepted)
            case .pingFlood:
                connection.send(content: Data(handshake), completion: .contentProcessed { _ in })
                let flood = Task {
                    try? await Task.sleep(for: .seconds(1))
                    while !Task.isCancelled, await Self.write(pings, to: connection) {
                        try? await Task.sleep(for: .milliseconds(5))
                    }
                }
                accepted.floods.withLock { $0.append(flood) }
            }
        }
    }

    /// 보내고 스택이 받아 갈 때까지 기다린다. 연결이 실패했으면 false.
    private static func write(_ bytes: [UInt8], to connection: NWConnection) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in continuation.resume(returning: error == nil) })
        }
    }

    /// 끝까지 읽는다. 읽은 바이트는 `keep`일 때만 모은다.
    private static func read(from connection: NWConnection, keep: Bool, into accepted: Accepted) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, isComplete, error in
            if keep, let data { accepted.received.withLock { $0 += data } }
            guard error == nil, !isComplete else { return }
            read(from: connection, keep: keep, into: accepted)
        }
    }

    /// 클라이언트가 보낸 SendPacket 프레임들의 패킷 앞 4바이트 번호(빅엔디언). HTTP 요청 머리를 건너뛰고, 끝의 덜 온
    /// 프레임은 무시한다.
    func sentPacketIndices() -> [Int] {
        let bytes = accepted.received.withLock { $0 }
        let headEnd = Array("\r\n\r\n".utf8)
        guard var offset = bytes.indices.first(where: { bytes[$0...].starts(with: headEnd) }).map({ $0 + headEnd.count }) else {
            return []
        }
        var indices: [Int] = []
        while offset + DERPFrame.headerSize <= bytes.count {
            let length = bytes[(offset + 1)..<(offset + 5)].reduce(0) { $0 << 8 | Int($1) }
            let body = offset + DERPFrame.headerSize
            guard body + length <= bytes.count else { break }
            if bytes[offset] == DERPFrame.Kind.sendPacket.rawValue {
                let packet = body + DERPFrame.keySize
                indices.append(bytes[packet..<(packet + 4)].reduce(0) { $0 << 8 | Int($1) })
            }
            offset = body + length
        }
        return indices
    }

    /// 받아들인 연결을 모두 끊는다. 듣기는 계속한다.
    func dropConnections() {
        accepted.connections.withLock { connections in
            for connection in connections { connection.cancel() }
        }
    }

    func port() async throws -> UInt16 {
        let listener = listener
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue {
                        once.withLock { $0.take() }?.resume(returning: port)
                    }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
    }

    func close() {
        listener.cancel()
        accepted.floods.withLock { floods in
            for flood in floods { flood.cancel() }
            floods = []
        }
        accepted.connections.withLock { connections in
            for connection in connections { connection.cancel() }
            connections = []
        }
    }
}
