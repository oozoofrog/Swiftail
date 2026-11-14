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
/// 클라이언트가 보낸 바이트는 읽지 않는다.
private final class FakeDERPServer: Sendable {
    enum Behavior: Sendable {
        /// 핸드셰이크 뒤 아무것도 하지 않는다.
        case silent
        /// 핸드셰이크 뒤 2바이트 번호(0부터)를 담은 RecvPacket을 이만큼 보낸다.
        case packets(Int)
        /// 핸드셰이크 뒤 1초를 기다렸다가 Ping을 끝없이 보낸다. 100개(1,300바이트)씩 5ms 간격으로 보내, 한 번 읽은 조각에서
        /// 나오는 Pong은 한도(64KiB)에 한참 못 미친다. 한도를 넘는다면 쓰지 못한 Pong이 쌓였기 때문이다.
        case pingFlood
    }

    private let listener: NWListener
    private let accepted = Accepted()

    private final class Accepted: Sendable {
        let connections = Mutex<[NWConnection]>([])
        let floods = Mutex<[Task<Void, Never>]>([])
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
