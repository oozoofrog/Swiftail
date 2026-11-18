import Foundation
import Network
import SwiftailBase
import Synchronization
import Testing

@testable import SwiftailDERP

/// Memory limits and event buffering in `DERPClient`. Connects to a fake loopback server (plaintext).
///
/// Runs serially. Concurrent tests that hold several MiB of 64KiB packets make the test measuring `phys_footprint` growth unstable.
@Suite("DERP client limits", .serialized)
struct DERPClientTests {
    private static let packet = [UInt8](repeating: 0x5A, count: DERPConnection.maximumPacketSize)

    private static func client(port: UInt16, writeTimeout: Duration, interface: NWInterface? = nil) throws -> DERPClient {
        let server = DERPServer(hostName: "127.0.0.1", targets: [.address(try #require(IPAddress("127.0.0.1")))], port: port, verification: .noneForTests)
        return DERPClient(
            servers: [server], privateKey: try DERPFixtures.privateKey(seed: DERPFixtures.clientSeed), isPreferred: true,
            interface: interface, writeTimeout: writeTimeout, plaintextForTests: true
        )
    }

    /// A packet event with a `size`-byte body whose first byte is `tag`.
    private static func packetEvent(_ tag: UInt8, size: Int, from peer: NodePublicKey) -> DERPClient.Event {
        .packet([tag] + [UInt8](repeating: 0, count: size - 1), from: peer)
    }

    private static func drain(_ queue: DERPClient.EventQueue) async -> [String] {
        queue.finish()
        var seen: [String] = []
        while let event = await queue.next() { seen.append(EventLog.name(event)) }
        return seen
    }

    /// Before the fix, packets went straight to the socket while connected. The socket did not wait, so blocked writes only grew memory without disconnecting.
    @Test("Repeatedly sending to a server that does not read retains at most 32 packets, then disconnects and reconnects when the write deadline passes")
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

    /// Before the fix, when the write watchdog disconnected, the write loop drained the entire queue into the closed socket, losing the whole queue.
    @Test("If blocked writes cause a disconnect, queued packets go out in order on the next connection")
    func queueSurvivesStalledWrite() async throws {
        let server = try FakeDERPServer(.silentThenReading)
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(1))
        let log = EventLog()
        let peer = try DERPFixtures.nodeKey(7)
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))

            // A full queue that does not shrink means writes are blocked. Record the numbers of the packets queued at that point.
            var held: [Int] = []
            for index in 0..<10_000 where held.isEmpty {
                await client.send(Self.indexed(index, size: DERPConnection.maximumPacketSize), to: peer)
                guard await client.queuedPackets.count == DERPClient.queuedPacketLimit else { continue }
                try await Task.sleep(for: .milliseconds(50))
                let queued = await client.queuedPackets
                if queued.count == DERPClient.queuedPacketLimit {
                    held = queued.map { $0.packet.prefix(4).reduce(0) { $0 << 8 | Int($1) } }
                }
            }
            try #require(held.count == DERPClient.queuedPacketLimit)

            try await log.wait(for: ["connected", "disconnected", "connected"], within: .seconds(20))
            let deadline = ContinuousClock.now + .seconds(10)
            while server.sentPacketIndices().count < held.count, ContinuousClock.now < deadline {
                try await Task.sleep(for: .milliseconds(20))
            }
            #expect(server.sentPacketIndices() == held)
        }
    }

    // MARK: Write batching and the write watchdog

    @Test("A batch always includes the first packet and adds more until the combined packet frames would exceed 64KiB")
    func packetsPerWrite() {
        let frameOverhead = DERPFrame.headerSize + DERPFrame.keySize
        #expect(DERPClient.packetCountForNextWrite([]) == 0)
        // All 32 typical WireGuard datagrams (the queue limit) fit in one batch.
        #expect(DERPClient.packetCountForNextWrite(Array(repeating: 1_400, count: DERPClient.queuedPacketLimit)) == 32)
        // The largest packet forms a batch by itself even if it exceeds the limit.
        let largest = DERPConnection.maximumPacketSize
        #expect(DERPClient.packetCountForNextWrite([largest, largest, 1]) == 1)
        #expect(DERPClient.packetCountForNextWrite([1, largest]) == 1)
        // Include the packet if the total equals the limit. If it exceeds the limit by even 1 byte, defer it to the next batch.
        let half = DERPClient.maximumWriteBytes / 2 - frameOverhead
        #expect(DERPClient.packetCountForNextWrite([half, half, 0]) == 2)
        #expect(DERPClient.packetCountForNextWrite([half, half + 1]) == 1)
    }

    /// Batched writes still send every frame in `send` call order. Wait for the queue to empty after each batch to avoid overflowing it.
    @Test("Batched packets all reach the server in the order sent")
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

    /// Before the fix, each write used `withTimeout`, leaving the deadline Task and timer alive until the deadline even when the write finished promptly
    /// (about 700 bytes per write). With a deadline of 60 seconds, none are released during the test, so all retained allocations accumulate.
    @Test("Memory does not accumulate across many writes that finish promptly")
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
            // Send one packet and wait for the queue to drain, so each batch is one packet and therefore one write.
            while ContinuousClock.now - started < .seconds(4) {
                await client.send(packet, to: peer)
                while await !client.queuedPackets.isEmpty { await Task.yield() }
                writes += 1
            }
            let growth = try #require(Self.footprint()) - before
            // Leave a large margin because other tests run in the same process at the same time.
            #expect(writes > 10_000, "Too few writes to detect retained allocations: \(writes)")
            #expect(growth < 16 << 20, "phys_footprint grew by \(growth) bytes after \(writes) writes")
            #expect(server.acceptedCount == 1)
        }
    }

    /// The write watchdog is a child of the connection's TaskGroup. Even with a 60-second deadline, a disconnect moves to the next connection and cancellation stops immediately.
    @Test("A disconnect triggers reconnect, and cancellation makes run() return promptly along with the write watchdog")
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

    /// This process's `phys_footprint` in bytes, or nil if it cannot be read.
    ///
    /// `task_info` fills a C struct through a pointer, so the pointer stays inside this function.
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

    /// A `size`-byte packet with a big-endian number in its first 4 bytes.
    private static func indexed(_ index: Int, size: Int) -> [UInt8] {
        let value = UInt32(index)
        return [UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8),
                UInt8(truncatingIfNeeded: value)] + [UInt8](repeating: 0, count: size - 4)
    }

    /// Before the fix, each read drained Pong replies into a socket that did not wait, so blocked writes never hit the pending limit (64KiB) and only the
    /// `NWConnection` buffer grew.
    @Test("If the server keeps sending Ping while writes are blocked, Pong replies back up past the limit and a connection error disconnects")
    func pingFloodEndsConnection() async throws {
        let server = try FakeDERPServer(.pingFlood)
        defer { server.close() }
        // Use a long write deadline so it does not cause a disconnect. A disconnect is due to accumulated Pong replies.
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(120))
        let log = EventLog()
        let peer = try DERPFixtures.nodeKey(7)
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await log.wait(for: ["connected"], within: .seconds(10))
            // The server does not read, so writes block before the Ping arrives (1 second).
            group.addTask {
                while !Task.isCancelled {
                    await client.send(Self.packet, to: peer)
                    try await Task.sleep(for: .milliseconds(1))
                }
            }
            try await log.wait(for: ["connected", "disconnected"], within: .seconds(15))
        }
    }

    /// Before the fix, the `AsyncStream` buffer discarded old events regardless of type, so packets could push out `connected`.
    @Test("If slow consumption causes packet overflow, connected stays and the newest 256 packets remain", .timeLimit(.minutes(1)))
    func connectedSurvivesPacketOverflow() async throws {
        let sent = 300
        let server = try FakeDERPServer(.packets(sent))
        defer { server.close() }
        let client = try Self.client(port: try await server.port(), writeTimeout: .seconds(5))
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            // Wait to read until all packets sent by the server have become events.
            try await Task.sleep(for: .seconds(1))
            var events: [DERPClient.Event] = []
            var packetCount = 0
            for await event in client.events {
                events.append(event)
                if case .packet = event { packetCount += 1 }
                if packetCount == DERPClient.eventBufferLimit { break }
            }
            guard case .connected = events.first else {
                Issue.record("The first event is not connected: \(String(describing: events.first))")
                return
            }
            let indices = events.dropFirst().compactMap { event -> Int? in
                guard case let .packet(bytes, from: _) = event else { return nil }
                return bytes.count == 2 ? Int(bytes[0]) << 8 | Int(bytes[1]) : nil
            }
            #expect(indices == Array((sent - DERPClient.eventBufferLimit)..<sent))
        }
    }

    @Test("Only the newest unread connection state event remains, and order relative to packets is preserved")
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

    // MARK: Byte limit

    /// Before the fix, there was only a count limit (256), so 256 large packets could be retained (16MiB in the worst case).
    @Test("Unread packets retain at most 1MiB in total. All 16 that exactly fill the limit stay, and the 17th evicts the oldest")
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

    @Test("When small packets push the total past the byte limit, only the oldest packets are evicted, and only as many as needed")
    func smallPacketsAreEvictedOnlyAsNeeded() async throws {
        let peer = try DERPFixtures.nodeKey(1)
        let limit = DERPClient.eventBufferByteLimit
        let queue = DERPClient.EventQueue()
        // Fill to just below the limit: packet 0 is 1 byte under the limit and packet 1 is 1 byte.
        queue.push(Self.packetEvent(0, size: limit - 1, from: peer))
        queue.push(Self.packetEvent(1, size: 1, from: peer))
        // No eviction occurs when the total exactly equals the limit (packet 1 just filled it).
        // When packet 2 (1 byte) arrives, packet 0 must be evicted to fit. Packet 1 stays.
        queue.push(Self.packetEvent(2, size: 1, from: peer))
        #expect(await Self.drain(queue) == ["packet 1", "packet 2"])
    }

    @Test("Connection state events and peerGone remain when packets are evicted by the byte limit")
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
        #expect(seen.filter { $0 == "connected" }.isEmpty, "Only the newest unread connection state remains")
        #expect(seen.count(where: { $0.hasPrefix("packet") }) == DERPClient.eventBufferByteLimit / size)
    }

    @Test("Consumed packets are removed from the byte total, and small packets hit the count limit of 256 first")
    func byteAccountingFollowsConsumption() async throws {
        let peer = try DERPFixtures.nodeKey(1)
        let size = DERPConnection.maximumPacketSize
        let fits = DERPClient.eventBufferByteLimit / size
        let queue = DERPClient.EventQueue()
        for tag in 0..<fits { queue.push(Self.packetEvent(UInt8(tag), size: size, from: peer)) }
        // Consuming two packets frees that much space. Adding two more causes no evictions.
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

    // MARK: Interfaces

    /// Loopback connections skip interface binding, so the fake loopback server is reachable regardless of the supplied interface. This exercises the
    /// client connection path for a supplied interface (the binding branch). `SwiftailIOTests` verifies binding itself.
    @Test("A client with a supplied interface connects to a loopback server without binding to the interface")
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
        let interface = try #require(wrongInterface, "No non-loopback interface found")
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

/// Records events by name and waits for the expected sequence to appear.
final class EventLog: Sendable {
    private let names = Mutex<[String]>([])

    static func name(_ event: DERPClient.Event) -> String {
        switch event {
        case .connected: "connected"
        case .disconnected: "disconnected"
        case let .attemptFailed(failure, consecutiveFailures): "attemptFailed \(failure) \(consecutiveFailures)"
        case let .packet(bytes, from: _): "packet \(bytes.first ?? 0)"
        case .peerGone: "peerGone"
        }
    }

    func record(_ events: AsyncStream<DERPClient.Event>) async {
        for await event in events {
            names.withLock { $0.append(Self.name(event)) }
        }
    }

    /// All recorded event names.
    var all: [String] { names.withLock { $0 } }

    /// Waits for `expected` to appear in order among connection state events. Ignores `attemptFailed`.
    func wait(for expected: [String], within duration: Duration) async throws {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            if linkStates.starts(with: expected) { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        Issue.record("\(expected) did not appear within \(duration): \(linkStates)")
        throw CancellationError()
    }

    /// Waits for the event named `name`.
    func wait(forEvent name: String, within duration: Duration) async throws {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            if all.contains(name) { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        Issue.record("\(name) did not appear within \(duration): \(all)")
        throw CancellationError()
    }

    private var linkStates: [String] {
        names.withLock { $0.filter { !$0.hasPrefix("packet") && !$0.hasPrefix("attemptFailed") } }
    }
}

/// A fake loopback DERP server (plaintext). For each accepted connection, sends a 101 response, ServerKey, and ServerInfo, then follows `behavior`.
/// Reads bytes sent by the client only for `reading` and `unresponsive`.
final class FakeDERPServer: Sendable {
    enum Behavior: Sendable {
        /// Does nothing after the handshake.
        case silent
        /// After the handshake, sends this many RecvPacket frames with 2-byte sequence numbers starting at 0.
        case packets(Int)
        /// Reads all bytes sent by the client after the handshake. Collects them in `received` if `keep` is true.
        case reading(keep: Bool)
        /// Uses `silent` for the first connection and `reading(keep: true)` for subsequent connections.
        case silentThenReading
        /// Waits 1 second after the handshake, then sends Ping indefinitely. Sends 100 at a time (1,300 bytes) at 5ms intervals, so the Pongs from one
        /// read chunk are well below the limit (64KiB). Exceeding the limit means unwritten Pongs have accumulated.
        case pingFlood
        /// Sends nothing and reads all bytes sent by the client. The client stalls at the handshake.
        case unresponsive
    }

    private let listener: NWListener
    private let accepted = Accepted()

    private final class Accepted: Sendable {
        let connections = Mutex<[NWConnection]>([])
        let floods = Mutex<[Task<Void, Never>]>([])
        let received = Mutex<[UInt8]>([])
        /// Number of connections observed to close during a read (closed by the client or by `dropConnections`).
        let closedCount = Mutex(0)
    }

    var acceptedCount: Int { accepted.connections.withLock { $0.count } }
    /// Number of accepted connections still open. Accurate only for behaviors that read (`reading` and `unresponsive`).
    var openCount: Int { acceptedCount - accepted.closedCount.withLock { $0 } }

    /// - Parameters:
    ///   - host: The loopback address to listen on (`127.0.0.1` or `::1`).
    ///   - port: The port to listen on. The system chooses it for `.any`.
    init(_ behavior: Behavior, host: NWEndpoint.Host = "127.0.0.1", port: NWEndpoint.Port = .any) throws {
        let handshake = DERPFixtures.Server.upgradeResponse + (try DERPFixtures.Server.serverKeyFrame()) + (try DERPFixtures.Server.serverInfoFrame())
        let sender = try DERPFixtures.nodeKey(9)
        let pings = (0..<100).flatMap { _ in DERPFixtures.Server.frame(0x12, [1, 2, 3, 4, 5, 6, 7, 8]) }
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: host, port: port)
        // Without this option, `::1` cannot listen on a port used by `127.0.0.1` (EADDRINUSE). With it enabled, each family still reaches only its own listener.
        parameters.allowLocalEndpointReuse = true
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [accepted] connection in
            connection.start(queue: .global())
            let isFirst = accepted.connections.withLock { connections in
                connections.append(connection)
                return connections.count == 1
            }
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
            case .silentThenReading:
                connection.send(content: Data(handshake), completion: .contentProcessed { _ in })
                if !isFirst { Self.read(from: connection, keep: true, into: accepted) }
            case .pingFlood:
                connection.send(content: Data(handshake), completion: .contentProcessed { _ in })
                let flood = Task {
                    try? await Task.sleep(for: .seconds(1))
                    while !Task.isCancelled, await Self.write(pings, to: connection) {
                        try? await Task.sleep(for: .milliseconds(5))
                    }
                }
                accepted.floods.withLock { $0.append(flood) }
            case .unresponsive:
                Self.read(from: connection, keep: false, into: accepted)
            }
        }
    }

    /// Sends bytes and waits for the stack to accept them. Returns false if the connection failed.
    private static func write(_ bytes: [UInt8], to connection: NWConnection) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in continuation.resume(returning: error == nil) })
        }
    }

    /// Reads to the end. Collects the bytes read only when `keep` is true.
    private static func read(from connection: NWConnection, keep: Bool, into accepted: Accepted) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, isComplete, error in
            if keep, let data { accepted.received.withLock { $0 += data } }
            guard error == nil, !isComplete else {
                accepted.closedCount.withLock { $0 += 1 }
                return
            }
            read(from: connection, keep: keep, into: accepted)
        }
    }

    /// The big-endian numbers in the first 4 bytes of packets in SendPacket frames sent by the client. Skips the HTTP request header and ignores
    /// an incomplete frame at the end.
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

    /// Closes all accepted connections and continues listening.
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
