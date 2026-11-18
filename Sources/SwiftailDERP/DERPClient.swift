import CryptoKit
import Network
import SwiftailBase
import SwiftailIO

/// Maintains a connection to one DERP server. Backs off and reconnects after a disconnect.
///
/// This is the only place in the package with a socket and a clock. The I/O-free state machine (`DERPConnection`) makes
/// protocol decisions. This actor feeds it bytes and times and emits the results as events (`events`).
///
/// Uses structured concurrency. For the lifetime of one connection, `run()` runs the read loop, write loop, write watchdog, and idle watchdog as children of one TaskGroup.
/// Canceling the Task that called `run()` stops all children and closes the socket. Creates no detached Tasks.
///
/// ```swift
/// let client = DERPClient(servers: [server], privateKey: nodeKey, isPreferred: true)
/// async let running: Void = client.run()
/// await client.send(packet, to: peer)
/// for await event in client.events { … }
/// ```
///
/// Providing `interface` restricts the connection to that interface (to keep the DERP connection from looping back into the packet tunnel).
/// If the interface changes, close this client and create a new one with the new interface. Moving a connection to a different interface
/// requires closing it (`docs/contracts/SwiftailTunnel.md` behavior N §3.2).
/// `shortcut:` does not report network loss (no satisfied path). The connection relies on this client's retries and backoff.
/// Add reporting if retries while the network is unavailable cause battery or memory problems on a real device (same document, behavior N §5).
///
/// Memory limits (the iOS network extension has about 50MB).
///
/// - Caps unread incoming events by both count (`eventBufferLimit`) and total packet bytes (`eventBufferByteLimit`).
/// - `send` queues a packet without waiting. The queue holds up to `queuedPacketLimit` packets regardless of connection state and
///   drops the oldest on overflow.
/// - The write loop combines pending Pong replies and queued packets (up to `maximumWriteBytes` total for the packet frames)
///   into one batch for `NetworkSocket.write`. It waits for the socket to accept it before taking the next batch. While the write is blocked,
///   Pong replies accumulate in the state machine. Above 64KiB the state machine ends the connection with `tooManyPendingReplies`. A batch
///   that fails to complete within `writeTimeout` is also a connection error (write watchdog). Both cases disconnect and reconnect.
/// - One watchdog per connection checks the start time of the current write to enforce the write deadline, without creating a Task or timer
///   per write. Using `withTimeout` for each write left canceled timer Tasks alive until the deadline (5 seconds), so memory grew with the write rate.
/// - Writes go out in call order, so each frame is sent whole and in order.
///
/// Reads continue during blocked writes because the reader is a separate child. The server disconnects if it cannot write within 2 seconds.
///
/// Contract `docs/contracts/SwiftailDERP.md` "DERPClient" and `docs/protocol-notes/derp-stun.md` §4.1 and §4.4~§4.6
/// (origin: tailscale.com `derp/derphttp/derphttp_client.go` and `wgengine/magicsock/derp.go`, BSD-3-Clause).
public actor DERPClient {
    public enum Event: Sendable {
        case connected
        case disconnected
        /// The connection could not be opened (one attempt that did not reach `connected`). Backs off and retries.
        ///
        /// `consecutiveFailures` counts consecutive attempts that could not open a connection since the last successful one (or since startup), starting at 1.
        /// Attempts stopped by cancellation do not emit this event.
        case attemptFailed(AttemptFailure, consecutiveFailures: Int)
        case packet([UInt8], from: NodePublicKey)
        case peerGone(NodePublicKey)
    }

    /// The kind of failure to open a connection. Safe to log as is, since it contains no values such as addresses, keys, or names.
    public enum AttemptFailure: Sendable, Equatable {
        /// The deadline from the start of dialing to `ready` (`readyTimeout`, 10 seconds) elapsed.
        case timedOut
        /// TCP or TLS could not connect. This includes connection refusal, no route, name resolution failure, and certificate rejection
        /// (the socket layer does not report which occurred).
        case connectionFailed
        /// The server connected, then rejected the upgrade or handshake, sent bytes that violated the specification, or disconnected.
        case handshakeFailed
        /// No target to dial (the server list or the last server's `targets` is empty).
        case noServers

        init(_ error: any Error) {
            switch error {
            case is TimeoutError:
                self = .timedOut
            case let socketError as SocketError:
                if case .connectFailed = socketError { self = .connectionFailed } else { self = .handshakeFailed }
            case let disconnection as Disconnection where disconnection == .noServers:
                self = .noServers
            default:
                self = .handshakeFailed
            }
        }
    }

    /// The maximum unread `attemptFailed`, `packet`, and `peerGone` events. Drops the oldest first on overflow.
    static let eventBufferLimit = 256
    /// The byte limit for unread `packet` event bodies (1MiB). Drops the oldest packets first on overflow.
    ///
    /// The count limit alone permits up to 65,536 bytes per packet × 256 packets = 16MiB in the worst case. That is about a third of the iOS packet tunnel
    /// extension's limit (about 50MiB), so three receive buffers would exceed it. 1MiB is one sixteenth of that worst case. This is a proposed value based only on this calculation
    /// (`docs/contracts/SwiftailTunnel.md` behavior M). Adjust it if real device throughput measurements show packet drops. Packets are datagrams and may
    /// be dropped (TCP over WireGuard retransmits). One maximum-size packet (65,536 bytes) fits within the limit, so no individual packet
    /// can exceed it.
    static let eventBufferByteLimit = 1 << 20
    /// The maximum packets still waiting to be written to the socket, regardless of connection state. Drops the oldest on overflow.
    ///
    /// Matches `derpWriteQueueDepth = 32` (the write queue for one regional connection) in Go's `wgengine/magicsock/derp.go`, and dropping the oldest
    /// on overflow matches `sendDerp` in `magicsock.go`. As the Go comment notes, a queue above the TCP buffer is almost pure
    /// bufferbloat, so keep it shallow.
    static let queuedPacketLimit = 32
    /// The total byte limit of packet frames in one batch (64KiB). Includes the first packet regardless of size.
    ///
    /// One batch contains at most 64KiB of packet frames (65,573 bytes for one maximum-size packet frame) plus Pong replies (at most 64KiB), with at most
    /// 32 packets per the queue limit. A single batch fits 32 typical WireGuard datagrams (about 1.3KB each). `NWConnection` holds a separate
    /// copy of the batch passed to the socket, so keeping the batch small reduces the memory held alongside the queue (up to about 2MiB).
    static let maximumWriteBytes = 64 * 1024
    /// The deadline for handing one batch off to the socket. Disconnects if it elapses.
    ///
    /// Follows the 5-second timer that `ForwardPacket` in Go's `derp/derp_client.go` sets for each write (`writeTimeoutFired` closes the connection).
    /// Go's `send` (SendPacket) has no deadline, and the writing goroutine blocks on TCP. This client applies the same 5 seconds to all writes
    /// so a blocked connection cannot retain the queue and Pong replies. The 5 seconds apply to one batch.
    static let writeTimeout = Duration.seconds(5)
    /// The deadline for a TCP connection attempt to one server.
    static let tcpTimeout = Duration.milliseconds(1500)
    /// The deadline from connection through `ready`.
    static let readyTimeout = Duration.seconds(10)
    /// Disconnects after this much time without receiving anything. The server sends KeepAlive every 60 seconds + [0, 5) seconds.
    static let idleTimeout = Duration.seconds(120)
    static let maximumBackoff = Duration.seconds(5)

    private let servers: [DERPServer]
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private let isPreferred: Bool
    private let writeTimeout: Duration
    /// True only when tests connect without TLS to a fake server on loopback.
    private let plaintextForTests: Bool
    /// The interface to bind the connection to. A nil value leaves the connection unbound.
    private let interface: NWInterface?
    private let eventStream: AsyncStream<Event>
    private let eventQueue = EventQueue()

    private var hasRun = false
    /// The current connection, or nil before readiness and after disconnection.
    private var connection: DERPConnection?
    /// Packets still waiting to be written to the socket. The write loop takes them from the front.
    private(set) var queuedPackets: [(peer: NodePublicKey, packet: [UInt8])] = []
    /// Wakes the write loop of the current connection. Nil when there is no connection.
    private var writeSignal: AsyncStream<Void>.Continuation?
    /// The start time of the batch write currently being handed to the socket, or nil when idle. The write watchdog uses this time.
    private var writeStartedAt: ContinuousClock.Instant?
    /// The most recent time bytes were received. The idle watchdog uses this time.
    private var lastReceive = ContinuousClock.now
    /// The consecutive failure count. Resets to 1 when a connection that received a frame disconnects.
    private var consecutiveFailures = 0
    /// The consecutive count of attempts that failed to open a connection. Resets to 0 when a connection opens. Included in `attemptFailed`.
    private var consecutiveAttemptFailures = 0

    /// - Parameters:
    ///   - servers: The servers in one region. Tries them in list order.
    ///   - interface: The outbound interface. With nil, the system chooses. Leaves loopback server connections unbound.
    public init(
        servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, interface: NWInterface? = nil
    ) {
        self.init(
            servers: servers, privateKey: privateKey, isPreferred: isPreferred, interface: interface,
            writeTimeout: Self.writeTimeout, plaintextForTests: false
        )
    }

    /// Used by tests to inject a short write deadline and a plaintext connection.
    init(
        servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, interface: NWInterface? = nil,
        writeTimeout: Duration, plaintextForTests: Bool
    ) {
        self.servers = servers
        self.interface = interface
        self.privateKey = privateKey
        self.isPreferred = isPreferred
        self.writeTimeout = writeTimeout
        self.plaintextForTests = plaintextForTests
        let queue = eventQueue
        eventStream = AsyncStream(unfolding: { await queue.next() })
    }

    /// The event stream. Supports one subscriber. Ends when `run()` ends.
    ///
    /// With a slow consumer, keeps up to the newest 256 `attemptFailed`, `packet`, and `peerGone` events and 1MiB of total packet bytes, dropping
    /// the oldest first. Packets are datagrams and may be dropped. Preserves `connected` and `disconnected`, keeping just the latest unread state event
    /// (`EventQueue`).
    public nonisolated var events: AsyncStream<Event> { eventStream }

    /// Connects, reads, and reconnects after a disconnect. Returns only when the calling Task is canceled.
    ///
    /// Call once per client. Subsequent calls return immediately.
    public func run() async {
        guard !hasRun else { return }
        hasRun = true
        defer { eventQueue.finish() }

        while !Task.isCancelled {
            let receivedFrame = await serveOneConnection()
            if Task.isCancelled { return }
            consecutiveFailures = receivedFrame ? 1 : consecutiveFailures + 1
            let delay = Backoff.delay(failures: consecutiveFailures, maximum: Self.maximumBackoff, jitter: .random(in: 0..<1))
            do {
                try await Task.sleep(for: delay, clock: .continuous)
            } catch {
                return
            }
        }
    }

    /// Sends a packet. Queues it without waiting. If disconnected, sends it after reconnecting.
    ///
    /// The queue holds up to 32 packets and drops the oldest on overflow. Drops packets over 65,536 bytes.
    public func send(_ packet: [UInt8], to peer: NodePublicKey) {
        guard packet.count <= DERPConnection.maximumPacketSize else { return }
        if queuedPackets.count == Self.queuedPacketLimit { queuedPackets.removeFirst() }
        queuedPackets.append((peer, packet))
        writeSignal?.yield()
    }

    // MARK: One connection

    /// Runs one connection for its lifetime. Closes the socket and clears state on error or cancellation. Returns true if a frame arrived after the handshake.
    private func serveOneConnection() async -> Bool {
        let opened: OpenedConnection
        do {
            let (servers, privateKey, isPreferred, plaintextForTests, interface) =
                (servers, privateKey, isPreferred, plaintextForTests, interface)
            opened = try await withTimeout(Self.readyTimeout) {
                try await Self.open(
                    servers: servers, privateKey: privateKey, isPreferred: isPreferred, plaintextForTests: plaintextForTests,
                    interface: interface
                )
            }
        } catch {
            if !Task.isCancelled {
                consecutiveAttemptFailures += 1
                eventQueue.push(.attemptFailed(AttemptFailure(error), consecutiveFailures: consecutiveAttemptFailures))
            }
            return false
        }

        consecutiveAttemptFailures = 0
        connection = opened.connection
        lastReceive = .now
        let (signals, signal) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        writeSignal = signal
        // Write queued packets and Pong replies to Ping frames that arrived in the handshake chunk immediately.
        signal.yield()
        eventQueue.push(.connected)
        deliver(opened.events)

        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                defer { group.cancelAll() }
                group.addTask { try await self.readLoop(from: opened.socket) }
                group.addTask { await self.writeLoop(to: opened.socket, signals: signals) }
                group.addTask { try await self.watchForStalledWrite() }
                group.addTask { try await self.watchForIdleness() }
                try await group.next()
            }
        } catch {
            // A read error, server close, write deadline, Pong backlog, idle timeout, or cancellation ends this connection. The caller backs off
            // and reconnects.
        }

        // Reconnect only after closing the socket. If two connections share a key, the server forwards packets to only one of them.
        opened.socket.close()
        signal.finish()
        writeSignal = nil
        let receivedFrame = connection?.hasReceivedFrameAfterHandshake ?? false
        connection = nil
        eventQueue.push(.disconnected)
        return receivedFrame
    }

    /// Receives from the socket and feeds the state machine. Ends only by throwing.
    private func readLoop(from socket: NetworkSocket) async throws {
        while true {
            guard let bytes = try await socket.receive() else { throw Disconnection.closedByServer }
            lastReceive = .now
            guard let events = try connection?.receive(bytes) else { throw DERPError.closed }
            deliver(events)
            // A Ping may have queued a Pong. The write loop takes and writes it.
            writeSignal?.yield()
        }
    }

    /// Writes queued packets and state machine replies in batches. Sets `writeStartedAt` to the start time during the write.
    /// Returns on cancellation (closing the socket if it was writing). Stops draining the queue after cancellation. A canceled Task's `write`
    /// returns immediately, so draining would discard the entire queue into a closed socket. The next connection sends remaining packets.
    private func writeLoop(to socket: NetworkSocket, signals: AsyncStream<Void>) async {
        for await _ in signals {
            while !Task.isCancelled, let bytes = nextWrite() {
                writeStartedAt = .now
                await socket.write(bytes)
                writeStartedAt = nil
            }
        }
    }

    /// Throws if a write fails to finish within `writeTimeout`.
    ///
    /// Sleeps until the current write's deadline when writing, or for `writeTimeout` from now when idle, then checks again. If another write is
    /// in progress when it wakes, sleeps again until that write's deadline. This catches a blocked write at nearly `writeTimeout` from its start,
    /// and creates one timer per `writeTimeout`.
    private func watchForStalledWrite() async throws {
        while true {
            try await Task.sleep(until: (writeStartedAt ?? .now) + writeTimeout, clock: .continuous)
            if let writeStartedAt, ContinuousClock.now >= writeStartedAt + writeTimeout { throw Disconnection.writeStalled }
        }
    }

    /// The next batch to write, including pending Pong replies and the first `packetCountForNextWrite` packets in the queue. Returns nil if empty.
    ///
    /// Frames go out in the order they entered the state machine. Pong replies were queued first, so they precede the packets in this batch.
    private func nextWrite() -> [UInt8]? {
        let count = Self.packetCountForNextWrite(queuedPackets.lazy.map(\.packet.count))
        for next in queuedPackets.prefix(count) {
            try? connection?.send(next.packet, to: next.peer)
        }
        queuedPackets.removeFirst(count)
        let bytes = connection?.takeOutboundBytes() ?? []
        return bytes.isEmpty ? nil : bytes
    }

    /// The number of packets from the front of the queue to put in a batch. Includes packets of sizes `packetSizes` as long as their total SendPacket frame size
    /// stays within `maximumWriteBytes`. Always includes the first packet regardless of size.
    static func packetCountForNextWrite(_ packetSizes: some Sequence<Int>) -> Int {
        var count = 0
        var frameBytes = 0
        for size in packetSizes {
            frameBytes += DERPFrame.headerSize + DERPFrame.keySize + size
            guard count == 0 || frameBytes <= maximumWriteBytes else { break }
            count += 1
        }
        return count
    }

    /// Throws if no bytes arrive for `idleTimeout`.
    private func watchForIdleness() async throws {
        while true {
            try await Task.sleep(until: lastReceive + Self.idleTimeout, clock: .continuous)
            if ContinuousClock.now >= lastReceive + Self.idleTimeout { throw Disconnection.idle }
        }
    }

    private func deliver(_ events: [DERPConnection.Event]) {
        for event in events {
            switch event {
            case .ready: break
            case let .packet(bytes, from: sender): eventQueue.push(.packet(bytes, from: sender))
            case let .peerGone(peer, reason: _): eventQueue.push(.peerGone(peer))
            }
        }
    }
}

/// Reasons a connection ends that are outside `DERPError`.
enum Disconnection: Error {
    case closedByServer
    case idle
    case writeStalled
    case noServers
}

extension DERPClient: CustomReflectable {
    /// Hides children because they hold a private key.
    public nonisolated var customMirror: Mirror {
        Mirror(self, children: ["serverCount": servers.count, "isPreferred": isPreferred])
    }
}
