import CryptoKit
import SwiftailBase
import SwiftailIO

/// DERP 서버 하나와의 연결을 유지한다. 끊기면 물러났다가 다시 잇는다.
///
/// 이 패키지에서 소켓과 시계를 갖는 곳은 여기뿐이다. 프로토콜의 판단은 입출력 없는 상태 기계(`DERPConnection`)가
/// 하고, 이 actor는 바이트와 시각을 거기에 넣고 결과를 사건(`events`)으로 내보낸다.
///
/// 동시성은 구조적이다. `run()`이 연결 하나의 수명 동안 읽기 루프와 유휴 감시를 한 TaskGroup의 자식으로
/// 돌리므로, `run()`을 부른 Task를 취소하면 모두 멈추고 소켓이 닫힌다. 분리된 Task는 만들지 않는다.
///
/// ```swift
/// let client = DERPClient(servers: [server], privateKey: nodeKey, isPreferred: true)
/// async let running: Void = client.run()
/// await client.send(packet, to: peer)
/// for await event in client.events { … }
/// ```
///
/// 쓰기는 기다리지 않는다. `NetworkSocket.send`가 부른 순서대로 내보내므로 프레임 하나는 통째로, 순서대로 나간다.
/// 읽기는 멈추지 않는다. 서버는 2초 안에 쓰지 못하면 연결을 끊는다.
///
/// 계약 `docs/contracts/SwiftailDERP.md` "DERPClient", `docs/protocol-notes/derp-stun.md` 4.1·4.4~4.6절
/// (출처: tailscale.com `derp/derphttp/derphttp_client.go`·`wgengine/magicsock/derp.go`, BSD-3-Clause).
public actor DERPClient {
    public enum Event: Sendable {
        case connected
        case disconnected
        case packet([UInt8], from: NodePublicKey)
        case peerGone(NodePublicKey)
    }

    /// 읽지 않은 사건 수의 한도. 넘으면 오래된 것부터 버린다.
    static let eventBufferLimit = 256
    /// 연결되기 전에 쌓아 두는 패킷 수의 한도. 넘으면 가장 오래된 것을 버린다.
    static let queuedPacketLimit = 32
    /// 서버 하나로의 TCP 연결 시도 기한.
    static let tcpTimeout = Duration.milliseconds(1500)
    /// 연결부터 `ready`까지의 기한.
    static let readyTimeout = Duration.seconds(10)
    /// 이만큼 아무것도 오지 않으면 끊는다. 서버는 60초 + [0, 5)초마다 KeepAlive를 보낸다.
    static let idleTimeout = Duration.seconds(120)
    static let maximumBackoff = Duration.seconds(5)

    private let servers: [DERPServer]
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private let isPreferred: Bool
    private let eventStream: AsyncStream<Event>
    private let eventContinuation: AsyncStream<Event>.Continuation

    private var hasRun = false
    /// 지금 연결. 준비되기 전과 끊긴 뒤에는 nil이다.
    private var socket: NetworkSocket?
    private var connection: DERPConnection?
    /// 연결되기 전에 `send`로 받은 패킷. 준비되면 순서대로 보낸다.
    private var queuedPackets: [(peer: NodePublicKey, packet: [UInt8])] = []
    /// 마지막으로 바이트를 받은 시각. 유휴 감시의 기준이다.
    private var lastReceive = ContinuousClock.now
    /// 연속 실패 수. 프레임을 받은 연결이 끊기면 1로 돌아간다.
    private var consecutiveFailures = 0

    /// - Parameter servers: 한 지역의 서버들. 앞에서부터 차례로 시도한다.
    public init(servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool) {
        self.servers = servers
        self.privateKey = privateKey
        self.isPreferred = isPreferred
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: Event.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
    }

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    ///
    /// 읽지 않은 사건은 가장 새 것 256개까지만 쥐고 오래된 것부터 버린다. 패킷은 데이터그램이므로 버려도 된다.
    // shortcut: 버리는 것은 오래된 `packet`만이 아니라 오래된 사건 전부다. 256개가 쌓이면 이미 소비자가 막힌 것이고,
    // 그때는 연결 상태 사건도 믿을 수 없다. `AsyncStream`으로는 종류를 가려 버릴 수 없어 따로 큐를 만들지 않았다.
    public nonisolated var events: AsyncStream<Event> { eventStream }

    /// 연결하고, 읽고, 끊기면 다시 잇는다. 호출한 Task가 취소될 때까지 돌아오지 않는다.
    ///
    /// 클라이언트 하나에 한 번만 부른다. 다시 부르면 바로 돌아온다.
    public func run() async {
        guard !hasRun else { return }
        hasRun = true
        defer { eventContinuation.finish() }

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

    /// 패킷을 보낸다. 연결되어 있지 않으면 다음 연결 때까지 큐에 둔다. 기다리지 않는다.
    ///
    /// 65,536바이트를 넘는 패킷은 버린다.
    // shortcut: 연결된 동안에는 큐 없이 바로 소켓에 쓴다. `NetworkSocket.send`가 기다리지 않으므로 소켓이 막혀도
    // 여기서 패킷이 쌓이는 것을 막지 못한다. 쓰기 완료를 알려 주는 API가 `SwiftailIO`에 생기면 큐를 32개로 묶는다.
    public func send(_ packet: [UInt8], to peer: NodePublicKey) {
        guard packet.count <= DERPConnection.maximumPacketSize else { return }
        guard let socket, connection != nil else {
            if queuedPackets.count == Self.queuedPacketLimit { queuedPackets.removeFirst() }
            queuedPackets.append((peer, packet))
            return
        }
        try? connection?.send(packet, to: peer)
        socket.send(connection?.takeOutboundBytes() ?? [])
    }

    // MARK: 연결 하나

    /// 연결 하나의 수명. 연결이 끝나면(오류든 취소든) 소켓을 닫고 상태를 비운다. 핸드셰이크 뒤 프레임을 받았으면 true.
    private func serveOneConnection() async -> Bool {
        let opened: OpenedConnection
        do {
            let (servers, privateKey, isPreferred) = (servers, privateKey, isPreferred)
            opened = try await withTimeout(Self.readyTimeout) {
                try await Self.open(servers: servers, privateKey: privateKey, isPreferred: isPreferred)
            }
        } catch {
            return false
        }

        socket = opened.socket
        connection = opened.connection
        lastReceive = .now
        eventContinuation.yield(.connected)
        deliver(opened.events)
        flushQueuedPackets(to: opened.socket)

        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                defer { group.cancelAll() }
                group.addTask { try await self.readLoop(from: opened.socket) }
                group.addTask { try await self.watchForIdleness() }
                try await group.next()
            }
        } catch {
            // 읽기 오류, 서버가 닫음, 유휴, 취소. 어느 쪽이든 이 연결은 끝났고 호출한 쪽이 물러났다가 다시 잇는다.
        }

        // 소켓을 닫은 뒤에만 새로 잇는다. 같은 키의 연결이 둘이면 서버가 한쪽에만 패킷을 넘긴다.
        opened.socket.close()
        let receivedFrame = connection?.hasReceivedFrameAfterHandshake ?? false
        socket = nil
        connection = nil
        eventContinuation.yield(.disconnected)
        return receivedFrame
    }

    /// 소켓에서 받아 상태 기계에 넣는다. 던지는 것으로만 끝난다.
    private func readLoop(from socket: NetworkSocket) async throws {
        while true {
            guard let bytes = try await socket.receive() else { throw Disconnection.closedByServer }
            lastReceive = .now
            guard let events = try connection?.receive(bytes) else { throw DERPError.closed }
            deliver(events)
            // Ping에 대한 Pong. 실패한 연결에서는 비어 있다.
            socket.send(connection?.takeOutboundBytes() ?? [])
        }
    }

    /// `idleTimeout` 동안 아무것도 오지 않으면 던진다.
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
            case let .packet(bytes, from: sender): eventContinuation.yield(.packet(bytes, from: sender))
            case let .peerGone(peer, reason: _): eventContinuation.yield(.peerGone(peer))
            }
        }
    }

    private func flushQueuedPackets(to socket: NetworkSocket) {
        for queued in queuedPackets {
            try? connection?.send(queued.packet, to: queued.peer)
        }
        queuedPackets = []
        socket.send(connection?.takeOutboundBytes() ?? [])
    }
}

/// 연결 하나를 끝내는 사정 가운데 `DERPError`로 드러내지 않는 것.
enum Disconnection: Error {
    case closedByServer
    case idle
    case noServers
}

extension DERPClient: CustomReflectable {
    /// 개인 키를 쥐므로 자식을 감춘다.
    public nonisolated var customMirror: Mirror {
        Mirror(self, children: ["serverCount": servers.count, "isPreferred": isPreferred])
    }
}
