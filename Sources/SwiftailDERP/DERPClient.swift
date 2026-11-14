import CryptoKit
import Network
import SwiftailBase
import SwiftailIO

/// DERP 서버 하나와의 연결을 유지한다. 끊기면 물러났다가 다시 잇는다.
///
/// 이 패키지에서 소켓과 시계를 갖는 곳은 여기뿐이다. 프로토콜의 판단은 입출력 없는 상태 기계(`DERPConnection`)가
/// 하고, 이 actor는 바이트와 시각을 거기에 넣고 결과를 사건(`events`)으로 내보낸다.
///
/// 동시성은 구조적이다. `run()`이 연결 하나의 수명 동안 읽기 루프, 쓰기 루프, 유휴 감시를 한 TaskGroup의 자식으로
/// 돌리므로, `run()`을 부른 Task를 취소하면 모두 멈추고 소켓이 닫힌다. 분리된 Task는 만들지 않는다.
///
/// ```swift
/// let client = DERPClient(servers: [server], privateKey: nodeKey, isPreferred: true)
/// async let running: Void = client.run()
/// await client.send(packet, to: peer)
/// for await event in client.events { … }
/// ```
///
/// 인터페이스: `interface`를 주면 연결은 그 인터페이스로만 나간다(패킷 터널 안에서 DERP 연결이 터널로 되돌아가지
/// 않게 한다). 인터페이스가 바뀌면 이 클라이언트를 닫고 새 인터페이스로 새로 만든다. 연결 하나를 닫지 않은 채 다른
/// 인터페이스로 옮기는 길은 없다(`docs/contracts/SwiftailTunnel.md` 동작 N 3.2).
/// `shortcut:` 망이 내려간 것(만족된 경로 없음)은 알리지 않는다. 연결은 이 클라이언트의 재시도·물러남으로 버틴다.
/// 필요해지는 시점: 실기기에서 망이 없는 동안의 재시도가 배터리·메모리에 문제일 때(같은 문서 동작 N 5).
///
/// 메모리 상한(iOS 네트워크 확장은 약 50MB다):
///
/// - 읽지 않은 받은 사건은 개수(`eventBufferLimit`)와 패킷 바이트 합(`eventBufferByteLimit`) 둘 다로 묶는다.
/// - `send`는 기다리지 않고 패킷을 큐에 넣는다. 큐는 연결 상태와 무관하게 `queuedPacketLimit`개까지만 쥐고, 넘치면
///   가장 오래된 것을 버린다.
/// - 쓰기 루프가 큐의 패킷과 상태 기계가 낸 답(Pong)을 한 덩어리씩 `NetworkSocket.write`로 쓰고, 소켓이 받아 갈
///   때까지 다음 덩어리를 꺼내지 않는다. 그래서 쓰기가 막힌 동안 Pong은 상태 기계 안에 쌓이고, 64KiB를 넘으면
///   상태 기계가 연결 오류(`tooManyPendingReplies`)로 끝낸다. 쓰기 하나가 `writeTimeout` 안에 끝나지 않아도 연결
///   오류다. 어느 쪽이든 끊고 다시 잇는다.
/// - 쓰기는 부른 순서대로 나가므로 프레임 하나는 통째로, 순서대로 나간다.
///
/// 읽기는 쓰기가 막혀도 멈추지 않는다(따로 도는 자식이다). 서버는 2초 안에 쓰지 못하면 연결을 끊는다.
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

    /// 읽지 않은 `packet`·`peerGone` 사건 수의 한도. 넘으면 오래된 것부터 버린다.
    static let eventBufferLimit = 256
    /// 읽지 않은 `packet` 사건의 바이트 합(패킷 본문)의 한도(1MiB). 넘으면 오래된 패킷부터 버린다.
    ///
    /// 개수 한도만으로는 패킷당 최대 65,536바이트 × 256개 = 최악 16MiB를 쥔다. iOS 패킷 터널 확장의 한도(약 50MiB)의
    /// 3분의 1이라 받는 쪽 버퍼가 셋이면 넘친다. 1MiB는 그 최악의 16분의 1이다. 근거는 이 계산뿐인 제안값이다
    /// (`docs/contracts/SwiftailTunnel.md` 동작 M). 실기기 처리량 측정에서 버림이 보이면 조정한다. 패킷은 데이터그램이라
    /// 버려도 되고(WireGuard 위 TCP가 재전송한다), 가장 큰 패킷 하나(65,536바이트)는 한도 안이므로 어떤 패킷도 혼자서
    /// 한도를 넘지 않는다.
    static let eventBufferByteLimit = 1 << 20
    /// 아직 소켓에 쓰지 않은 패킷 수의 한도. 연결 상태와 무관하다. 넘으면 가장 오래된 것을 버린다.
    ///
    /// Go `wgengine/magicsock/derp.go`의 `derpWriteQueueDepth = 32`(지역 연결 하나의 쓰기 큐)와 같고, 넘칠 때 오래된
    /// 것을 버리는 것도 `magicsock.go`의 `sendDerp`와 같다. Go의 주석대로 TCP 버퍼 위의 큐는 거의 순수한 버퍼
    /// 부풀림이므로 깊게 두지 않는다.
    static let queuedPacketLimit = 32
    /// 쓰기 하나(패킷 하나와 함께 나갈 Pong)가 소켓에 넘어가기까지의 기한. 넘으면 연결을 끊는다.
    ///
    /// Go `derp/derp_client.go`의 `ForwardPacket`이 쓰기마다 거는 5초 타이머(`writeTimeoutFired`가 연결을 닫는다)를
    /// 따랐다. Go의 `send`(SendPacket)에는 기한이 없고 쓰는 goroutine이 TCP에서 막힌다. 여기서는 막힌 연결이 큐와
    /// Pong을 쥔 채 남지 않게 모든 쓰기에 같은 5초를 건다.
    static let writeTimeout = Duration.seconds(5)
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
    private let writeTimeout: Duration
    /// 시험에서 TLS 없이 루프백의 가짜 서버에 붙을 때만 true다.
    private let plaintextForTests: Bool
    /// 연결을 묶을 인터페이스. nil이면 묶지 않는다.
    private let interface: NWInterface?
    private let eventStream: AsyncStream<Event>
    private let eventQueue = EventQueue()

    private var hasRun = false
    /// 지금 연결. 준비되기 전과 끊긴 뒤에는 nil이다.
    private var connection: DERPConnection?
    /// 아직 소켓에 쓰지 않은 패킷. 쓰기 루프가 앞에서부터 꺼낸다.
    private(set) var queuedPackets: [(peer: NodePublicKey, packet: [UInt8])] = []
    /// 지금 연결의 쓰기 루프를 깨운다. 연결이 없으면 nil.
    private var writeSignal: AsyncStream<Void>.Continuation?
    /// 마지막으로 바이트를 받은 시각. 유휴 감시의 기준이다.
    private var lastReceive = ContinuousClock.now
    /// 연속 실패 수. 프레임을 받은 연결이 끊기면 1로 돌아간다.
    private var consecutiveFailures = 0

    /// - Parameters:
    ///   - servers: 한 지역의 서버들. 앞에서부터 차례로 시도한다.
    ///   - interface: 연결이 나갈 인터페이스. nil이면 시스템이 고른다. 서버가 루프백이면 묶지 않는다.
    public init(
        servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, interface: NWInterface? = nil
    ) {
        self.init(
            servers: servers, privateKey: privateKey, isPreferred: isPreferred, interface: interface,
            writeTimeout: Self.writeTimeout, plaintextForTests: false
        )
    }

    /// 시험이 짧은 쓰기 기한과 평문 연결을 넣을 때 쓴다.
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

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    ///
    /// 소비가 느리면 `packet`·`peerGone`은 가장 새 것 256개까지만, 패킷 바이트 합은 1MiB까지만 쥐고 오래된 것부터
    /// 버린다. 패킷은 데이터그램이므로 버려도 된다. `connected`·`disconnected`는 버리지 않고, 읽지 않은 것 가운데 가장 새 것 하나만 남긴다
    /// (`EventQueue`).
    public nonisolated var events: AsyncStream<Event> { eventStream }

    /// 연결하고, 읽고, 끊기면 다시 잇는다. 호출한 Task가 취소될 때까지 돌아오지 않는다.
    ///
    /// 클라이언트 하나에 한 번만 부른다. 다시 부르면 바로 돌아온다.
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

    /// 패킷을 보낸다. 큐에 넣고 기다리지 않는다. 연결되어 있지 않으면 다음 연결 때 보낸다.
    ///
    /// 큐는 32개까지 쥐고 넘치면 가장 오래된 것을 버린다. 65,536바이트를 넘는 패킷은 버린다.
    public func send(_ packet: [UInt8], to peer: NodePublicKey) {
        guard packet.count <= DERPConnection.maximumPacketSize else { return }
        if queuedPackets.count == Self.queuedPacketLimit { queuedPackets.removeFirst() }
        queuedPackets.append((peer, packet))
        writeSignal?.yield()
    }

    // MARK: 연결 하나

    /// 연결 하나의 수명. 연결이 끝나면(오류든 취소든) 소켓을 닫고 상태를 비운다. 핸드셰이크 뒤 프레임을 받았으면 true.
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
            return false
        }

        connection = opened.connection
        lastReceive = .now
        let (signals, signal) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        writeSignal = signal
        // 큐에 남은 패킷과 핸드셰이크 조각에 붙어 온 Ping의 Pong을 곧바로 쓰게 한다.
        signal.yield()
        eventQueue.push(.connected)
        deliver(opened.events)

        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                defer { group.cancelAll() }
                group.addTask { try await self.readLoop(from: opened.socket) }
                group.addTask { try await self.writeLoop(to: opened.socket, signals: signals) }
                group.addTask { try await self.watchForIdleness() }
                try await group.next()
            }
        } catch {
            // 읽기 오류, 서버가 닫음, 쓰기 기한, Pong 적체, 유휴, 취소. 어느 쪽이든 이 연결은 끝났고 호출한 쪽이 물러났다가
            // 다시 잇는다.
        }

        // 소켓을 닫은 뒤에만 새로 잇는다. 같은 키의 연결이 둘이면 서버가 한쪽에만 패킷을 넘긴다.
        opened.socket.close()
        signal.finish()
        writeSignal = nil
        let receivedFrame = connection?.hasReceivedFrameAfterHandshake ?? false
        connection = nil
        eventQueue.push(.disconnected)
        return receivedFrame
    }

    /// 소켓에서 받아 상태 기계에 넣는다. 던지는 것으로만 끝난다.
    private func readLoop(from socket: NetworkSocket) async throws {
        while true {
            guard let bytes = try await socket.receive() else { throw Disconnection.closedByServer }
            lastReceive = .now
            guard let events = try connection?.receive(bytes) else { throw DERPError.closed }
            deliver(events)
            // Ping에 대한 Pong이 생겼을 수 있다. 쓰기 루프가 꺼내 쓴다.
            writeSignal?.yield()
        }
    }

    /// 큐의 패킷과 상태 기계가 낸 답을 한 덩어리씩 쓴다. 덩어리 하나가 `writeTimeout` 안에 소켓에 넘어가지 않으면
    /// 던진다. 취소되면 돌아온다.
    private func writeLoop(to socket: NetworkSocket, signals: AsyncStream<Void>) async throws {
        let writeTimeout = writeTimeout
        for await _ in signals {
            while let bytes = nextWrite() {
                try await withTimeout(writeTimeout) { await socket.write(bytes) }
            }
        }
    }

    /// 다음에 쓸 덩어리: 큐의 가장 오래된 패킷 하나와 그때까지 쌓인 Pong. 쓸 것이 없으면 nil.
    private func nextWrite() -> [UInt8]? {
        if !queuedPackets.isEmpty {
            let next = queuedPackets.removeFirst()
            try? connection?.send(next.packet, to: next.peer)
        }
        let bytes = connection?.takeOutboundBytes() ?? []
        return bytes.isEmpty ? nil : bytes
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
            case let .packet(bytes, from: sender): eventQueue.push(.packet(bytes, from: sender))
            case let .peerGone(peer, reason: _): eventQueue.push(.peerGone(peer))
            }
        }
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
