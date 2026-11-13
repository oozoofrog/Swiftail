import Foundation

/// 제어 서버 클라이언트. 등록하고, 이 노드의 상태를 올리고, 맵 스트림으로 netmap을 받아 유지한다.
///
/// 이 패키지에서 소켓과 시계를 갖는 곳은 여기뿐이다. 프로토콜의 판단은 입출력 없는 상태 기계
/// (`ControlHandshake`·`ControlSession`·`HTTP2ClientConnection`·`MapResponseFramer`·`MapSession`)가 하고, 이 actor는
/// 바이트와 시각을 그것들에 넣고 결과를 사건(`events`)으로 내보낸다.
///
/// 동시성은 구조적이다. `run()`이 연결 하나의 수명 동안 읽기 루프·맵 스트림·감시·상태 올리기를 한 TaskGroup의
/// 자식으로 돌리므로, `run()`을 부른 Task를 취소하면 모두 멈추고 소켓이 닫힌다.
///
/// ```swift
/// let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d"),
///                            identityStore: NodeIdentityStore(directory: stateDirectory))
/// async let running: Void = client.run()
/// for await event in client.events { … }
/// ```
///
/// 계약 `docs/contracts/SwiftailControl.md` 단위 4. 절차는 `docs/protocol-notes/control-map.md` 4.1·4.2·4.4·4.5,
/// `docs/protocol-notes/control-transport.md` 4장 (출처: tailscale.com `control/controlclient/direct.go`·`auto.go`).
public actor ControlClient {
    public struct Configuration: Sendable {
        /// 제어 서버 URL. `http://` 또는 `https://`.
        public var serverURL: URL
        /// 노드의 호스트 이름. 서버가 노드 이름을 지을 때 쓴다.
        public var hostname: String
        /// 인증 키. 첫 등록에만 쓴다. 로그에 남기지 않는다.
        public var authKey: String?
        /// 오래 비활성이면 서버가 지우는 노드로 등록한다.
        public var ephemeral: Bool

        public init(serverURL: URL, hostname: String, authKey: String? = nil, ephemeral: Bool = false) {
            self.serverURL = serverURL
            self.hostname = hostname
            self.authKey = authKey
            self.ephemeral = ephemeral
        }
    }

    public enum Event: Sendable {
        /// 사용자가 이 URL에서 로그인해야 등록이 끝난다.
        case loginRequired(URL)
        /// 등록이 끝났다. 신원은 저장되었다.
        case registered(NodePublicKey)
        /// netmap이 바뀌었다(맵 스트림의 첫 응답 포함).
        case netmap(Netmap)
        /// 맵 스트림이 끊겼다. 물러났다가 다시 잇는다. 그동안 마지막 netmap은 유효하다.
        case disconnected
    }

    /// 지금 알려 둘 이 노드의 상태. 맵 스트림과 별개의 요청으로 올라간다.
    public struct LocalStatus: Sendable, Equatable {
        public var discoKey: DiscoPublicKey
        public var endpoints: [IPEndpoint]
        public var endpointTypes: [EndpointType]
        public var netInfo: NetInfo?

        public init(
            discoKey: DiscoPublicKey = .zero,
            endpoints: [IPEndpoint] = [],
            endpointTypes: [EndpointType] = [],
            netInfo: NetInfo? = nil
        ) {
            self.discoKey = discoKey
            self.endpoints = endpoints
            self.endpointTypes = endpointTypes
            self.netInfo = netInfo
        }
    }

    /// 연결 하나가 살아 있는 동안 맵 스트림 밖에서 처리할 일.
    enum SessionSignal: Sendable {
        case statusChanged
        case loginRequested
        case ping(PingRequest)
    }

    let configuration: Configuration
    let identityStore: NodeIdentityStore
    let eventContinuation: AsyncStream<Event>.Continuation
    private let eventStream: AsyncStream<Event>

    /// 지금의 신원. `run()`이 읽거나 만든다.
    var identity = NodeIdentity()
    var localStatus = LocalStatus()
    /// 지금 연결에서 마지막으로 올린 상태. 같은 상태를 다시 올리지 않는다.
    var uploadedStatus: LocalStatus?
    var needsRegistration = true
    /// 다음 등록에서 새 node 키를 만든다(대화형 로그인, 만료).
    var rotateNodeKey = false
    /// 연속 실패 수. 전체 netmap을 받으면 0이 된다.
    var consecutiveFailures = 0
    /// 지금 맵 스트림이 열려 있다.
    var mapStreamOpen = false
    /// 맵 스트림에서 마지막으로 무언가를 받은 시각. 120초 감시의 기준이다.
    var lastMapActivity = ContinuousClock.now
    /// 이미 답한 핑의 URL. 서버가 같은 핑을 다시 보내도 한 번만 답한다.
    var lastPingURL: String?
    /// 지금 연결의 신호 통로. 연결이 없으면 nil.
    var signals: AsyncStream<SessionSignal>.Continuation?
    private var isRunning = false

    public init(configuration: Configuration, identityStore: NodeIdentityStore) {
        self.configuration = configuration
        self.identityStore = identityStore
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: Event.self)
    }

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 이 흐름도 끝난다.
    public nonisolated var events: AsyncStream<Event> { eventStream }

    /// 상태를 바꾼다. 연결되어 있으면 곧 올리고, 아니면 다음 연결 때 올린다. 마지막 값만 남는다.
    public func setLocalStatus(_ status: LocalStatus) {
        localStatus = status
        signals?.yield(.statusChanged)
    }

    /// 대화형 로그인 URL을 새로 요청한다(이미 등록되어 있어도). 새 node 키로 다시 등록하고,
    /// 서버가 준 URL을 `loginRequired`로 알린다.
    public func startInteractiveLogin() {
        rotateNodeKey = true
        needsRegistration = true
        signals?.yield(.loginRequested)
    }

    /// 등록하고, 상태를 올리고, 맵 스트림을 유지한다. 끊기면 물러났다가 다시 잇는다.
    /// 호출한 Task가 취소될 때까지 돌아오지 않는다. 다시 시도해도 소용없는 실패는 던진다.
    public func run() async throws(ControlError) {
        guard !isRunning else { throw .invalidConfiguration("run()이 이미 실행 중이다") }
        isRunning = true
        defer {
            isRunning = false
            eventContinuation.finish()
        }

        let endpoint = try ControlEndpoint(serverURL: configuration.serverURL)
        guard !configuration.hostname.isEmpty else { throw .invalidConfiguration("호스트 이름이 비었다") }
        if let stored = try identityStore.load() {
            identity = stored
        } else {
            identity = NodeIdentity()
            // machine 키는 등록 전에도 저장한다. 다시 시작해도 같은 기기로 보여야 한다.
            try identityStore.save(identity)
        }
        needsRegistration = true

        var serverKey: MachinePublicKey?
        while !Task.isCancelled {
            let delay: Duration
            do {
                let key: MachinePublicKey
                if let serverKey { key = serverKey } else { key = try await ServerKey.fetch(for: endpoint) }
                serverKey = key
                try await ControlConnection.withConnection(to: endpoint, machineKey: identity.machineKey, serverKey: key) {
                    try await self.serve($0)
                }
                delay = .zero
            } catch {
                if Task.isCancelled { return }
                switch error {
                case SessionInterruption.loginRequested:
                    delay = .zero
                case SessionInterruption.rateLimited(let wait):
                    delay = wait
                case let error as ControlError where !error.isRetryable:
                    throw error
                default:
                    // 연결·HTTP 실패, 만료로 인한 재등록. 서버 키도 다시 받는다(서버가 키를 바꿨을 수 있다).
                    serverKey = nil
                    consecutiveFailures += 1
                    delay = RetryPolicy.backoff(failures: consecutiveFailures, jitter: .random(in: 0..<1))
                }
            }
            if mapStreamOpen {
                mapStreamOpen = false
                eventContinuation.yield(.disconnected)
            }
            do {
                try await Task.sleep(for: delay, clock: .continuous)
            } catch {
                return
            }
        }
    }

    /// 연결 하나에서 할 일: 필요하면 등록, 상태 올리기, 그 뒤 맵 스트림·감시·신호 처리를 함께 돌린다.
    /// 던지는 것으로만 끝난다.
    private func serve(_ connection: ControlConnection) async throws {
        let (signalStream, continuation) = AsyncStream.makeStream(of: SessionSignal.self)
        signals = continuation
        uploadedStatus = nil
        defer {
            continuation.finish()
            signals = nil
        }

        if needsRegistration {
            try await register(over: connection)
        }
        try await uploadStatus(over: connection)

        lastMapActivity = .now
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await self.receiveMap(over: connection) }
            group.addTask { try await self.watchMapActivity() }
            group.addTask { try await self.handle(signalStream, over: connection) }
            try await group.next()
            throw ControlError.connection("맵 처리가 끝났다")
        }
    }

    /// 지금 신원으로 정한 node 공개 키. 등록 전이면 nil.
    var nodePublicKey: NodePublicKey? { identity.nodePublicKey }

    /// 등록·상태 올리기에 보낼 Hostinfo.
    var hostinfo: Hostinfo {
        Hostinfo.swiftail(
            hostname: configuration.hostname,
            machineKey: identity.machinePublicKey,
            netInfo: localStatus.netInfo
        )
    }
}

/// 연결 하나를 끝내는 사정 가운데 `ControlError`로 드러내지 않는 것.
enum SessionInterruption: Error {
    /// 대화형 로그인을 요청받았다. 곧바로 다시 연결해 등록한다.
    case loginRequested
    /// self 노드의 키가 만료되었다. 물러났다가 새 키로 다시 등록한다.
    case nodeKeyExpired
    /// 서버가 기다리라고 했다(429, `Retry-After`가 붙은 503).
    case rateLimited(Duration)
}

extension ControlClient.Configuration: CustomStringConvertible, CustomReflectable {
    /// 인증 키를 가린다. 설정 값을 그대로 로그에 찍어도 비밀이 새지 않게 한다.
    public var description: String {
        "Configuration(serverURL: \(serverURL), hostname: \(hostname), authKey: \(authKey == nil ? "없음" : "<가림>"), ephemeral: \(ephemeral))"
    }

    /// `dump`는 `description`을 거치지 않으므로 여기서도 인증 키를 가린다.
    public var customMirror: Mirror {
        Mirror(self, children: [
            "serverURL": serverURL,
            "hostname": hostname,
            "authKey": authKey == nil ? "없음" : "<가림>",
            "ephemeral": ephemeral,
        ])
    }
}
