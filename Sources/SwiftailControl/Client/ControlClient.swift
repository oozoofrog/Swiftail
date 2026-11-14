import CryptoKit
import Foundation
import SwiftailBase
import SwiftailIO

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

    /// 응답을 기다리는 요청의 기한. 넘기면 연결 오류로 보고 물러났다가 다시 잇는다.
    ///
    /// Go는 맵 요청(스트림과 상태 갱신 모두)에만 120초 감시 타이머를 두고, 등록과 Followup에는 기한이 없다
    /// (`direct.go` `sendMapRequest`의 `watchdogTimeout`, `doLogin`). 응답 없는 서버에 영영 묶이지 않게 등록에도
    /// 같은 120초를 두고, 사용자의 로그인을 기다리는 Followup 긴 폴링에는 10분을 둔다. Followup을 끊어도 후보 키와
    /// Followup URL을 유지하므로 다시 이으면 같은 로그인을 이어서 기다린다.
    struct Timeouts: Sendable {
        /// 등록(Followup이 아닌 것)과 상태 올리기.
        var request = Duration.seconds(120)
        /// Followup 긴 폴링.
        var followup = Duration.seconds(600)
    }

    let configuration: Configuration
    let identityStore: NodeIdentityStore
    let timeouts: Timeouts
    let eventContinuation: AsyncStream<Event>.Continuation
    private let eventStream: AsyncStream<Event>

    /// 확정 전의 등록: 후보 node 키와 서버가 준 Followup URL. 사용자가 그 URL에서 로그인하면 이 키로 등록이 끝나므로,
    /// 등록이 확정되거나 새 로그인을 요청받을 때까지 재연결 너머로 쥔다. 저장하지 않는다(Go `Direct.tryingNewKey`와
    /// `LoginGoal.url`).
    struct PendingRegistration {
        var nodeKey: Curve25519.KeyAgreement.PrivateKey
        var oldNodeKey: NodePublicKey
        var followup: String
    }

    /// 버리지 않고 쥐는 사건 수. 구독자가 읽지 않으면 오래된 것부터 버린다.
    static let eventBufferLimit = 64

    /// 지금의 신원. `run()`이 읽거나 만든다.
    var identity = NodeIdentity()
    var localStatus = LocalStatus()
    /// 지금 연결에서 마지막으로 올린 상태. 같은 상태를 다시 올리지 않는다.
    var uploadedStatus: LocalStatus?
    var needsRegistration = true
    /// 다음 등록에서 새 node 키를 만든다(대화형 로그인, 만료).
    var rotateNodeKey = false
    /// `startInteractiveLogin()`을 부른 횟수. 등록은 시작할 때의 값과 끝날 때의 값이 같을 때만 그 요청을 채운 것으로 본다.
    var loginRequests = 0
    var pendingRegistration: PendingRegistration?
    /// 로그인을 기다리는 Followup 긴 폴링이 걸려 있을 때, 새 로그인 요청으로 그것을 그만두게 하는 통로.
    var followupInterrupt: AsyncStream<Void>.Continuation?
    /// 만료로 새 키를 등록했고, 아직 만료되지 않은 self 노드를 받지 못했다. 이때 또 만료면 끝낸다.
    var renewedExpiredKey = false
    /// 지금 연결에서 받은 마지막 netmap의 self 노드 키 만료 시각. 감시가 이 시각에 깨어난다.
    var selfKeyExpiry: Date?
    /// `selfKeyExpiry`가 바뀌면 잠든 감시를 깨운다.
    var selfKeyExpiryChanged: AsyncStream<Void>.Continuation?
    /// 연속 실패 수. 전체 netmap을 받으면 0이 된다.
    var consecutiveFailures = 0
    /// 지금 맵 스트림이 열려 있다.
    var mapStreamOpen = false
    /// 맵 스트림에서 마지막으로 무언가를 받은 시각. 120초 감시의 기준이다.
    var lastMapActivity = ContinuousClock.now
    /// 이미 답한 핑의 URL. 서버가 같은 핑을 다시 보내도 한 번만 답한다.
    var lastPingURL: String?
    /// 서버가 마지막으로 보낸 tailnet lock 상태. `tailnetLockEnabled`로 끝난 까닭을 진단할 때 본다.
    var lastTKAInfo: TKAInfo?
    /// 지금 연결의 신호 통로. 연결이 없으면 nil.
    var signals: AsyncStream<SessionSignal>.Continuation?
    private var hasRun = false

    public init(configuration: Configuration, identityStore: NodeIdentityStore) {
        self.init(configuration: configuration, identityStore: identityStore, timeouts: Timeouts())
    }

    /// 기한을 정해 만든다. 시험이 짧은 기한을 넣을 때 쓴다.
    init(configuration: Configuration, identityStore: NodeIdentityStore, timeouts: Timeouts) {
        self.configuration = configuration
        self.identityStore = identityStore
        self.timeouts = timeouts
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: Event.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
    }

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 이 흐름도 끝난다.
    ///
    /// 읽지 않은 사건은 가장 새 것 64개까지만 쥐고 오래된 것부터 버린다. `netmap`은 늘 전체 상태이므로 마지막 것만
    /// 읽어도 된다.
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
        loginRequests += 1
        pendingRegistration = nil
        followupInterrupt?.yield()
        signals?.yield(.loginRequested)
    }

    /// 등록하고, 상태를 올리고, 맵 스트림을 유지한다. 끊기면 물러났다가 다시 잇는다.
    /// 호출한 Task가 취소될 때까지 돌아오지 않는다. 다시 시도해도 소용없는 실패는 던진다.
    /// 클라이언트 하나에 한 번만 부른다. 실행 중이든 끝난 뒤든 다시 부르면 `invalidConfiguration`이다.
    public func run() async throws(ControlError) {
        guard !hasRun else { throw .invalidConfiguration("run()은 클라이언트 하나에 한 번만 부른다") }
        hasRun = true
        defer { eventContinuation.finish() }

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
                    delay = Backoff.delay(failures: consecutiveFailures, maximum: RetryPolicy.maximumBackoff, jitter: .random(in: 0..<1))
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
        selfKeyExpiry = nil
        selfKeyExpiryChanged = nil
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
    /// self 노드의 키가 만료되었다(맵 응답 또는 만료 시각의 도래). 물러났다가 새 키로 다시 등록한다.
    case nodeKeyExpired
    /// 서버가 기다리라고 했다(429, `Retry-After`가 붙은 503).
    case rateLimited(Duration)
}

extension ControlClient.PendingRegistration: CustomReflectable {
    /// 후보 node 키는 공개 키만 보인다.
    var customMirror: Mirror {
        Mirror(self, children: ["nodePublicKey": NodePublicKey(nodeKey.publicKey), "oldNodeKey": oldNodeKey, "followup": followup])
    }
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
