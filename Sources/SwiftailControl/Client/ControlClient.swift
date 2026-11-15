import CryptoKit
import Foundation
import Network
import SwiftailBase
import SwiftailIO
import SwiftailTKA

/// 제어 서버 클라이언트. 등록하고, 이 노드의 상태를 올리고, 맵 스트림으로 netmap을 받아 유지한다.
///
/// 이 패키지에서 소켓과 시계를 갖는 곳은 여기뿐이다. 프로토콜의 판단은 입출력 없는 상태 기계
/// (`ControlHandshake`·`ControlSession`·`HTTP2ClientConnection`·`MapResponseFramer`·`MapSession`)가 하고, 이 actor는
/// 바이트와 시각을 그것들에 넣고 결과를 사건(`events`)으로 내보낸다.
///
/// 동시성은 구조적이다. `run()`이 연결 하나의 수명 동안 읽기 루프·맵 스트림·감시·상태 올리기·tailnet lock 절차를 한
/// TaskGroup의 자식으로 돌리므로, `run()`을 부른 Task를 취소하면 모두 멈추고 소켓이 닫힌다.
///
/// 사건으로 내는 netmap은 tailnet lock으로 이미 걸러져 있다(`ControlClient+TailnetLock.swift`).
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
        /// netmap이 바뀌었다(맵 스트림의 첫 응답 포함). tailnet lock으로 걸러진 것이고 `tailnetLock`에 그 모습이 있다.
        /// 피어는 그대로인데 lock의 모습만 바뀌어도(서명 권한 상태의 변화) 다시 낸다.
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
        /// `setDNS`: 연결을 기다리는 시간과 응답까지 합한 기한(계약 `docs/contracts/SwiftailHost.md` 동작 D2).
        var setDNS = Duration.seconds(60)
        /// tailnet lock의 RPC 하나(Go와 같은 1분. 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 M).
        var tkaRequest = Duration.seconds(60)
        /// 검증한 상태 없이 닫혀 있을 때(`.unverified`) 부트스트랩을 다시 시도하는 간격의 범위(동작 N6).
        var lockRetry = Duration.seconds(5)...Duration.seconds(300)
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
    /// 설정의 인증 키가 서명된 인증 키(`--TL`)면 그 해석. `run()`이 첫 연결 전에 한 번 해석한다.
    var wrappedAuthKey: WrappedAuthKey?
    var localStatus = LocalStatus()
    /// 지금 연결에서 마지막으로 올린 상태. 같은 상태를 다시 올리지 않는다.
    var uploadedStatus: LocalStatus?
    /// 지금 연결에서 마지막으로 올린 `TKAHead`. 로컬 머리가 달라지면 상태를 한 번 더 올린다.
    var uploadedTKAHead: String?
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
    /// 검증한 서명 권한 상태. lock이 없으면 nil. `run()`이 저장소에서 열고, 연결이 끊겨 다시 이어도 그대로 쥔다.
    var lockAuthority: Authority?
    /// 저장된 서명 권한 상태를 열지 못했다. 앱이 그 파일을 지우고 다시 시작할 때까지 피어를 올리지 않는다.
    var isLockStoreUnreadable = false
    /// 거절한 끄기 비밀들의 BLAKE2s-256(오래된 것부터 `maximumRejectedDisablementCount`개까지)과 그때의 머리. 같은 비밀로
    /// KDF(16MiB)를 다시 돌리지 않는다. 머리가 바뀌면 새로 쥔다. 메모리에만 쥔다.
    var rejectedDisablements: (head: AUMHash, secretDigests: [[UInt8]])?
    /// 저장된 상태가 서버가 알린 사슬과 이어지지 않았다(동기화에서 교차를 찾지 못했다). 다음 동기화가 교차를 찾거나 lock이
    /// 꺼지면 풀린다. 연결이 끊겨도 쥔다.
    var isLockStateDiverged = false
    /// 끄기 비밀의 KDF를 돈 횟수. 같은 비밀을 다시 계산하지 않는지 시험이 본다.
    var disablementDerivationCount = 0
    /// 지금 맵 세션의 tailnet lock 처리 상태.
    var lockSession = LockSession()
    /// 지금 연결의 신호 통로. 연결이 없으면 nil.
    var signals: AsyncStream<SessionSignal>.Continuation?
    /// 등록을 마친 지금 연결. 맵 스트림 밖의 요청(`setDNS`)이 이 연결 위의 새 스트림으로 나간다. 연결이 없으면 nil.
    var activeConnection: ControlConnection?
    /// `activeConnection`이 서기를 기다리는 `setDNS`의 깨움 통로. 연결이 서면 모두 깨운다.
    var connectionWaiters: [Int: AsyncStream<Void>.Continuation] = [:]
    var nextConnectionWaiter = 0
    /// 통로에 든 채 아직 처리하지 않은 신호. 처리(상태 올리기의 물러나기, 핑 답)가 막힌 동안 통로가 끝없이 자라지
    /// 않게 한다: 상태 바뀜은 하나면 충분하고(올릴 때 마지막 값을 읽는다), 핑은 `queuedPingLimit`개까지만 넣는다.
    var isStatusChangeQueued = false
    var queuedPings = 0
    static let queuedPingLimit = 8
    /// 연결을 묶을 인터페이스. nil이면 묶지 않는다. `run()`이 연결을 시작할 때 읽는다.
    private var networkInterface: NWInterface?
    /// `setNetworkInterface`를 부른 횟수. 연결 시도는 시작할 때의 값과 달라지면 그 시도를 버린다. 신호가 시도 사이에
    /// 들어와도 잃지 않게 하는 기준이다(`loginRequests`와 같은 방식).
    private var interfaceGeneration = 0
    /// 지금 기다리는 쪽의 깨움 통로. 기다리는 곳이 없으면 nil.
    private var interfaceChange: AsyncStream<Void>.Continuation?
    /// 지금 쥔 제어 서버의 Noise 공개 키. 연결이 실패하면 지우고 다음에 다시 받는다.
    private var serverKey: MachinePublicKey?
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
        guard !isStatusChangeQueued, let signals else { return }
        isStatusChangeQueued = true
        signals.yield(.statusChanged)
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

    /// 연결을 묶을 인터페이스를 바꾸고, 지금 연결을 끊고 새 인터페이스로 곧바로 다시 잇는다.
    ///
    /// 물러나지 않는다. 연결 중이든, 이어진 채 맵 스트림을 받는 중이든, 실패해서 물러나는 중이든 지금 하던 것을
    /// 버리고 곧바로 새 연결을 시작한다. 등록 상태와 마지막 netmap은 그대로다(맵 스트림은 새 연결에서 전체 맵부터
    /// 다시 받는다). 끊긴 연결은 `disconnected`로 알린다.
    ///
    /// **같은 인터페이스를 다시 알려도 다시 잇는다.** 같은 Wi-Fi에서 주소만 바뀐 경우(다른 AP, DHCP 갱신) 옛 연결은
    /// 이미 죽어 있다. 다시 이을지의 판정(인터페이스나 로컬 주소가 바뀌었는가, `docs/contracts/SwiftailTunnel.md`
    /// 동작 N 2)은 부르는 쪽의 몫이고, 여기서는 부른 만큼 다시 잇는다. 여러 번 연달아 불러도 시도 하나를 새로 시작할
    /// 뿐이고 가장 나중 값을 쓴다.
    ///
    /// `shortcut:` 망이 내려간 것(만족된 경로 없음)은 알리지 않는다. 그동안 연결은 `run()`의 재시도·물러남으로 버틴다.
    /// 필요해지는 시점: 실기기에서 망이 없는 동안의 재시도가 배터리·메모리에 문제일 때
    /// (`docs/contracts/SwiftailTunnel.md` 동작 N 5).
    ///
    /// `run()`을 시작하기 전이나 끝난 뒤에 부르면 값만 기억한다. `nil`이면 묶지 않는다. 서버가 루프백이면 어느
    /// 인터페이스든 묶지 않는다(`NetworkSocket.bindableInterface`).
    public func setNetworkInterface(_ interface: NWInterface?) {
        networkInterface = interface
        interfaceGeneration += 1
        interfaceChange?.yield()
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
        try prepareRegistration()
        openLockStore()
        needsRegistration = true

        while !Task.isCancelled {
            // 인터페이스와 그 세대는 시도를 시작하는 순간 함께 읽는다(둘 사이에 멈추는 곳이 없다).
            let (interface, generation) = (networkInterface, interfaceGeneration)
            let delay: Duration
            do {
                try await untilInterfaceChanges(since: generation) {
                    try await self.connectAndServe(to: endpoint, interface: interface)
                }
                delay = .zero
            } catch {
                if Task.isCancelled { return }
                switch error {
                case SessionInterruption.loginRequested:
                    delay = .zero
                case SessionInterruption.interfaceChanged:
                    // 옛 망에서 쌓인 실패로 새 망의 첫 시도를 늦추지 않는다.
                    consecutiveFailures = 0
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
                // 물러나는 동안에도 인터페이스가 바뀌면 기다리지 않고 곧바로 다시 잇는다.
                try await untilInterfaceChanges(since: generation) {
                    try await Task.sleep(for: delay, clock: .continuous)
                }
            } catch SessionInterruption.interfaceChanged {
                consecutiveFailures = 0
            } catch {
                return
            }
        }
    }

    /// 서버 키를 받고(아직 없으면) 연결을 맺어 `serve`를 돌린다. 던지는 것으로만 끝난다.
    private func connectAndServe(to endpoint: ControlEndpoint, interface: NWInterface?) async throws {
        let key: MachinePublicKey
        if let serverKey { key = serverKey } else { key = try await ServerKey.fetch(for: endpoint) }
        serverKey = key
        try await ControlConnection.withConnection(to: endpoint, interface: interface, machineKey: identity.machineKey, serverKey: key) {
            try await self.serve($0)
        }
    }

    /// `operation`을 돌리다가 `generation` 뒤에 인터페이스가 바뀌면 취소하고 `SessionInterruption.interfaceChanged`를
    /// 던진다. `operation`이 먼저 끝나면 그 결과(또는 오류)를 낸다.
    ///
    /// 깨움 통로는 기다릴 때마다 새로 만든다. 경쟁에서 진 쪽을 취소하면 그 흐름은 끝나기 때문이다. 이미 바뀌어 있었으면
    /// (`generation`이 낡았으면) 통로가 곧바로 깨어난다. 그래서 시도 사이에 들어온 변경도 잃지 않는다.
    private func untilInterfaceChanges<Result: Sendable>(
        since generation: Int, _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        if interfaceGeneration != generation { continuation.yield() }
        interfaceChange = continuation
        defer { interfaceChange = nil }
        return try await withThrowingTaskGroup(of: Result?.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await operation() }
            group.addTask {
                for await _ in changes { return nil }
                return nil
            }
            guard let first = try await group.next(), let result = first else {
                throw SessionInterruption.interfaceChanged
            }
            return result
        }
    }

    /// 연결 하나에서 할 일: 필요하면 등록, 상태 올리기, 그 뒤 맵 스트림·감시·신호 처리·tailnet lock 절차를 함께 돌린다.
    /// 던지는 것으로만 끝난다.
    private func serve(_ connection: ControlConnection) async throws {
        let (signalStream, continuation) = AsyncStream.makeStream(of: SessionSignal.self)
        signals = continuation
        isStatusChangeQueued = false
        queuedPings = 0
        uploadedStatus = nil
        uploadedTKAHead = nil
        lockSession = LockSession()
        selfKeyExpiry = nil
        selfKeyExpiryChanged = nil
        defer {
            continuation.finish()
            signals = nil
            activeConnection = nil
        }

        if needsRegistration {
            try await register(over: connection)
        }
        activeConnection = connection
        for waiter in connectionWaiters.values { waiter.yield() }
        try await uploadStatus(over: connection)

        lastMapActivity = .now
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await self.receiveMap(over: connection) }
            group.addTask { try await self.watchMapActivity() }
            group.addTask { try await self.handle(signalStream, over: connection) }
            group.addTask { try await self.runLockProcedures(over: connection) }
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
    /// `setNetworkInterface`가 불렸다. 물러나지 않고 곧바로 새 인터페이스로 다시 잇는다.
    case interfaceChanged
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
