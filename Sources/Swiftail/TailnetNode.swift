import CryptoKit
import Foundation
import Network
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailEngine
import SwiftailIO
import SwiftailMagicsock
import SwiftailNetstack
import os

/// tailnet의 노드 하나. 터널 장치(utun 또는 메모리)로 IP 패킷을 주고받고, 앱이 OS에 적용할 터널 설정을 내고, 서비스 IP의
/// MagicDNS 질의에 답한다. 피어와는 직접 UDP 경로를 찾아 쓰고, 찾지 못하거나 끊기면 DERP 중계로 보낸다. `.inProcess`
/// 장치에서는 OS 없이 프로세스 안의 TCP 스택으로 듣고 건다(`listen(port:)`, `connect(to:port:)`).
///
/// 이 actor는 가장자리다. 프로토콜의 판단은 `ControlClient`(등록·맵), `DERPClient`(중계), 그리고 입출력 없는 상태 기계들
/// (`TailnetEngine`: WireGuard·필터·로컬 응답, `Magicsock`: 경로 찾기·STUN·홈 지역, `TCPStack`: 프로세스 안의 TCP,
/// `NodeStateMachine`: 노드 상태, `NetworkSettingsPublisher`: 설정 내기, `DefaultLink`: 망 전환 판정)이 하고, 여기서는
/// 그것들과 장치·소켓·시계를 잇는다.
///
/// 상태 기계는 값 타입이라 이 actor의 저장 프로퍼티로 두고 제자리에서만 바꾼다. 사건 하나(받은 UDP, 받은 DERP 패킷, 장치에서
/// 읽은 IP 패킷, 타이머)를 처리할 때는 한쪽의 출력을 다른 쪽에 넘기는 일을 `await` 없이 끝까지 돌리고, 입출력은 통로에
/// 넣기만 한다. 그래서 actor 재진입이 두 상태 사이에 끼어들지 못한다. 시각(`ContinuousClock.now`, `Date()`)을 만드는 곳도
/// 여기뿐이다.
///
/// 동시성은 구조적이다. 모든 일은 `run()` 안의 TaskGroup 자식이고, `run()`을 부른 Task를 취소하면 모두 멈춘다.
///
/// ```
/// run()
///  └ TaskGroup: 노드의 수명. 자식 하나가 끝나면 나머지를 취소하고 run()이 돌아온다
///     ├ control.run()             등록, 맵 스트림, 끊기면 다시 잇기. 끝나는 실패면 던진다
///     ├ follow(control)           제어 사건 → 엔진·Magicsock, 상태 기계, 설정
///     ├ forwardLoginRequests      startInteractiveLogin() → 제어
///     ├ forwardInterfaces         setDefaultInterface()가 고른 인터페이스 → 제어(다시 잇기)
///     ├ uploadLocalStatus         Magicsock이 바꾼 엔드포인트·홈 지역 → 제어
///     ├ receiveUDP()              열린 UDP 소켓마다 데이터그램 → Magicsock. 소켓이 닫히면 그 소켓의 일이 끝난다
///     ├ rebindUDP()               재결속 요청마다 새 소켓을 연다(같은 포트, 안 되면 0) → Magicsock.rebind
///     ├ maintainDERP()            열린 지역 연결마다 아래 묶음 하나. 연결의 우편함을 닫으면 그 묶음이 접힌다
///     │   └ TaskGroup: DERP 지역 연결 하나의 수명
///     │      ├ client.run()
///     │      ├ client.events → Magicsock, 상태 기계
///     │      └ 이 지역으로 보낼 데이터그램 → client.send. 우편함이 닫히면 끝나고 묶음 전체를 접는다
///     ├ runTimer()                엔진·Magicsock·스택의 이른 기한에 깨어나 셋 다 advance
///     ├ releaseHandles()          버려진 TailnetConnection·TailnetListener(deinit) → RST로 끊기, 듣기 그만두기
///     ├ awaitFailure()            재결속에서 UDP를 열지 못함, 메모리 장치 실패(시험) → 그 실패로 끝난다
///     └ readTunnel()              (utun일 때) 장치에서 읽은 패킷 → 엔진. 장치가 닫히면 tunnelDeviceClosed로 끝난다
/// ```
///
/// ```swift
/// let node = try TailnetNode(
///     configuration: .init(stateDirectory: directory, hostname: "rd-phone-1a2b3c4d"),
///     device: .utun(fileDescriptor: descriptor, mtu: 1280))
/// let runTask = Task { try await node.run() }
/// for await settings in node.networkSettings { … }   // 앱이 OS에 적용
/// runTask.cancel(); _ = await runTask.result          // 정지
/// ```
///
/// 계약 `docs/contracts/SwiftailTunnel.md`, `docs/contracts/SwiftailEngine.md` "노드 API (`Swiftail`)"와 "M4에서 바뀌는 것",
/// `docs/contracts/SwiftailNetstack.md` 동작 N·A.
public actor TailnetNode {
    /// 읽지 않은 사건 수의 한도. 넘으면 오래된 것부터 버린다.
    static let eventBufferLimit = 64
    /// 읽지 않은 받은 패킷 수의 한도(메모리 장치). 넘으면 오래된 것부터 버린다(IP는 원래 그렇다).
    static let inboundPacketLimit = 256
    /// DERP로 아직 넘기지 못한 데이터그램 수와 바이트 합의 한도(지역 연결마다). 넘으면 오래된 것부터 버린다. WireGuard가
    /// 다시 보낸다(계약 동작 M).
    static let outboundDatagramLimit = 256
    static let outboundByteLimit = 1 << 20

    /// 비밀 없는 요약만 남긴다: 상태 전이, 제어·DERP 연결과 끊김, 경로 전환, 재결속, 설정 산출. 키·인증 키·로그인 URL·
    /// 주소 전체·DNS 이름은 남기지 않는다(첫 사용처 검토 결과 5).
    static let log = Logger(subsystem: "Swiftail", category: "node")

    let configuration: NodeConfiguration
    let device: TunnelDevice
    /// utun 장치의 인터페이스 이름. `init`이 읽는다. 기본 인터페이스 통지에서 자기 utun을 걸러 낸다(동작 N 1).
    let tunnelName: String?
    let identityStore: NodeIdentityStore
    let eventContinuation: AsyncStream<NodeEvent>.Continuation
    let inboundContinuation: AsyncStream<[UInt8]>.Continuation
    let settingsContinuation: AsyncStream<TunnelNetworkSettings>.Continuation
    private let eventStream: AsyncStream<NodeEvent>
    private let inboundStream: AsyncStream<[UInt8]>
    private let settingsStream: AsyncStream<TunnelNetworkSettings>
    /// `startInteractiveLogin()`이 `run()` 밖에서도 불릴 수 있으므로 요청을 흐름에 담아 두고 자식이 제어로 넘긴다.
    private let loginRequests: AsyncStream<Void>
    private let loginContinuation: AsyncStream<Void>.Continuation
    /// 제어 연결을 묶을 인터페이스. 마지막 것만 의미가 있다.
    private let interfaceRequests: AsyncStream<NWInterface>
    let interfaceContinuation: AsyncStream<NWInterface>.Continuation
    /// 제어 서버에 올릴 상태. 마지막 것만 의미가 있다.
    private let statusUploads: AsyncStream<ControlClient.LocalStatus>
    let statusUploadContinuation: AsyncStream<ControlClient.LocalStatus>.Continuation
    /// 새로 연 DERP 지역 연결. `maintainDERP()`가 받아 돌린다. 그 자식이 돌기 전에 연 연결도 잃지 않게 여기서 만든다.
    let openedDERPLinks: AsyncStream<DERPLink>
    let openedDERPLinkContinuation: AsyncStream<DERPLink>.Continuation
    /// 새로 연 UDP 소켓. `receiveUDP()`가 받아 읽는다.
    let openedSockets: AsyncStream<DatagramSocket>
    let openedSocketContinuation: AsyncStream<DatagramSocket>.Continuation
    /// UDP 소켓을 새 인터페이스로 다시 열어 달라는 요청. 겹치면 하나로 합친다.
    let rebindRequests: AsyncStream<Void>
    let rebindContinuation: AsyncStream<Void>.Continuation
    /// 버려진 연결·리스너 핸들. `deinit`은 기다릴 수 없으므로 여기에 넣고, `run()`의 자식이 받아 끊는다(계약 동작 N9).
    /// `run()`이 끝나면 닫혀 그 뒤의 것은 버려진다.
    let handleReleaseStream: AsyncStream<HandleRelease>
    nonisolated let handleReleases: AsyncStream<HandleRelease>.Continuation
    /// `run()`을 끝내는 실패. 처음 것만 쓴다.
    private let failures: AsyncStream<NodeError>
    let failureContinuation: AsyncStream<NodeError>.Continuation
    private(set) var hasRun = false
    /// `run()`이 돌고 있다(시작 검사를 마친 뒤부터 끝날 때까지).
    var isRunning = false

    /// 이 노드의 disco 개인 키. 저장하지 않고 노드마다 새로 만든다(노트 disco-magicsock 4.10 4). 사건·오류·`dump`에
    /// 나오지 않는다(`customMirror`).
    let discoKey = Curve25519.KeyAgreement.PrivateKey()

    // MARK: 데이터면 상태

    /// `run()` 동안 열려 있는 UDP 소켓. WireGuard·disco·STUN이 함께 쓴다. 재결속하는 동안 잠깐 nil이다.
    var socket: DatagramSocket?
    /// 마지막으로 읽은 인터페이스 주소. `Magicsock`의 local 엔드포인트가 된다.
    var interfaceAddresses: (regular: [SwiftailBase.IPAddress], loopback: [SwiftailBase.IPAddress]) = ([], [])
    /// `run()` 동안 쓰는 utun 장치(복제본). 메모리 장치면 nil.
    var tunnel: UTUNDevice?
    /// 등록을 마친 뒤에 생긴다. node 키가 바뀌면 `magicsock`과 함께 새로 만든다.
    var engine: TailnetEngine?
    /// 피어와의 경로를 고른다. `engine`과 함께 생기고 함께 바뀐다.
    var magicsock: Magicsock?
    /// 엔진과 DERP 클라이언트가 쓰는 node 개인 키. 신원 파일에서 읽는다.
    var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    /// 마지막으로 받은 netmap. 엔진을 새로 만들 때 다시 적용하고, DERP 지역의 서버를 찾고, `status`를 만든다.
    var lastNetmap: Netmap?
    /// 데이터면 피어의 키와 이름.
    var peerDirectory = PeerDirectory()
    /// `Magicsock`이 고른 홈 DERP 지역. 0이면 아직 없다.
    var homeRegion: Int64 = 0
    /// 열려 있는 DERP 지역 연결. 지역 ID → 연결.
    var derpLinks: [Int64: DERPLink] = [:]
    /// 서버와 연결되어 있는 지역.
    var connectedDERPRegions: Set<Int64> = []
    /// 제어 서버에 올릴 이 노드의 상태(disco 키, 엔드포인트, 홈 지역).
    var localStatus = ControlClient.LocalStatus()
    /// 시험용: 이 원격 포트로 보낼 UDP와 이 포트에서 온 UDP를 소켓 경계에서 버린다.
    var blockedUDPPorts: Set<UInt16> = []

    // MARK: 기본 인터페이스 (동작 N)

    /// 앱이 마지막으로 알린 기본 인터페이스. 새로 여는 모든 소켓과 연결을 여기에 묶는다. nil이면 묶지 않는다.
    var defaultInterface: NWInterface?
    /// 지금 소켓·연결을 묶은 인터페이스와 그때의 주소. `run()` 동안만 있다.
    var defaultLink: DefaultLink?

    // MARK: 알린 상태

    var stateMachine = NodeStateMachine()
    var settingsPublisher = NetworkSettingsPublisher()

    // MARK: 프로세스 안의 TCP (`.inProcess`)

    /// 스택과 응용이 쥔 연결. `.inProcess` 장치의 `run()` 동안만 있다(계약 M6 동작 N).
    var netstack: Netstack?
    /// 열린 리스너. `run()` 전에 연 것은 스택 없이 적어 두었다가 `run()`이 시작할 때 스택에 올린다(동작 A1).
    var listenerRecords: [UInt64: ListenerRecord] = [:]
    var nextListenerToken: UInt64 = 1
    /// 시험용: 스택과 엔진 사이에서 패킷을 버리는 확률과 난수(계약 동작 N11). nil이면 버리지 않는다.
    var inProcessLoss: PacketLoss?

    // MARK: 타이머를 깨우는 통로

    /// 다음 기한이 타이머가 잠든 시각보다 앞당겨졌다.
    var timerChanged: AsyncStream<Void>.Continuation?
    /// 타이머가 깨어나기로 한 시각.
    var armedDeadline: ContinuousClock.Instant?

    /// 설정과 장치를 검사한다. 파일·소켓·Task를 만들지 않는다(utun 검사는 읽기만 하는 시스템 호출이다).
    ///
    /// - Throws: `NodeError.invalidConfiguration`. 상태 디렉터리가 파일 URL이 아니거나, 제어 서버 URL이 `http(s)://`가
    ///   아니거나 호스트가 없거나, 호스트 이름이 비었거나, MTU가 1280…1420 밖이거나, utun 기술자가 아니다.
    public init(configuration: NodeConfiguration, device: TunnelDevice = .memory()) throws(NodeError) {
        try configuration.validate()
        tunnelName = try device.validate()
        self.configuration = configuration
        self.device = device
        identityStore = NodeIdentityStore(directory: configuration.stateDirectory)
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: NodeEvent.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
        (inboundStream, inboundContinuation) = AsyncStream.makeStream(of: [UInt8].self, bufferingPolicy: .bufferingNewest(Self.inboundPacketLimit))
        (settingsStream, settingsContinuation) = AsyncStream.makeStream(of: TunnelNetworkSettings.self, bufferingPolicy: .bufferingNewest(1))
        (loginRequests, loginContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        (interfaceRequests, interfaceContinuation) = AsyncStream.makeStream(of: NWInterface.self, bufferingPolicy: .bufferingNewest(1))
        (statusUploads, statusUploadContinuation) = AsyncStream.makeStream(of: ControlClient.LocalStatus.self, bufferingPolicy: .bufferingNewest(1))
        (openedDERPLinks, openedDERPLinkContinuation) = AsyncStream.makeStream(of: DERPLink.self)
        (openedSockets, openedSocketContinuation) = AsyncStream.makeStream(of: DatagramSocket.self)
        (rebindRequests, rebindContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        (handleReleaseStream, handleReleases) = AsyncStream.makeStream(of: HandleRelease.self)
        (failures, failureContinuation) = AsyncStream.makeStream(of: NodeError.self, bufferingPolicy: .bufferingOldest(1))
    }

    /// 상태와 경로 사건. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    ///
    /// 읽지 않은 사건은 가장 새 것 64개까지만 쥐고 오래된 것부터 버린다.
    public nonisolated var events: AsyncStream<NodeEvent> { eventStream }

    /// 앱이 OS에 적용할 터널 설정. 바뀐 경우에만 나오고, 읽지 않은 것은 가장 새 것 하나만 남는다(동작 E).
    /// 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    public nonisolated var networkSettings: AsyncStream<TunnelNetworkSettings> { settingsStream }

    /// 메모리 장치일 때 장치로 쓸 IP 패킷: 피어가 보냈고 필터를 통과한 것, 노드가 로컬에서 만든 응답(MagicDNS 등), 자기
    /// 주소로 보내 되돌아온 것. utun·`.inProcess` 장치일 때는 아무것도 내지 않는다(패킷은 utun이나 스택으로 간다).
    /// 구독자는 하나다. `run()`이
    /// 끝나면 흐름도 끝난다.
    ///
    /// 소비가 느리면 가장 새 것 256개까지만 쥐고 오래된 것부터 버린다.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { inboundStream }

    /// 지금 상태.
    public var status: NodeStatus {
        NodeStatus(state: stateMachine.state, netmap: lastNetmap, networkSettings: settingsPublisher.published)
    }

    /// 등록하고, netmap을 받아 데이터면을 유지한다. 호출한 Task가 취소될 때까지 돌아오지 않는다. 노드 하나에 한 번만 부른다.
    ///
    /// 끊긴 연결은 안에서 물러났다가 다시 잇는다. 다시 켜도 소용없는 실패만 던진다: 제어의 끝난 실패(`control`), 장치 닫힘
    /// (`tunnelDeviceClosed`), 같은 프로세스의 다른 노드가 상태 디렉터리를 쓰는 중(`stateDirectoryInUse`, 파일·소켓을 열기
    /// 전), UDP 소켓을 열지 못함(`udpUnavailable`). 실행 중이든 끝난 뒤든 다시 부르면 `invalidConfiguration`이다.
    ///
    /// `Task { }` 안에서 부를 때는 `do throws(NodeError) { try await node.run() } catch { … }`로 적어야 `catch`의
    /// `error`가 `NodeError`다. `throws(NodeError)`를 빼면 `any Error`로 추론된다.
    public func run() async throws(NodeError) {
        guard !hasRun else { throw .invalidConfiguration("run()은 노드 하나에 한 번만 부른다") }
        hasRun = true
        defer {
            // 시작 검사에서 끝났으면 `run()` 전에 연 리스너가 여기서 끝난다.
            stopNetstack()
            eventContinuation.finish()
            inboundContinuation.finish()
            settingsContinuation.finish()
        }
        let directory = configuration.stateDirectory
        guard StateDirectoryClaims.shared.claim(directory) else { throw .stateDirectoryInUse }
        defer { StateDirectoryClaims.shared.release(directory) }

        if case let .utun(descriptor, mtu) = device {
            do {
                tunnel = try UTUNDevice(duplicating: descriptor, mtu: mtu)
            } catch {
                throw NodeError(openingTunnel: error)
            }
        }
        // 읽지 못하면 local 엔드포인트 없이 계속한다. STUN이 찾은 엔드포인트만 올라간다(계약 N1).
        interfaceAddresses = (try? LocalInterfaceAddresses.current()) ?? ([], [])
        if let defaultInterface {
            defaultLink = DefaultLink(defaultInterface, addresses: interfaceAddresses)
        }
        let socket: DatagramSocket
        do {
            socket = try openSocketOnAnyPort()
        } catch {
            tunnel?.close()
            tunnel = nil
            throw error
        }
        adopt(socket)
        isRunning = true
        defer {
            isRunning = false
            // 끝난 노드는 키·세션·연결·기술자를 쥐지 않는다. `path(toPeerNamed:)`는 nil이 되고 `send`는 버린다.
            // utun은 복제본만 닫는다(동작 U2).
            self.socket?.close()
            self.socket = nil
            tunnel?.close()
            tunnel = nil
            closeAllDERPLinks()
            openedDERPLinkContinuation.finish()
            openedSocketContinuation.finish()
            engine = nil
            magicsock = nil
            nodeKey = nil
            defaultLink = nil
        }
        startNetstack()
        // 위의 정리보다 먼저 돈다: 소켓과 엔진이 있을 때 열린 연결마다 RST를 낸다(동작 N8).
        defer { stopNetstack() }

        let control = ControlClient(
            configuration: .init(
                serverURL: configuration.controlURL,
                hostname: configuration.hostname,
                authKey: configuration.authKey,
                ephemeral: configuration.ephemeral
            ),
            identityStore: identityStore
        )
        // 0이 아닌 DiscoKey를 올려야 Go 피어가 이 노드를 피어로 만든다(노트 derp-stun 6절 7).
        localStatus = .init(discoKey: DiscoPublicKey(discoKey.publicKey))
        await control.setLocalStatus(localStatus)
        if let defaultInterface {
            await control.setNetworkInterface(defaultInterface)
        }

        let failure = await withTaskGroup(of: NodeError?.self, returning: NodeError?.self) { group in
            group.addTask {
                do throws(ControlError) {
                    try await control.run()
                    return nil
                } catch {
                    return NodeError(error)
                }
            }
            group.addTask { await self.follow(control) }
            group.addTask { await self.forwardLoginRequests(to: control); return nil }
            group.addTask { await self.forwardInterfaces(to: control); return nil }
            group.addTask { await self.uploadLocalStatus(to: control); return nil }
            group.addTask { await self.receiveUDP(); return nil }
            group.addTask { await self.rebindUDP(); return nil }
            group.addTask { await self.maintainDERP(); return nil }
            group.addTask { await self.runTimer(); return nil }
            group.addTask { await self.releaseHandles(); return nil }
            group.addTask { await self.awaitFailure() }
            if let tunnel = self.tunnel {
                group.addTask { await self.readTunnel(tunnel) }
            }

            // 자식들은 취소될 때까지 돌므로, 하나라도 끝났다면 노드가 끝난 것이다. 나머지를 거두며 실패를 모은다.
            // 제어가 실패하면 사건 흐름도 함께 끝나므로 어느 쪽이 먼저 돌아올지 모른다. 그래서 첫 결과만 보지 않는다.
            var failure: NodeError?
            for await result in group {
                group.cancelAll()
                failure = failure ?? result
            }
            return failure
        }
        if let failure {
            Self.log.error("노드가 끝남: \(failure.kind, privacy: .public)")
            throw failure
        }
        Self.log.info("노드가 멈춤")
    }

    /// 메모리 장치일 때 IP 패킷 하나를 넣는다(utun에서 읽은 것과 같은 처리). 보낼 수 없으면(등록 전, 피어 없음, 경로 없음)
    /// 조용히 버린다. utun 장치와 `.inProcess` 장치일 때는 버린다.
    public func send(_ ipPacket: [UInt8]) {
        guard case .memory = device else { return }
        deliverFromDevice(ipPacket)
    }

    /// 이름이 `fqdn`인 피어의 지금 경로. 그런 피어가 데이터면에 없거나 45초 넘게 주고받은 것이 없으면(유휴) nil.
    ///
    /// 이름은 끝의 점 하나를 떼고 ASCII 대소문자를 무시해 비교한다. 같은 이름이 둘이면 node ID가 작은 쪽이다.
    /// 경로의 뜻은 Go `tailscale status`의 직접 주소(`CurAddr`)와 같다(`PeerPath`).
    public func path(toPeerNamed fqdn: String) -> PeerPath? {
        guard let key = peerDirectory.key(named: fqdn) else { return nil }
        return magicsock?.path(to: key, at: .now)
    }

    /// 대화형 로그인 URL을 새로 요청한다(이미 등록되어 있어도). URL은 `.stateChanged(.needsLogin(url))`로 온다.
    public func startInteractiveLogin() {
        loginContinuation.yield()
    }

    /// 시험 전용(공개 API 아님). 이 원격 UDP 포트로 보낼 것과 이 포트에서 온 것을 소켓 경계에서 버린다.
    ///
    /// 직접 경로가 끊긴 상황을 만든다. `Magicsock`과 엔진은 이 집합을 모른다. 기본은 빈 집합이다(계약 N8).
    package func setBlockedUDPPorts(_ ports: Set<UInt16>) {
        blockedUDPPorts = ports
    }

    private func forwardLoginRequests(to control: ControlClient) async {
        for await _ in loginRequests {
            await control.startInteractiveLogin()
        }
    }

    private func forwardInterfaces(to control: ControlClient) async {
        for await interface in interfaceRequests {
            await control.setNetworkInterface(interface)
        }
    }

    private func uploadLocalStatus(to control: ControlClient) async {
        for await status in statusUploads {
            await control.setLocalStatus(status)
        }
    }

    /// `run()`을 끝내는 실패를 기다린다.
    private func awaitFailure() async -> NodeError? {
        for await failure in failures {
            return failure
        }
        return nil
    }

    /// 상태 기계가 낸 새 상태를 알린다.
    func announce(_ state: NodeState?) {
        guard let state else { return }
        Self.log.info("상태: \(state.logName, privacy: .public)")
        eventContinuation.yield(.stateChanged(state))
    }
}

extension TailnetNode: CustomReflectable {
    /// node 개인 키, disco 개인 키, 엔진(WireGuard 세션)을 쥐므로 자식을 감춘다.
    public nonisolated var customMirror: Mirror {
        Mirror(self, children: ["hostname": configuration.hostname])
    }
}

extension DefaultLink {
    init(_ interface: NWInterface, addresses: (regular: [SwiftailBase.IPAddress], loopback: [SwiftailBase.IPAddress])) {
        self.init(name: interface.name, index: interface.index, addresses: addresses.regular, loopbackAddresses: addresses.loopback)
    }
}

extension NodeState {
    /// 로그에 남길 이름. 로그인 URL은 남기지 않는다.
    var logName: String {
        switch self {
        case .starting: "starting"
        case .needsLogin: "needsLogin"
        case .needsMachineAuth: "needsMachineAuth"
        case .running: "running"
        }
    }
}

extension NodeError {
    /// utun을 복제하지 못한 실패. 검사(`init`) 뒤에 기술자가 닫혔거나 바뀐 것은 설정 오류, 그 밖은 장치를 쓸 수 없는 것이다.
    init(openingTunnel error: SocketError) {
        if case .invalidDevice = error {
            self = .invalidConfiguration("utun 기술자가 아니다")
        } else {
            self = .tunnelDeviceClosed(error.message)
        }
    }

    /// 로그에 남길 종류. 서버의 진단 문자열은 남기지 않는다.
    var kind: String {
        switch self {
        case let .control(error): "control(\(error.kind))"
        case .invalidConfiguration: "invalidConfiguration"
        case let .udpUnavailable(message): "udpUnavailable(\(message))"
        case .stateDirectoryInUse: "stateDirectoryInUse"
        case let .tunnelDeviceClosed(message): "tunnelDeviceClosed(\(message))"
        }
    }
}

extension ControlError {
    /// 로그에 남길 종류.
    var kind: String {
        switch self {
        case .invalidConfiguration: "invalidConfiguration"
        case .storage: "storage"
        case .connection: "connection"
        case let .http(status): "http(\(status))"
        case .authKeyRejected: "authKeyRejected"
        case .registrationRejected: "registrationRejected"
        case .nodeKeyExpired: "nodeKeyExpired"
        case .tailnetLockEnabled: "tailnetLockEnabled"
        }
    }
}

extension SocketError {
    /// errno 이름 등 사람이 읽을 메시지. 경로나 키를 담지 않는다.
    var message: String {
        switch self {
        case let .connectFailed(message), let .readFailed(message), let .bindFailed(message), let .sendFailed(message),
            let .invalidDevice(message):
            message
        }
    }
}
