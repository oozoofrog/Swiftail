import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailEngine
import SwiftailIO
import SwiftailMagicsock

/// tailnet의 노드 하나. IP 패킷을 메모리로 주고받는다(TUN은 M5, 리스너는 M6). 피어와는 직접 UDP 경로를 찾아 쓰고,
/// 찾지 못하거나 끊기면 DERP 중계로 보낸다.
///
/// 이 actor는 가장자리다. 프로토콜의 판단은 `ControlClient`(등록·맵), `DERPClient`(중계), 그리고 입출력 없는 두 상태 기계
/// `TailnetEngine`(WireGuard·필터)과 `Magicsock`(경로 찾기·STUN·홈 지역)이 하고, 여기서는 그것들과 UDP 소켓, 시계를 잇는다.
///
/// 두 상태 기계는 값 타입이라 이 actor의 저장 프로퍼티로 두고 제자리에서만 바꾼다. 사건 하나(받은 UDP, 받은 DERP 패킷,
/// 내려온 IP 패킷, 타이머)를 처리할 때는 한쪽의 출력을 다른 쪽에 넘기는 일을 `await` 없이 끝까지 돌리고, 입출력은 통로에
/// 넣기만 한다. 그래서 actor 재진입이 두 상태 사이에 끼어들지 못한다. 시각(`ContinuousClock.now`, `Date()`)을 만드는 곳도
/// 여기뿐이다.
///
/// 동시성은 구조적이다. 모든 일은 `run()` 안의 TaskGroup 자식이고, `run()`을 부른 Task를 취소하면 모두 멈춘다.
///
/// ```
/// run()
///  └ TaskGroup: 노드의 수명. 자식 하나가 끝나면 나머지를 취소하고 run()이 돌아온다
///     ├ control.run()             등록, 맵 스트림, 끊기면 다시 잇기
///     ├ follow(control)           제어 사건 → 엔진·Magicsock, NodeEvent
///     ├ forwardLoginRequests      startInteractiveLogin() → 제어
///     ├ uploadLocalStatus         Magicsock이 바꾼 엔드포인트·홈 지역 → 제어
///     ├ receiveUDP()              소켓의 데이터그램 → Magicsock. 소켓이 닫히면 끝난다
///     ├ maintainDERP()            열린 지역 연결마다 아래 묶음 하나. 연결의 통로를 닫으면 그 묶음이 접힌다
///     │   └ TaskGroup: DERP 지역 연결 하나의 수명
///     │      ├ client.run()
///     │      ├ client.events → Magicsock
///     │      └ 이 지역으로 보낼 데이터그램 → client.send. 통로가 닫히면 끝나고 묶음 전체를 접는다
///     └ runTimer()                엔진과 Magicsock의 이른 기한에 깨어나 둘 다 advance
/// ```
///
/// ```swift
/// let node = TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: url))
/// async let running: Void = node.run()
/// for await event in node.events { … }
/// ```
///
/// 계약 `docs/contracts/SwiftailEngine.md` "노드 API (`Swiftail`)"와 "M4에서 바뀌는 것".
public actor TailnetNode {
    /// 읽지 않은 사건 수의 한도. 넘으면 오래된 것부터 버린다.
    static let eventBufferLimit = 64
    /// 읽지 않은 받은 패킷 수의 한도. 넘으면 오래된 것부터 버린다(IP는 원래 그렇다).
    static let inboundPacketLimit = 256
    /// DERP로 아직 넘기지 못한 데이터그램 수의 한도(지역 연결마다). 넘으면 오래된 것부터 버린다. WireGuard가 다시 보낸다.
    static let outboundDatagramLimit = 256

    /// 끊기면 `reconnecting`을 알리는 연결.
    enum Link: Hashable {
        case control
        /// 홈 지역의 DERP 연결. 다른 지역의 연결은 세지 않는다.
        case derp
    }

    let configuration: NodeConfiguration
    let identityStore: NodeIdentityStore
    let eventContinuation: AsyncStream<NodeEvent>.Continuation
    let inboundContinuation: AsyncStream<[UInt8]>.Continuation
    private let eventStream: AsyncStream<NodeEvent>
    private let inboundStream: AsyncStream<[UInt8]>
    /// `startInteractiveLogin()`이 `run()` 밖에서도 불릴 수 있으므로 요청을 흐름에 담아 두고 자식이 제어로 넘긴다.
    private let loginRequests: AsyncStream<Void>
    private let loginContinuation: AsyncStream<Void>.Continuation
    /// 제어 서버에 올릴 상태. 마지막 것만 의미가 있다.
    private let statusUploads: AsyncStream<ControlClient.LocalStatus>
    let statusUploadContinuation: AsyncStream<ControlClient.LocalStatus>.Continuation
    /// 새로 연 DERP 지역 연결. `maintainDERP()`가 받아 돌린다. 그 자식이 돌기 전에 연 연결도 잃지 않게 여기서 만든다.
    let openedDERPLinks: AsyncStream<DERPLink>
    let openedDERPLinkContinuation: AsyncStream<DERPLink>.Continuation
    private var hasRun = false

    /// 이 노드의 disco 개인 키. 저장하지 않고 노드마다 새로 만든다(노트 disco-magicsock 4.10 4). 사건·오류·`dump`에
    /// 나오지 않는다(`customMirror`).
    let discoKey = Curve25519.KeyAgreement.PrivateKey()

    // MARK: 데이터면 상태

    /// `run()` 동안 열려 있는 UDP 소켓. WireGuard·disco·STUN이 함께 쓴다.
    var socket: DatagramSocket?
    /// `run()`이 시작할 때 한 번 읽은 인터페이스 주소. `Magicsock`의 local 엔드포인트가 된다.
    // shortcut: 주소 변경 감지와 재결속은 하지 않는다(계약 제외 표). 필요해지는 시점: M5(`setDefaultInterface`, 링크 변경).
    var interfaceAddresses: (regular: [IPAddress], loopback: [IPAddress]) = ([], [])
    /// 등록을 마친 뒤에 생긴다. node 키가 바뀌면 `magicsock`과 함께 새로 만든다.
    var engine: TailnetEngine?
    /// 피어와의 경로를 고른다. `engine`과 함께 생기고 함께 바뀐다.
    var magicsock: Magicsock?
    /// 엔진과 DERP 클라이언트가 쓰는 node 개인 키. 신원 파일에서 읽는다.
    var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    /// 마지막으로 받은 netmap. 엔진을 새로 만들 때 다시 적용하고, DERP 지역의 서버를 찾는다.
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

    // MARK: 알린 상태

    /// 마지막으로 `running`에 실은 주소. 아직 알리지 않았으면 nil.
    var announcedAddresses: [IPAddress]?
    /// `reconnecting`을 알린 뒤 아직 돌아오지 않은 연결.
    var brokenLinks: Set<Link> = []

    // MARK: 타이머를 깨우는 통로

    /// 다음 기한이 타이머가 잠든 시각보다 앞당겨졌다.
    var timerChanged: AsyncStream<Void>.Continuation?
    /// 타이머가 깨어나기로 한 시각.
    var armedDeadline: ContinuousClock.Instant?

    public init(configuration: NodeConfiguration) {
        self.configuration = configuration
        identityStore = NodeIdentityStore(directory: configuration.stateDirectory)
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: NodeEvent.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
        (inboundStream, inboundContinuation) = AsyncStream.makeStream(of: [UInt8].self, bufferingPolicy: .bufferingNewest(Self.inboundPacketLimit))
        (loginRequests, loginContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        (statusUploads, statusUploadContinuation) = AsyncStream.makeStream(of: ControlClient.LocalStatus.self, bufferingPolicy: .bufferingNewest(1))
        (openedDERPLinks, openedDERPLinkContinuation) = AsyncStream.makeStream(of: DERPLink.self)
    }

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    ///
    /// 읽지 않은 사건은 가장 새 것 64개까지만 쥐고 오래된 것부터 버린다.
    public nonisolated var events: AsyncStream<NodeEvent> { eventStream }

    /// 피어가 보냈고 필터를 통과한 IP 패킷. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    ///
    /// 소비가 느리면 가장 새 것 256개까지만 쥐고 오래된 것부터 버린다.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { inboundStream }

    /// 등록하고, netmap을 받아 데이터면을 유지한다. 호출한 Task가 취소될 때까지 돌아오지 않는다.
    ///
    /// 끊긴 연결은 안에서 다시 잇는다. 다시 시도해도 소용없는 실패만 던진다. 노드 하나에 한 번만 부른다.
    /// 실행 중이든 끝난 뒤든 다시 부르면 `invalidConfiguration`이다. UDP 소켓을 열지 못하면 `udpUnavailable`이다.
    public func run() async throws(NodeError) {
        guard !hasRun else { throw .invalidConfiguration("run()은 노드 하나에 한 번만 부른다") }
        hasRun = true
        defer {
            eventContinuation.finish()
            inboundContinuation.finish()
        }
        guard configuration.stateDirectory.isFileURL else { throw .invalidConfiguration("상태 디렉터리는 파일 URL이어야 한다") }

        let socket: DatagramSocket
        do {
            socket = try DatagramSocket(port: 0)
        } catch {
            throw .udpUnavailable(error.message)
        }
        self.socket = socket
        defer {
            socket.close()
            self.socket = nil
            // 끝난 노드는 키·세션·연결을 쥐지 않는다. `path(toPeerNamed:)`는 nil이 되고 `send`는 버린다.
            closeAllDERPLinks()
            openedDERPLinkContinuation.finish()
            engine = nil
            magicsock = nil
            nodeKey = nil
        }
        // 읽지 못하면 local 엔드포인트 없이 계속한다. STUN이 찾은 엔드포인트만 올라간다(계약 N1).
        interfaceAddresses = (try? LocalInterfaceAddresses.current()) ?? ([], [])

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
            group.addTask { await self.uploadLocalStatus(to: control); return nil }
            group.addTask { await self.receiveUDP(from: socket); return nil }
            group.addTask { await self.maintainDERP(); return nil }
            group.addTask { await self.runTimer(); return nil }

            // 자식들은 취소될 때까지 돌므로, 하나라도 끝났다면 노드가 끝난 것이다. 나머지를 거두며 실패를 모은다.
            // 제어가 실패하면 사건 흐름도 함께 끝나므로 어느 쪽이 먼저 돌아올지 모른다. 그래서 첫 결과만 보지 않는다.
            var failure: NodeError?
            for await result in group {
                group.cancelAll()
                failure = failure ?? result
            }
            return failure
        }
        if let failure { throw failure }
    }

    /// IP 패킷 하나를 tailnet으로 보낸다. 보낼 수 없으면(등록 전, 피어 없음, 경로 없음) 조용히 버린다.
    public func send(_ ipPacket: [UInt8]) {
        let now = ContinuousClock.now
        process(engine?.send(ipPacket, at: now) ?? [], at: now)
    }

    /// 이름이 `fqdn`인 피어의 지금 경로. 그런 피어가 데이터면에 없거나 45초 넘게 주고받은 것이 없으면(유휴) nil.
    ///
    /// 이름은 끝의 점 하나를 떼고 ASCII 대소문자를 무시해 비교한다. 같은 이름이 둘이면 node ID가 작은 쪽이다.
    /// 경로의 뜻은 Go `tailscale status`의 직접 주소(`CurAddr`)와 같다(`PeerPath`).
    public func path(toPeerNamed fqdn: String) -> PeerPath? {
        guard let key = peerDirectory.key(named: fqdn) else { return nil }
        return magicsock?.path(to: key, at: .now)
    }

    /// 대화형 로그인 URL을 새로 요청한다(이미 등록되어 있어도). URL은 `loginRequired`로 온다.
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

    private func uploadLocalStatus(to control: ControlClient) async {
        for await status in statusUploads {
            await control.setLocalStatus(status)
        }
    }
}

extension TailnetNode: CustomReflectable {
    /// node 개인 키, disco 개인 키, 엔진(WireGuard 세션)을 쥐므로 자식을 감춘다.
    public nonisolated var customMirror: Mirror {
        Mirror(self, children: ["hostname": configuration.hostname])
    }
}

private extension SocketError {
    /// errno 이름 등 사람이 읽을 메시지. 경로나 키를 담지 않는다.
    var message: String {
        switch self {
        case let .connectFailed(message), let .readFailed(message), let .bindFailed(message), let .sendFailed(message),
            let .invalidDevice(message):
            message
        }
    }
}
