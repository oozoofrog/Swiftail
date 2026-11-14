import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailEngine

/// tailnet의 노드 하나. M3에서는 IP 패킷을 메모리로 주고받고, 모든 패킷이 홈 DERP 지역을 거친다
/// (직접 UDP는 M4, TUN은 M5, 리스너는 M6).
///
/// 이 actor는 가장자리다. 프로토콜의 판단은 `ControlClient`(등록·맵), `DERPClient`(중계), 입출력 없는 상태 기계
/// `TailnetEngine`(WireGuard·필터)이 하고, 여기서는 그 셋과 시계를 잇는다. 엔진은 값 타입이라 이 actor의 저장
/// 프로퍼티로 두고 제자리에서만 바꾼다. 엔진을 `await` 너머로 들고 다니지 않으므로 actor 재진입으로 상태가 어긋나지 않는다.
/// 시각(`ContinuousClock.now`, `Date()`)을 만드는 곳도 여기뿐이다.
///
/// 동시성은 구조적이다. 모든 일은 `run()` 안의 TaskGroup 자식이고, `run()`을 부른 Task를 취소하면 모두 멈춘다.
///
/// ```
/// run()
///  └ TaskGroup: 노드의 수명. 자식 하나가 끝나면 나머지를 취소하고 run()이 돌아온다
///     ├ control.run()             등록, 맵 스트림, 끊기면 다시 잇기
///     ├ follow(control)           제어 사건 → 엔진, 홈 DERP, NodeEvent
///     ├ forwardLoginRequests      startInteractiveLogin() → 제어
///     ├ maintainDERP()            홈 지역이나 node 키가 바뀔 때마다 아래 묶음을 접고 새로 띄운다
///     │   └ TaskGroup: DERP 클라이언트 하나의 수명
///     │      ├ client.run()
///     │      ├ client.events → 엔진
///     │      ├ 엔진이 낸 데이터그램 → client.send
///     │      └ 바뀜 신호 기다리기. 오면 이 묶음 전체를 취소한다
///     └ runTimer()                engine.nextDeadline에 깨어나 engine.advance
/// ```
///
/// ```swift
/// let node = TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: url))
/// async let running: Void = node.run()
/// for await event in node.events { … }
/// ```
///
/// 계약 `docs/contracts/SwiftailEngine.md` "노드 API (`Swiftail`)".
public actor TailnetNode {
    /// 읽지 않은 사건 수의 한도. 넘으면 오래된 것부터 버린다.
    static let eventBufferLimit = 64
    /// 읽지 않은 받은 패킷 수의 한도. 넘으면 오래된 것부터 버린다(IP는 원래 그렇다).
    static let inboundPacketLimit = 256
    /// DERP로 아직 넘기지 못한 데이터그램 수의 한도. 넘으면 오래된 것부터 버린다. WireGuard가 다시 보낸다.
    static let outboundDatagramLimit = 256

    /// 끊기면 `reconnecting`을 알리는 연결.
    enum Link: Hashable {
        case control
        case derp
    }

    /// 엔진이 낸, DERP로 보낼 WireGuard 메시지.
    struct OutboundDatagram: Sendable {
        var bytes: [UInt8]
        var peer: NodePublicKey
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
    private var hasRun = false

    // MARK: 데이터면 상태

    /// 등록을 마친 뒤에 생긴다. node 키가 바뀌면 새로 만든다.
    var engine: TailnetEngine?
    /// 엔진과 DERP 클라이언트가 쓰는 node 개인 키. 신원 파일에서 읽는다.
    var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    /// 마지막으로 받은 netmap. 엔진을 새로 만들 때 다시 적용한다.
    var lastNetmap: Netmap?
    /// 지금 홈 DERP 지역. 쓸 수 있는 지역을 받기 전에는 nil이고, 그동안 DERP 클라이언트가 없다.
    var home: DERPHome?
    /// 제어 서버에 올릴 이 노드의 상태(disco 키, 홈 지역).
    var localStatus = ControlClient.LocalStatus()

    // MARK: 알린 상태

    /// 마지막으로 `running`에 실은 주소. 아직 알리지 않았으면 nil.
    var announcedAddresses: [IPAddress]?
    /// `reconnecting`을 알린 뒤 아직 돌아오지 않은 연결.
    var brokenLinks: Set<Link> = []

    // MARK: 자식을 깨우는 통로

    /// 홈 지역이나 node 키가 바뀌었다. DERP 클라이언트를 다시 띄운다.
    var derpChanged: AsyncStream<Void>.Continuation?
    /// 지금 DERP 클라이언트로 가는 데이터그램 통로. 클라이언트가 없으면 nil이고 데이터그램은 버린다.
    var derpOutbound: AsyncStream<OutboundDatagram>.Continuation?
    /// 엔진의 다음 기한이 타이머가 잠든 시각보다 앞당겨졌다.
    var timerChanged: AsyncStream<Void>.Continuation?
    /// 타이머가 깨어나기로 한 시각.
    var armedDeadline: ContinuousClock.Instant?

    public init(configuration: NodeConfiguration) {
        self.configuration = configuration
        identityStore = NodeIdentityStore(directory: configuration.stateDirectory)
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: NodeEvent.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
        (inboundStream, inboundContinuation) = AsyncStream.makeStream(of: [UInt8].self, bufferingPolicy: .bufferingNewest(Self.inboundPacketLimit))
        (loginRequests, loginContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
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
    /// 실행 중이든 끝난 뒤든 다시 부르면 `invalidConfiguration`이다.
    public func run() async throws(NodeError) {
        guard !hasRun else { throw .invalidConfiguration("run()은 노드 하나에 한 번만 부른다") }
        hasRun = true
        defer {
            eventContinuation.finish()
            inboundContinuation.finish()
        }
        guard configuration.stateDirectory.isFileURL else { throw .invalidConfiguration("상태 디렉터리는 파일 URL이어야 한다") }

        let control = ControlClient(
            configuration: .init(
                serverURL: configuration.controlURL,
                hostname: configuration.hostname,
                authKey: configuration.authKey,
                ephemeral: configuration.ephemeral
            ),
            identityStore: identityStore
        )
        // disco 키는 저장하지 않고 시작할 때마다 새로 만든다. 0이 아닌 DiscoKey를 올려야 Go 피어가 이 노드를 피어로
        // 만든다(노트 derp-stun 6절 7).
        // shortcut: M3은 disco 메시지에 답하지 않으므로 개인 키를 쥐지 않는다. disco는 M4에서 magicsock이 맡는다.
        localStatus = .init(discoKey: DiscoPublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey))
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

    /// IP 패킷 하나를 tailnet으로 보낸다. 보낼 수 없으면(등록 전, 피어 없음, 홈 지역 밖) 조용히 버린다.
    public func send(_ ipPacket: [UInt8]) {
        route(engine?.send(ipPacket, at: .now) ?? [])
    }

    /// 대화형 로그인 URL을 새로 요청한다(이미 등록되어 있어도). URL은 `loginRequired`로 온다.
    public func startInteractiveLogin() {
        loginContinuation.yield()
    }

    private func forwardLoginRequests(to control: ControlClient) async {
        for await _ in loginRequests {
            await control.startInteractiveLogin()
        }
    }
}

extension TailnetNode: CustomReflectable {
    /// node 개인 키와 엔진(WireGuard 세션)을 쥐므로 자식을 감춘다.
    public nonisolated var customMirror: Mirror {
        Mirror(self, children: ["hostname": configuration.hostname])
    }
}
