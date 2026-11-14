import Foundation
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock

/// 데이터면의 흐름: 엔진과 `Magicsock`의 출력을 서로에게 넘기고 입출력으로 내보낸다. 타이머도 여기 있다.
///
/// ```
/// 장치 ─► engine.send ─┬ .datagram(to: 피어) ─► magicsock.send ─┬ .udp ─► 소켓
///                     │                                      └ .derp ─► 그 지역 연결
///                     └ .ipPacket(로컬 응답·되돌린 패킷) ─► 장치
/// 소켓 ─► magicsock.receiveUDP ─┐
/// DERP ─► magicsock.receiveDERP ┴ .wireGuard ─► engine.receive ─ .ipPacket ─► 장치
///                                                              └ .datagram(핸드셰이크 응답 등) ─► magicsock.send …
/// ```
///
/// 사건 하나는 `process`로 시작해 두 상태 기계 사이의 주고받기를 `await` 없이 끝까지 돈다. 입출력은 기다리지 않는
/// 통로(소켓 `send`, 지역 연결의 통로, 사건 흐름)에 넣기만 한다. 출력 목록은 받은 순서대로 처리한다(`Magicsock`의 호출 규칙).
/// 한 사건 안의 호출은 모두 같은 시각 `now`를 쓴다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N5·N6·N8, `docs/contracts/SwiftailTunnel.md` 동작 L·B.
extension TailnetNode {
    // MARK: 두 상태 기계 잇기

    /// 엔진의 출력을 처리한다. 엔진을 바꾼 모든 호출 뒤에 부른다.
    func process(_ outputs: [TailnetEngine.Output], at now: ContinuousClock.Instant) {
        for output in outputs {
            switch output {
            case let .datagram(bytes, to: peer):
                process(magicsock?.send(bytes, to: peer, at: now) ?? [], at: now)
            case let .ipPacket(bytes):
                // 엔진은 로컬 응답, 자기 주소로 되돌린 패킷, 피어가 보낸 패킷을 모두 "장치로 쓸 것"으로 낸다.
                deliverToDevice(bytes)
            case .dropped:
                break
            }
        }
        rearmTimer()
    }

    /// `Magicsock`의 출력을 처리한다. `Magicsock`을 바꾼 모든 호출 뒤에 부른다.
    func process(_ outputs: [Magicsock.Output], at now: ContinuousClock.Instant) {
        for output in outputs {
            switch output {
            case let .udp(bytes, to: destination):
                sendUDP(bytes, to: destination)
            case let .derp(bytes, to: peer, region: region):
                sendDERP(bytes, to: peer, region: region)
            case let .wireGuard(bytes):
                let received = engine?.receive(bytes, at: now) ?? []
                if received.contains(where: \.provesSession) {
                    announce(stateMachine.connected())
                }
                process(received, at: now)
            case let .endpointsChanged(endpoints):
                endpointsChanged(endpoints)
            case let .homeRegionChanged(region):
                homeRegionChanged(to: region)
            case let .pathChanged(peer, path):
                Self.log.info("피어 경로: \(path.logName, privacy: .public)")
                if let name = peerDirectory.name(of: peer) {
                    eventContinuation.yield(.peerPathChanged(fqdn: name, path: path))
                }
            case .dropped:
                break
            }
        }
        rearmTimer()
    }

    // MARK: UDP

    /// 데이터그램 하나를 소켓으로 보낸다. 실패는 버린다(DERP로 함께 나가거나 WireGuard·disco가 다시 보낸다).
    // shortcut: 송신 오류(`EHOSTUNREACH`·`EPERM` 등)에 따른 재결속은 하지 않는다(터널 계약 동작 N 6). 필요해지는 시점:
    // 실기기 전환 시험에서 `setDefaultInterface` 없이 소켓이 죽을 때.
    private func sendUDP(_ bytes: [UInt8], to destination: IPEndpoint) {
        guard !blockedUDPPorts.contains(destination.port) else { return }
        do {
            try socket?.send(bytes, to: destination)
        } catch {
            return
        }
    }

    // MARK: 타이머

    /// 엔진과 `Magicsock`의 다음 기한 가운데 이른 것.
    private var nextDeadline: ContinuousClock.Instant? {
        [engine?.nextDeadline, magicsock?.nextDeadline].compactMap { $0 }.min()
    }

    /// 다음 기한에 깨어나 엔진과 `Magicsock`의 `advance`를 부른다. 기한이 앞당겨지면 다시 계산한다. 취소될 때까지 돈다.
    ///
    /// 바뀜 신호를 받을 흐름을 매번 새로 만들어 통로를 actor에 건다(경쟁에서 진 쪽을 취소하면 그 흐름이 끝나기 때문이다).
    /// 통로를 거는 일과 기한을 읽는 일 사이에 `await`가 없으므로 그 사이의 바뀜을 놓치지 않는다.
    func runTimer() async {
        while !Task.isCancelled {
            let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            timerChanged = continuation
            let deadline = nextDeadline
            armedDeadline = deadline
            await withTaskGroup(of: Void.self) { group in
                if let deadline {
                    group.addTask { try? await Task.sleep(until: deadline, clock: .continuous) }
                }
                group.addTask {
                    for await _ in changes { return }
                }
                await group.next()
                group.cancelAll()
            }
            // 일찍 깨어났어도 괜찮다. 기한 전의 advance는 아무것도 하지 않는다.
            let now = ContinuousClock.now
            process(engine?.advance(to: now) ?? [], at: now)
            process(magicsock?.advance(to: now) ?? [], at: now)
        }
        timerChanged = nil
    }

    /// 다음 기한이 타이머가 잠든 시각보다 이르면 타이머를 깨운다. 늦어진 것은 타이머가 깨어나 다시 계산한다.
    func rearmTimer() {
        guard let next = nextDeadline else { return }
        if let armedDeadline, armedDeadline <= next { return }
        timerChanged?.yield()
    }
}

extension TailnetEngine.Output {
    /// 피어와의 WireGuard 세션이 섰다는 증거인가. `engine.receive`의 출력에만 묻는다.
    ///
    /// 복호화한 전송 패킷에서만 나오는 출력(올릴 패킷, 필터·해석·TSMP로 버린 것)이면 참이다. 엔진은 핸드셰이크를 마친
    /// 시각을 내지 않으므로 이것으로 상태 기계의 "세션을 맺은 피어가 있음"(동작 B 5)을 잰다.
    // shortcut: Go는 핸드셰이크를 마친 순간(`LastHandshake`)을 본다. 여기서는 그 세션의 첫 전송 패킷(keepalive 제외)을
    // 받을 때라 조금 늦을 수 있다. 홈 DERP 연결이 서면 그보다 먼저 `.running`이 되므로 보통은 차이가 없다. 필요해지는
    // 시점: DERP 없이 직접 경로만 쓰는 tailnet에서 `.running`이 늦는 것이 보일 때(엔진에 세션 사건을 더한다).
    var provesSession: Bool {
        switch self {
        case .ipPacket: true
        case .datagram: false
        case let .dropped(reason):
            switch reason {
            case .inbound, .malformedPacket, .unsupportedPacket, .consumedControlPacket: true
            case .serviceIPPacket, .noPeerForDestination, .wireGuard: false
            }
        }
    }
}

extension Optional<PeerPath> {
    /// 로그에 남길 경로의 종류. 주소는 남기지 않는다.
    var logName: String {
        switch self {
        case .direct: "direct"
        case let .relayed(region): "relayed(\(region))"
        case nil: "none"
        }
    }
}
