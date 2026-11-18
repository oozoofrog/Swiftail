import Foundation
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock

/// 데이터면의 흐름: 엔진과 `Magicsock`의 출력을 서로에게 넘기고 입출력으로 내보낸다. 타이머도 여기 있다.
/// `.inProcess` 장치의 TCP 스택과의 주고받기는 `TailnetNode+Netstack.swift`에 있다.
///
/// ```
/// 장치 ─► engine.send ─┬ .datagram(to: 피어) ─► magicsock.send ─┬ .udp ─► 소켓
///                     │                                      └ .derp ─► 그 지역 연결
///                     └ .ipPacket(로컬 응답·되돌린 패킷) ─► 장치
/// 소켓 ─► magicsock.receiveUDP ─┐
/// DERP ─► magicsock.receiveDERP ┴ .wireGuard(from: 길) ─► engine.receive ─ .ipPacket ─► 장치
///                                                                      ├ .datagram(핸드셰이크 응답 등) ─► magicsock.send …
///                                                                      ├ .cookieReply ─► 받은 길(UDP 주소, DERP 보낸 쪽)
///                                                                      └ .discoKeyAdvertised ─► magicsock.receiveDiscoKeyAdvertisement
/// ```
///
/// 사건 하나는 `process`로 시작해 두 상태 기계 사이의 주고받기를 `await` 없이 끝까지 돈다. 입출력은 기다리지 않는
/// 통로(UDP 송신 묶음, 지역 연결의 통로, 사건 흐름)에 넣기만 한다. 출력 목록은 받은 순서대로 처리한다(`Magicsock`의 호출 규칙).
/// 한 사건 안의 호출은 모두 같은 시각 `now`를 쓴다.
///
/// 처리는 겹쳐 열린다(`process` 안에서 다른 `process`를 부른다). 가장 바깥 처리가 닫힐 때 한 번만 마무리한다
/// (`endProcessing(at:)`): 스택의 대기열과 미뤄 둔 ACK, 모은 UDP 데이터그램을 소켓에 넘기기, 타이머 다시 걸기. 여러 사건을
/// 한 번에 처리하는 입구(UDP 묶음, 타이머)는 그 전체를 처리 하나로 연다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N5·N6·N8, `docs/contracts/SwiftailTunnel.md` 동작 L·B.
extension TailnetNode {
    // MARK: 두 상태 기계 잇기

    /// 엔진의 출력을 처리한다. 엔진을 바꾼 모든 호출 뒤에 부른다.
    ///
    /// - Parameter source: `engine.receive`의 출력이면 그 데이터그램이 온 길. `.cookieReply`를 이 길로 되돌린다.
    func process(_ outputs: [TailnetEngine.Output], repliesTo source: Magicsock.Source? = nil, at now: ContinuousClock.Instant) {
        beginProcessing()
        defer { endProcessing(at: now) }
        for output in outputs {
            switch output {
            case let .datagram(bytes, to: peer):
                process(magicsock?.send(bytes, to: peer, at: now) ?? [], at: now)
            case let .ipPacket(bytes):
                // 엔진은 로컬 응답, 자기 주소로 되돌린 패킷, 피어가 보낸 패킷을 모두 "장치로 쓸 것"으로 낸다.
                deliverToDevice(bytes)
            case let .cookieReply(bytes):
                // 피어를 아직 모르므로 경로 선택(`magicsock.send`)을 거치지 않고 받은 길로 보낸다.
                if let source {
                    process([source.reply(bytes)], at: now)
                }
            case let .discoKeyAdvertised(key, from: peer):
                // 키는 공개 키지만 로그에는 남기지 않는다(magicsock 계약 동작 T6).
                Self.log.debug("TSMP disco 키 광고 받음")
                process(magicsock?.receiveDiscoKeyAdvertisement(key, from: peer, at: now) ?? [], at: now)
            case .dropped:
                break
            }
        }
    }

    /// `Magicsock`의 출력을 처리한다. `Magicsock`을 바꾼 모든 호출 뒤에 부른다.
    func process(_ outputs: [Magicsock.Output], at now: ContinuousClock.Instant) {
        beginProcessing()
        defer { endProcessing(at: now) }
        for output in outputs {
            switch output {
            case let .udp(bytes, to: destination):
                sendUDP(bytes, to: destination)
            case let .derp(bytes, to: peer, region: region):
                sendDERP(bytes, to: peer, region: region)
            case let .wireGuard(bytes, from: source):
                let received = engine?.receive(bytes, from: source.engineSource, at: now) ?? []
                if received.contains(where: \.provesSession) {
                    announce(stateMachine.connected())
                }
                process(received, repliesTo: source, at: now)
            case let .endpointsChanged(endpoints):
                endpointsChanged(endpoints)
            case let .homeRegionChanged(region):
                homeRegionChanged(to: region)
            case let .pathChanged(peer, path):
                let line = pathEventTally.line(for: peer, path: path, downgrade: magicsock?.downgrade(of: peer), at: now)
                Self.log.info("\(line, privacy: .public)")
                if let name = peerDirectory.name(of: peer) {
                    eventQueue.push(.peerPathChanged(fqdn: name, path: path))
                }
            case let .dropped(reason):
                pathEventTally.count(reason)
            }
        }
    }

    // MARK: 처리의 시작과 끝

    /// 처리를 하나 연다. 같은 수의 `endProcessing(at:)`과 짝을 이룬다.
    func beginProcessing() {
        processingDepth += 1
    }

    /// 처리를 닫는다. 가장 바깥 처리면 그동안 쌓인 일을 마무리한다.
    ///
    /// 1. 스택: 대기열의 패킷을 넣고 같은 시각으로 `advance(to:)`한다(`settleNetstack(at:)`). 그 출력의 처리는 안쪽 처리로 돈다.
    /// 2. 모은 UDP 데이터그램을 소켓의 송신 큐에 한꺼번에 넘긴다.
    /// 3. 타이머를 다시 건다. 기한은 모든 상태 기계를 바꾼 뒤 한 번만 계산한다.
    func endProcessing(at now: ContinuousClock.Instant) {
        guard processingDepth == 1 else {
            processingDepth -= 1
            return
        }
        settleNetstack(at: now)
        processingDepth = 0
        flushUDP()
        rearmTimer()
    }

    // MARK: UDP

    /// 데이터그램 하나를 이번 처리의 UDP 송신 묶음에 넣는다. 가장 바깥 처리가 닫힐 때 소켓으로 넘어간다(`flushUDP()`).
    private func sendUDP(_ bytes: [UInt8], to destination: IPEndpoint) {
        guard !blockedUDPPorts.contains(destination.port) else { return }
        outgoingUDP.append((bytes, destination))
    }

    /// 모은 데이터그램을 지금 소켓의 송신 큐에 한꺼번에 넘긴다. `sendto`는 소켓의 직렬 큐가 이 actor 밖에서 한다(터널 계약
    /// 동작 M의 "UDP 송신 큐"). 소켓이 없으면(재결속 중) 버린다. 보내기 실패도 버린다(DERP로 함께 나가거나 WireGuard·disco가
    /// 다시 보낸다). 처리 안에서는 기다리지 않으므로 묶음을 넘기는 사이에 소켓이 바뀌지 않는다.
    // shortcut: 송신 오류(`EHOSTUNREACH`·`EPERM` 등)에 따른 재결속은 하지 않는다(터널 계약 동작 N 6). 필요해지는 시점:
    // 실기기 전환 시험에서 `setDefaultInterface` 없이 소켓이 죽을 때.
    private func flushUDP() {
        guard !outgoingUDP.isEmpty else { return }
        socket?.enqueue(outgoingUDP)
        outgoingUDP.removeAll(keepingCapacity: true)
    }

    // MARK: 타이머

    /// 엔진·`Magicsock`·스택의 다음 기한 가운데 이른 것(netstack 계약 동작 N6). 처리마다 부르므로 배열을 만들지 않는다.
    private var nextDeadline: ContinuousClock.Instant? {
        var earliest = engine?.nextDeadline
        if let deadline = magicsock?.nextDeadline, earliest.map({ deadline < $0 }) ?? true {
            earliest = deadline
        }
        if let deadline = netstack?.stack.nextDeadline, earliest.map({ deadline < $0 }) ?? true {
            earliest = deadline
        }
        return earliest
    }

    /// 다음 기한에 깨어나 엔진·`Magicsock`·스택의 `advance`를 부른다. 기한이 앞당겨지면 다시 계산한다. 취소될 때까지 돈다.
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
            beginProcessing()
            // 키 만료로 엔진이 피어를 바꾸면 주소의 주인도 바뀔 수 있다. 같은 때에 주인 표를 다시 읽는다.
            let recomputesPeers = engine?.recomputesPeers(at: now) ?? false
            process(engine?.advance(to: now) ?? [], at: now)
            if recomputesPeers, let lastNetmap {
                updateAddressOwners(for: lastNetmap)
            }
            process(magicsock?.advance(to: now) ?? [], at: now)
            process(netstack?.stack.advance(to: now) ?? [], at: now)
            endProcessing(at: now)
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
    /// 복호화한 전송 패킷에서만 나오는 출력(올릴 패킷, 필터·해석·TSMP로 버린 것, TSMP disco 키 광고)이면 참이다. 엔진은 핸드셰이크를 마친
    /// 시각을 내지 않으므로 이것으로 상태 기계의 "세션을 맺은 피어가 있음"(동작 B 5)을 잰다.
    // shortcut: Go는 핸드셰이크를 마친 순간(`LastHandshake`)을 본다. 여기서는 그 세션의 첫 전송 패킷(keepalive 제외)을
    // 받을 때라 조금 늦을 수 있다. 홈 DERP 연결이 서면 그보다 먼저 `.running`이 되므로 보통은 차이가 없다. 필요해지는
    // 시점: DERP 없이 직접 경로만 쓰는 tailnet에서 `.running`이 늦는 것이 보일 때(엔진에 세션 사건을 더한다).
    var provesSession: Bool {
        switch self {
        case .ipPacket, .discoKeyAdvertised: true
        case .datagram, .cookieReply: false
        case let .dropped(reason):
            switch reason {
            case .inbound, .malformedPacket, .unsupportedPacket, .consumedControlPacket: true
            case .serviceIPPacket, .noPeerForDestination, .wireGuard: false
            }
        }
    }
}

extension Magicsock.Source {
    /// WireGuard 장치에 넘길 출처. cookie는 `address`에, 속도 제한은 `host`에 묶인다.
    ///
    /// UDP는 Go 표준 bind와 같다: `address`는 `netip.AddrPort`의 이진 표현(주소 ‖ 포트 LE), `host`는 주소다.
    /// DERP는 Tailscale magicsock과 같은 뜻이다: 피어마다 하나로 정하고 지역은 넣지 않는다(Go는 피어별 가짜 주소에
    /// cookie를 묶고 피어의 tailnet 주소로 속도 제한한다, `wgengine/magicsock/endpoint.go`의 `DstToBytes`·`DstIP`).
    /// 여기서는 둘 다 node 공개 키 32바이트다. UDP 값(4·6·16·18바이트)과 길이가 달라 겹치지 않는다.
    var engineSource: TailnetEngine.Source {
        switch self {
        case let .udp(endpoint):
            let address = endpoint.address.bytes
            return TailnetEngine.Source(address: address + [UInt8(endpoint.port & 0xFF), UInt8(endpoint.port >> 8)], host: address)
        case let .derp(peer, _):
            return TailnetEngine.Source(address: peer.rawValue, host: peer.rawValue)
        }
    }

    /// 이 길로 `bytes`를 되돌려 보내는 `Magicsock` 출력: UDP면 그 주소로, DERP면 같은 지역으로 그 피어에게.
    func reply(_ bytes: [UInt8]) -> Magicsock.Output {
        switch self {
        case let .udp(endpoint): .udp(bytes, to: endpoint)
        case let .derp(peer, region): .derp(bytes, to: peer, region: region)
        }
    }
}

/// "피어 N 경로" 로그 줄을 만든다. 실기기 기록에서 경로가 왜, 어느 피어에서 바뀌었는지 가르는 진단이다.
///
/// 줄에는 피어 번호, 경로, 나빠졌으면 그 까닭, 같은 피어의 앞 경로 사건 뒤 시간, 앞 경로 사건(어느 피어든) 뒤 버린
/// disco의 종류별 개수가 들어간다. 예: `피어 2 경로: relayed(7) (신뢰 만료, 앞 사건 뒤 96.5초, 버린 disco: 모르는 키 0,
/// 열리지 않음 0, 경로 규칙 0)`.
/// - 피어 번호는 경로의 첫 사건에 1부터 차례로 붙인다. 피어가 빠지면 기록을 버리고 번호는 다시 쓰지 않는다.
///   공개 저장소에 로그가 실리므로 키·주소·이름·안정 ID는 담지 않는다.
/// - 버린 disco가 모르는 키로 쌓였으면 상대의 새 disco 키를 아직 모른 것이고(netmap이 늦음), 열리지 않음이 쌓였으면
///   상대가 이 노드의 옛 키로 봉한 것이며, 둘 다 없으면 disco는 오갔으나 UDP가 닿지 않은 것이다.
///
/// `docs/contracts/SwiftailMagicsock.md` "직접 경로 지연의 조사"의 "고친 것", "direct가 선 뒤 약 100초에 `relayed`"의 "조사 결과".
struct PathEventTally: Sendable {
    /// 경로 사건을 낸 피어의 번호와 그 피어의 앞 사건 시각.
    private var peers: [NodePublicKey: (number: Int, lastEvent: ContinuousClock.Instant)] = [:]
    private var nextPeerNumber = 1
    private var unknownKey = 0
    private var unopened = 0
    private var misrouted = 0

    /// 빠진 피어의 마지막 경로 사건을 처리한 뒤 기록을 거둬, 오래 실행해도 기록이 쌓이지 않게 한다.
    mutating func retainPeers(_ keys: Set<NodePublicKey>) {
        peers = peers.filter { keys.contains($0.key) }
    }

    /// disco를 버린 까닭이면 센다. 다른 까닭은 세지 않는다.
    mutating func count(_ drop: Magicsock.Drop) {
        switch drop {
        case .unknownDiscoKey: unknownKey += 1
        case .malformedDisco: unopened += 1
        case .misroutedDisco: misrouted += 1
        default: break
        }
    }

    /// 경로 사건 하나의 로그 줄. 그 피어의 사건 시각을 기억하고 버린 disco 개수를 0으로 되돌린다.
    mutating func line(
        for peer: NodePublicKey,
        path: PeerPath?,
        downgrade: PathDowngrade?,
        at now: ContinuousClock.Instant
    ) -> String {
        var details: [String] = []
        if let downgrade {
            details.append(downgrade.logName)
        }
        let number: Int
        if let previous = peers[peer] {
            number = previous.number
            let (seconds, attoseconds) = max(.zero, previous.lastEvent.duration(to: now)).components
            let tenths = seconds * 10 + attoseconds / 100_000_000_000_000_000
            details.append("앞 사건 뒤 \(tenths / 10).\(tenths % 10)초")
        } else {
            number = nextPeerNumber
            nextPeerNumber += 1
            details.append("첫 사건")
        }
        details.append("버린 disco: 모르는 키 \(unknownKey), 열리지 않음 \(unopened), 경로 규칙 \(misrouted)")
        peers[peer] = (number, now)
        (unknownKey, unopened, misrouted) = (0, 0, 0)
        return "피어 \(number) 경로: \(path.logName) (\(details.joined(separator: ", ")))"
    }
}

extension PathDowngrade {
    /// 로그에 남길 한 단어.
    var logName: String {
        switch self {
        case .trustExpired: "신뢰 만료"
        case .candidateRemoved: "후보 지움"
        case .rebind: "재결속"
        case .discoKeyChanged: "disco 키 바뀜"
        case .idle: "유휴"
        case .peerRemoved: "피어 빠짐"
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
