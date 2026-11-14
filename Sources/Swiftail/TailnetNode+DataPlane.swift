import Foundation
import SwiftailBase
import SwiftailEngine
import SwiftailIO
import SwiftailMagicsock

/// 데이터면의 흐름: 엔진과 `Magicsock`의 출력을 서로에게 넘기고 입출력으로 내보낸다. UDP 읽기와 타이머도 여기 있다.
///
/// ```
/// send(ipPacket) ─► engine.send ─ .datagram(to: 피어) ─► magicsock.send ─┬ .udp ─► 소켓
///                                                                        └ .derp ─► 그 지역 연결
/// 소켓 ─► magicsock.receiveUDP ─┐
/// DERP ─► magicsock.receiveDERP ┴ .wireGuard ─► engine.receive ─ .ipPacket ─► inboundPackets
///                                                              └ .datagram(핸드셰이크 응답 등) ─► magicsock.send …
/// ```
///
/// 사건 하나는 `process`로 시작해 두 상태 기계 사이의 주고받기를 `await` 없이 끝까지 돈다. 입출력은 기다리지 않는
/// 통로(소켓 `send`, 지역 연결의 통로, 사건 흐름)에 넣기만 한다. 출력 목록은 받은 순서대로 처리한다(`Magicsock`의 호출 규칙).
/// 한 사건 안의 호출은 모두 같은 시각 `now`를 쓴다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N5·N6·N8.
extension TailnetNode {
    // MARK: 두 상태 기계 잇기

    /// 엔진의 출력을 처리한다. 엔진을 바꾼 모든 호출 뒤에 부른다.
    func process(_ outputs: [TailnetEngine.Output], at now: ContinuousClock.Instant) {
        for output in outputs {
            switch output {
            case let .datagram(bytes, to: peer):
                process(magicsock?.send(bytes, to: peer, at: now) ?? [], at: now)
            case let .ipPacket(bytes):
                inboundContinuation.yield(bytes)
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
                process(engine?.receive(bytes, at: now) ?? [], at: now)
            case let .endpointsChanged(endpoints):
                endpointsChanged(endpoints)
            case let .homeRegionChanged(region):
                homeRegionChanged(to: region)
            case let .pathChanged(peer, path):
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

    /// 소켓의 데이터그램을 `Magicsock`에 넣는다. 소켓이 닫히거나 취소될 때까지 돈다.
    func receiveUDP(from socket: DatagramSocket) async {
        for await (bytes, source) in socket.datagrams {
            guard !blockedUDPPorts.contains(source.port) else { continue }
            let now = ContinuousClock.now
            process(magicsock?.receiveUDP(bytes, from: source, at: now) ?? [], at: now)
        }
    }

    /// 데이터그램 하나를 소켓으로 보낸다. 실패는 버린다(DERP로 함께 나가거나 WireGuard·disco가 다시 보낸다).
    // shortcut: 송신 오류(`EHOSTUNREACH`·`EPERM` 등)에 따른 재결속은 하지 않는다(magicsock 계약 제외 표). 필요해지는 시점: M5.
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
