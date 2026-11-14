import Foundation
import SwiftailBase
import SwiftailDERP
import SwiftailEngine

/// 데이터면의 입출력: 홈 지역 DERP 클라이언트의 수명, 엔진 출력의 배달, 엔진 타이머.
///
/// 두 자식(`maintainDERP`, `runTimer`)은 같은 모양으로 돈다. 바뀜 신호를 받을 흐름을 새로 만들어 통로를 actor에 걸고,
/// 지금 상태로 할 일을 하다가 신호가 오면 그 일을 취소하고 다시 계산한다. 신호 흐름을 매번 새로 만드는 까닭은 경쟁에서
/// 진 쪽을 취소하면 그 흐름이 끝나기 때문이다. 통로를 거는 일과 상태를 읽는 일 사이에 `await`가 없으므로 그 사이의
/// 바뀜을 놓치지 않는다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` 노드 API 동작 3·5·6.
extension TailnetNode {
    // MARK: DERP

    /// 홈 지역과 node 키가 정해져 있는 동안 그 지역에 DERP 클라이언트 하나를 띄워 둔다. 둘 중 하나가 바뀌면
    /// 지금 클라이언트를 접고 새로 띄운다. 취소될 때까지 돈다.
    func maintainDERP() async {
        while !Task.isCancelled {
            let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            derpChanged = continuation
            if let home, let nodeKey {
                let client = DERPClient(servers: home.servers, privateKey: nodeKey, isPreferred: true)
                await serve(client, until: changes)
            } else {
                for await _ in changes { break }
            }
        }
        derpChanged = nil
    }

    /// DERP 클라이언트 하나의 수명. `changes`에 신호가 오거나 취소되면 클라이언트와 그 곁의 일을 함께 접는다.
    private func serve(_ client: DERPClient, until changes: AsyncStream<Void>) async {
        let (outbound, continuation) = AsyncStream.makeStream(
            of: OutboundDatagram.self, bufferingPolicy: .bufferingNewest(Self.outboundDatagramLimit)
        )
        derpOutbound = continuation
        defer {
            continuation.finish()
            derpOutbound = nil
        }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await client.run() }
            group.addTask {
                for await event in client.events {
                    await self.handle(event)
                }
            }
            group.addTask {
                for await datagram in outbound {
                    await client.send(datagram.bytes, to: datagram.peer)
                }
            }
            group.addTask {
                for await _ in changes { return }
            }
            await group.next()
            group.cancelAll()
        }
    }

    private func handle(_ event: DERPClient.Event) {
        switch event {
        case let .packet(bytes, from: peer):
            route(engine?.receive(bytes, from: peer, at: .now) ?? [])
        case .connected:
            linkRestored(.derp)
        case .disconnected:
            // 다시 띄우려고 접은 클라이언트의 끊김은 알리지 않는다.
            if !Task.isCancelled { linkBroke(.derp) }
        case .peerGone:
            // shortcut: 역방향 경로(피어가 보내온 지역)를 쓰지 않으므로 지울 것이 없다. 다중 지역은 M4다.
            break
        }
    }

    // MARK: 엔진 출력

    /// 엔진의 출력을 내보낸다. 엔진을 바꾼 모든 호출 뒤에 부른다(다음 기한이 바뀌었을 수 있다).
    func route(_ outputs: [TailnetEngine.Output]) {
        for output in outputs {
            switch output {
            case let .datagram(bytes, to: peer, derpRegion: _):
                // 엔진은 우리 홈 지역에 있는 피어에게만 데이터그램을 낸다(M3). 그러니 모두 홈 지역 클라이언트로 간다.
                derpOutbound?.yield(OutboundDatagram(bytes: bytes, peer: peer))
            case let .ipPacket(bytes):
                inboundContinuation.yield(bytes)
            case .dropped:
                break
            }
        }
        rearmTimer()
    }

    // MARK: 타이머

    /// 엔진의 다음 기한에 깨어나 `advance`를 부른다. 기한이 앞당겨지면 다시 계산한다. 취소될 때까지 돈다.
    func runTimer() async {
        while !Task.isCancelled {
            let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            timerChanged = continuation
            let deadline = engine?.nextDeadline
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
            route(engine?.advance(to: .now) ?? [])
        }
        timerChanged = nil
    }

    /// 엔진의 다음 기한이 타이머가 잠든 시각보다 이르면 타이머를 깨운다. 늦어진 것은 타이머가 깨어나 다시 계산한다.
    func rearmTimer() {
        guard let next = engine?.nextDeadline else { return }
        if let armedDeadline, armedDeadline <= next { return }
        timerChanged?.yield()
    }
}
