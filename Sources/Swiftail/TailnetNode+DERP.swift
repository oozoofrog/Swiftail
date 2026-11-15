import Synchronization
import SwiftailBase
import SwiftailDERP
import SwiftailMagicsock

/// DERP 지역 연결의 수명. 연결은 지역마다 하나이고, 여닫는 일은 모두 actor 메서드(기다리지 않는다)가 한다.
///
/// - **열기**(`openDERPLink`): 홈 지역이 정해졌을 때(`isPreferred: true`), 또는 `Magicsock`이 아직 연결이 없는 지역으로
///   보내려 할 때(`isPreferred: false`) 연다. 클라이언트와 우편함을 만들어 표에 넣고 `maintainDERP()`에 넘긴다.
///   우편함은 클라이언트가 돌기 전부터 받으므로 첫 데이터그램도 잃지 않는다. 연결은 지금 기본 인터페이스에 묶는다
///   (서버가 루프백이면 `DERPClient`가 묶지 않는다).
/// - **돌리기**(`maintainDERP`): 넘겨받은 연결마다 자식 묶음(`serve`) 하나를 띄운다. `run()`이 취소되면 모두 멈춘다.
/// - **닫기**(`closeDERPLink`): 표에서 빼고 우편함을 닫는다. 우편함이 끝나면 그 연결의 묶음이 스스로 접힌다.
///   DERPMap에서 지역이 사라지거나 서버 정의가 바뀌거나 node 키나 기본 인터페이스가 바뀌면 닫는다. 홈이 바뀌어도 옛 홈은
///   닫지 않는다(magicsock 계약 E6).
///
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N3·N7, `docs/contracts/SwiftailTunnel.md` 동작 N 3·M.
// shortcut: 홈이 아닌 연결의 60초 미사용 정리(DERP 노트 4.9 5)는 하지 않는다. 열린 연결 수는 DERPMap 지역 수로 묶인다.
// 필요해지는 시점: M5 메모리 측정. 홈이 바뀌어도 이미 열린 연결의 NotePreferred는 다시 보내지 않는다(서버 통계용).
extension TailnetNode {
    /// DERP 지역 하나의 연결: 클라이언트와 그리로 보낼 데이터그램의 우편함.
    struct DERPLink: Sendable {
        let region: Int64
        /// 이 연결을 만들 때의 서버 목록. DERPMap의 정의가 이것과 달라지면 연결을 닫는다.
        let servers: [DERPServer]
        let client: DERPClient
        let outbox: DERPOutbox
    }

    /// 엔진이 낸, DERP로 보낼 WireGuard 메시지나 disco 메시지.
    struct DERPDatagram: Sendable {
        var bytes: [UInt8]
        var peer: NodePublicKey
    }

    /// 지역 연결로 아직 넘기지 못한 데이터그램. 연결의 송신 자식이 하나씩 꺼내 간다.
    ///
    /// 가장 새 것 256개까지, 그리고 바이트 합 1MiB까지만 쥐고 넘치면 오래된 것부터 버린다(계약 동작 M). `AsyncStream`의
    /// `bufferingNewest`는 개수로만 묶으므로 버퍼를 여기서 쥔다(`DatagramSocket`의 받은 큐와 같은 모양). 꺼내는 쪽은 하나다.
    final class DERPOutbox: Sendable {
        private struct State {
            var datagrams: [DERPDatagram] = []
            /// `datagrams`의 바이트 합.
            var bytes = 0
            /// 데이터그램을 기다리는 쪽.
            var waiter: CheckedContinuation<DERPDatagram?, Never>?
            var isClosed = false
        }

        private let state = Mutex(State())

        /// 넣는다. 기다리는 쪽이 있으면 곧바로 넘긴다. 닫은 뒤에는 버린다.
        func push(_ datagram: DERPDatagram) {
            let waiter: CheckedContinuation<DERPDatagram?, Never>? = state.withLock { state in
                guard !state.isClosed else { return nil }
                // 기다리는 쪽이 있으면 큐는 비어 있다.
                if let waiter = state.waiter.take() { return waiter }
                if state.datagrams.count >= TailnetNode.outboundDatagramLimit {
                    state.bytes -= state.datagrams.removeFirst().bytes.count
                }
                // 새 것이 들어갈 자리가 날 때까지 오래된 것부터 버린다. 하나가 한도보다 커도 비면 멈춘다.
                while state.bytes + datagram.bytes.count > TailnetNode.outboundByteLimit, !state.datagrams.isEmpty {
                    state.bytes -= state.datagrams.removeFirst().bytes.count
                }
                state.datagrams.append(datagram)
                state.bytes += datagram.bytes.count
                return nil
            }
            waiter?.resume(returning: datagram)
        }

        /// 닫는다. 남은 것은 버리고, 기다리는 쪽은 nil을 받는다.
        func close() {
            let waiter = state.withLock { state in
                state.isClosed = true
                state.datagrams = []
                state.bytes = 0
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// 다음 데이터그램. 없으면 올 때까지 기다린다. 닫혔거나 기다리는 Task가 취소되면 nil.
        func next() async -> DERPDatagram? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<DERPDatagram?, Never>) in
                    let ready: DERPDatagram?? = state.withLock { state in
                        if !state.datagrams.isEmpty {
                            let datagram = state.datagrams.removeFirst()
                            state.bytes -= datagram.bytes.count
                            return .some(datagram)
                        }
                        // 이미 취소되었으면 취소 처리기가 먼저 돌았으므로 기다리지 않는다. 둘째로 기다리는 쪽도 기다리게 하지 않는다.
                        if state.isClosed || Task.isCancelled || state.waiter != nil { return .some(nil) }
                        state.waiter = continuation
                        return .none
                    }
                    if let ready { continuation.resume(returning: ready) }
                }
            } onCancel: {
                state.withLock { $0.waiter.take() }?.resume(returning: nil)
            }
        }

        /// 쥐고 있는 데이터그램 수와 바이트 합. 시험용.
        var backlog: (count: Int, bytes: Int) {
            state.withLock { ($0.datagrams.count, $0.bytes) }
        }
    }

    // MARK: 여닫기

    /// 지역 `region`의 연결을 연다. 이미 열려 있으면 그것을 돌려준다. node 키가 없거나 DERPMap에 그 지역의 쓸 수 있는
    /// 서버가 없으면 nil.
    @discardableResult
    func openDERPLink(to region: Int64) -> DERPLink? {
        if let link = derpLinks[region] { return link }
        let servers = DERPServer.servers(of: lastNetmap?.derpMap?.regions?[region])
        guard let nodeKey, !servers.isEmpty else { return nil }
        let link = DERPLink(
            region: region,
            servers: servers,
            client: DERPClient(servers: servers, privateKey: nodeKey, isPreferred: region == homeRegion, interface: defaultInterface),
            outbox: DERPOutbox()
        )
        derpLinks[region] = link
        openedDERPLinkContinuation.yield(link)
        return link
    }

    /// 지역 `region`의 연결을 닫는다. 우편함이 닫히면 그 연결의 묶음이 접힌다. 아직 보내지 못한 데이터그램은 버려진다.
    func closeDERPLink(to region: Int64) {
        connectedDERPRegions.remove(region)
        derpLinks.removeValue(forKey: region)?.outbox.close()
    }

    func closeAllDERPLinks() {
        for region in derpLinks.keys {
            closeDERPLink(to: region)
        }
    }

    /// `Magicsock`이 지역 `region`으로 보내라고 한 데이터그램. 연결이 없으면 연다(DERPMap의 어느 지역이든). 열 수 없으면
    /// 버린다.
    func sendDERP(_ bytes: [UInt8], to peer: NodePublicKey, region: Int64) {
        openDERPLink(to: region)?.outbox.push(DERPDatagram(bytes: bytes, peer: peer))
    }

    // MARK: 돌리기

    /// 열린 연결마다 그 연결의 묶음을 자식으로 띄운다. 취소될 때까지 돈다.
    func maintainDERP() async {
        await withDiscardingTaskGroup { group in
            for await link in openedDERPLinks {
                group.addTask { await self.serve(link) }
            }
        }
    }

    /// 연결 하나의 수명. 우편함이 닫히거나(`closeDERPLink`) 취소되면 클라이언트와 그 곁의 일을 함께 접는다.
    private func serve(_ link: DERPLink) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await link.client.run() }
            group.addTask {
                for await event in link.client.events {
                    await self.handle(event, from: link)
                }
            }
            group.addTask {
                while let datagram = await link.outbox.next() {
                    await link.client.send(datagram.bytes, to: datagram.peer)
                }
            }
            await group.next()
            group.cancelAll()
        }
    }

    private func handle(_ event: DERPClient.Event, from link: DERPLink) {
        // 닫은 연결이 접히는 동안 낸 연결 사건은 지금 상태와 무관하다.
        let isCurrent = derpLinks[link.region]?.client === link.client
        switch event {
        case let .packet(bytes, from: peer):
            let now = ContinuousClock.now
            process(magicsock?.receiveDERP(bytes, from: peer, region: link.region, at: now) ?? [], at: now)
        case .connected:
            guard isCurrent else { return }
            Self.log.info("DERP 지역 \(link.region, privacy: .public): 연결됨")
            connectedDERPRegions.insert(link.region)
            if link.region == homeRegion { announce(stateMachine.connected()) }
        case .disconnected:
            guard isCurrent else { return }
            // `.running` 뒤 끊겨도 상태는 그대로다(동작 B). 클라이언트가 물러났다가 다시 잇는다.
            Self.log.info("DERP 지역 \(link.region, privacy: .public): 연결 끊김, 다시 잇는 중")
            connectedDERPRegions.remove(link.region)
        case let .attemptFailed(failure, consecutiveFailures):
            // 물러남의 상한이 5초라 망이 없는 동안 실패가 끝없이 이어진다. 연달아 실패한 첫 번째와 그 뒤 10번째마다만 적는다.
            guard isCurrent, consecutiveFailures == 1 || consecutiveFailures.isMultiple(of: 10) else { return }
            Self.log.info(
                "DERP 지역 \(link.region, privacy: .public): 연결 실패(\(String(describing: failure), privacy: .public)), 연달아 \(consecutiveFailures, privacy: .public)번째"
            )
        case .peerGone:
            // shortcut: 역방향 DERP 지역을 쓰지 않으므로 지울 것이 없다(magicsock 계약 D3).
            break
        }
    }
}
