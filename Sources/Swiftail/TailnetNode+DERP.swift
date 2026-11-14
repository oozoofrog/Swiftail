import SwiftailBase
import SwiftailDERP
import SwiftailMagicsock

/// DERP 지역 연결의 수명. 연결은 지역마다 하나이고, 여닫는 일은 모두 actor 메서드(기다리지 않는다)가 한다.
///
/// - **열기**(`openDERPLink`): 홈 지역이 정해졌을 때(`isPreferred: true`), 또는 `Magicsock`이 아직 연결이 없는 지역으로
///   보내려 할 때(`isPreferred: false`) 연다. 클라이언트와 보낼 통로를 만들어 표에 넣고 `maintainDERP()`에 넘긴다.
///   통로는 클라이언트가 돌기 전부터 받으므로 첫 데이터그램도 잃지 않는다.
/// - **돌리기**(`maintainDERP`): 넘겨받은 연결마다 자식 묶음(`serve`) 하나를 띄운다. `run()`이 취소되면 모두 멈춘다.
/// - **닫기**(`closeDERPLink`): 표에서 빼고 보낼 통로를 닫는다. 통로가 끝나면 그 연결의 묶음이 스스로 접힌다.
///   DERPMap에서 지역이 사라지거나 node 키가 바뀌면 닫는다. 홈이 바뀌어도 옛 홈은 닫지 않는다(magicsock 계약 E6).
///
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N3·N7.
// shortcut: 홈이 아닌 연결의 60초 미사용 정리(DERP 노트 4.9 5)는 하지 않는다. 열린 연결 수는 DERPMap 지역 수로 묶인다.
// 필요해지는 시점: M5 메모리 측정. 홈이 바뀌어도 이미 열린 연결의 NotePreferred는 다시 보내지 않는다(서버 통계용).
extension TailnetNode {
    /// DERP 지역 하나의 연결: 클라이언트와 그리로 보낼 데이터그램의 통로.
    struct DERPLink: Sendable {
        /// 엔진이 낸, DERP로 보낼 WireGuard 메시지나 disco 메시지.
        struct Datagram: Sendable {
            var bytes: [UInt8]
            var peer: NodePublicKey
        }

        let region: Int64
        let client: DERPClient
        let outbound: AsyncStream<Datagram>
        let outboundContinuation: AsyncStream<Datagram>.Continuation
    }

    // MARK: 여닫기

    /// 지역 `region`의 연결을 연다. 이미 열려 있으면 그것을 돌려준다. node 키가 없거나 DERPMap에 그 지역의 쓸 수 있는
    /// 서버가 없으면 nil.
    @discardableResult
    func openDERPLink(to region: Int64) -> DERPLink? {
        if let link = derpLinks[region] { return link }
        guard let nodeKey,
              let servers = lastNetmap?.derpMap?.regions?[region]?.nodes.compactMap(DERPServer.init),
              !servers.isEmpty
        else { return nil }
        let (outbound, continuation) = AsyncStream.makeStream(
            of: DERPLink.Datagram.self, bufferingPolicy: .bufferingNewest(Self.outboundDatagramLimit)
        )
        let link = DERPLink(
            region: region,
            client: DERPClient(servers: servers, privateKey: nodeKey, isPreferred: region == homeRegion),
            outbound: outbound,
            outboundContinuation: continuation
        )
        derpLinks[region] = link
        openedDERPLinkContinuation.yield(link)
        return link
    }

    /// 지역 `region`의 연결을 닫는다. 그 연결의 묶음이 남은 데이터그램을 넘긴 뒤 접힌다.
    func closeDERPLink(to region: Int64) {
        connectedDERPRegions.remove(region)
        derpLinks.removeValue(forKey: region)?.outboundContinuation.finish()
    }

    func closeAllDERPLinks() {
        for region in derpLinks.keys {
            closeDERPLink(to: region)
        }
    }

    /// `Magicsock`이 지역 `region`으로 보내라고 한 데이터그램. 연결이 없으면 연다(DERPMap의 어느 지역이든). 열 수 없으면
    /// 버린다.
    func sendDERP(_ bytes: [UInt8], to peer: NodePublicKey, region: Int64) {
        openDERPLink(to: region)?.outboundContinuation.yield(DERPLink.Datagram(bytes: bytes, peer: peer))
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

    /// 연결 하나의 수명. 보낼 통로가 닫히거나(`closeDERPLink`) 취소되면 클라이언트와 그 곁의 일을 함께 접는다.
    private func serve(_ link: DERPLink) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await link.client.run() }
            group.addTask {
                for await event in link.client.events {
                    await self.handle(event, from: link)
                }
            }
            group.addTask {
                for await datagram in link.outbound {
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
            connectedDERPRegions.insert(link.region)
            if link.region == homeRegion { linkRestored(.derp) }
        case .disconnected:
            guard isCurrent else { return }
            connectedDERPRegions.remove(link.region)
            // `reconnecting`은 홈 지역 연결의 끊김만 알린다(계약 N3).
            if link.region == homeRegion { linkBroke(.derp) }
        case .peerGone:
            // shortcut: 역방향 DERP 지역을 쓰지 않으므로 지울 것이 없다(magicsock 계약 D3).
            break
        }
    }
}
