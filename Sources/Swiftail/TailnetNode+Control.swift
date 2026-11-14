import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// 제어 사건을 데이터면과 노드 사건으로 옮긴다.
///
/// - `registered`: 신원 파일에서 node 개인 키를 읽어 엔진을 만든다. 키가 바뀌면 엔진과 DERP 클라이언트를 새로 띄운다.
/// - `netmap`: 홈 DERP 지역을 고르고, 엔진에 적용하고, 홈 지역을 제어 서버에 올리고, 자기 주소를 `running`으로 알린다.
/// - `disconnected`: `reconnecting`을 알린다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` 노드 API 동작 1~4, `docs/protocol-notes/derp-stun.md` 4.8.
extension TailnetNode {
    /// 제어 사건을 끝까지 따라간다. 계속할 수 없는 실패면 그것을 돌려준다.
    func follow(_ control: ControlClient) async -> NodeError? {
        for await event in control.events {
            do throws(ControlError) {
                try await handle(event, from: control)
            } catch {
                return NodeError(error)
            }
        }
        return nil
    }

    private func handle(_ event: ControlClient.Event, from control: ControlClient) async throws(ControlError) {
        switch event {
        case let .loginRequired(url):
            eventContinuation.yield(.loginRequired(url))
        case let .registered(key):
            try adoptNodeKey(key)
        case let .netmap(netmap):
            await apply(netmap, reportingTo: control)
        case .disconnected:
            linkBroke(.control)
        }
    }

    /// 등록을 마친 node 키로 엔진을 준비한다. `ControlClient`는 `registered`를 내기 전에 신원 파일에 키를 저장한다.
    private func adoptNodeKey(_ key: NodePublicKey) throws(ControlError) {
        if let nodeKey, NodePublicKey(nodeKey.publicKey) == key { return }
        guard let privateKey = try identityStore.load()?.nodeKey, NodePublicKey(privateKey.publicKey) == key else {
            throw .storage("등록한 node 키가 신원 파일에 없다")
        }
        nodeKey = privateKey
        // 새 키는 새 WireGuard 신원이다. 이전 세션은 쓸 수 없으므로 엔진을 새로 만든다.
        engine = TailnetEngine(nodeKey: privateKey, now: .now, wallClock: Date())
        if let lastNetmap {
            route(engine?.apply(lastNetmap, homeDERP: home?.regionID ?? 0, at: .now, wallClock: Date()) ?? [])
        }
        rearmTimer()
        derpChanged?.yield()
    }

    func apply(_ netmap: Netmap, reportingTo control: ControlClient) async {
        lastNetmap = netmap
        let previousHome = home
        home = DERPHome.choose(from: netmap.derpMap, keeping: home?.regionID ?? 0)
        if home != previousHome {
            derpChanged?.yield()
        }
        route(engine?.apply(netmap, homeDERP: home?.regionID ?? 0, at: .now, wallClock: Date()) ?? [])

        let addresses = netmap.selfNode.addresses
            .filter { $0.length == $0.address.bytes.count * 8 }
            .map(\.address)
        // 홈이 없으면 DERP 클라이언트도 없으므로 DERP를 끊긴 연결로 세지 않는다. 세면 `running`이 다시 나오지 않는다.
        let derpDropped = home == nil && brokenLinks.remove(.derp) != nil
        let controlRestored = brokenLinks.remove(.control) != nil
        let recovered = (derpDropped || controlRestored) && brokenLinks.isEmpty
        if !addresses.isEmpty, addresses != announcedAddresses || recovered {
            announcedAddresses = addresses
            eventContinuation.yield(.running(addresses: addresses))
        }

        // 홈 지역을 올리지 않으면 Go 피어가 이 노드에게 보낼 DERP 지역을 모른다(노트 derp-stun 4.8 4).
        let preferredDERP = home?.regionID ?? 0
        if preferredDERP != localStatus.netInfo?.preferredDERP ?? 0 {
            localStatus.netInfo = preferredDERP == 0 ? nil : NetInfo(preferredDERP: preferredDERP)
            await control.setLocalStatus(localStatus)
        }
    }

    /// 연결 하나가 끊겼다. 다른 연결이 이미 끊겨 있지 않았다면 `reconnecting`을 알린다. `running` 전에는 알리지 않는다.
    func linkBroke(_ link: Link) {
        guard announcedAddresses != nil else { return }
        if brokenLinks.isEmpty {
            eventContinuation.yield(.reconnecting)
        }
        brokenLinks.insert(link)
    }

    /// 끊겼던 연결이 돌아왔다. 모두 돌아왔으면 `running`을 다시 알린다.
    func linkRestored(_ link: Link) {
        guard brokenLinks.remove(link) != nil, brokenLinks.isEmpty, let addresses = announcedAddresses else { return }
        eventContinuation.yield(.running(addresses: addresses))
    }
}
