import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailEngine
import SwiftailMagicsock

/// 제어 사건을 데이터면, 상태 기계, 터널 설정으로 옮긴다.
///
/// - `loginRequired`: 상태 기계에 넣는다(`.needsLogin(url)`).
/// - `registered`: 신원 파일에서 node 개인 키를 읽어 엔진과 `Magicsock`을 만든다. 키가 바뀌면 둘 다 새로 만들고 DERP 지역
///   연결을 모두 다시 연다(disco 키와 소켓은 그대로). 상태 기계의 로그인 URL을 지운다.
/// - `netmap`: lock 모습이 바뀌었으면 먼저 알리고(`tailnetLockChanged`), 엔진에 적용하고, 피어와 홈 후보 지역을 `Magicsock`에 넣고, DERPMap에서 사라진 지역의 연결을 닫고,
///   (`.inProcess`면) 스택의 자기 주소와 피어 주소의 주인을 고치고, 터널 설정을 산출해 바뀌었으면 내고(동작 E), 상태
///   기계에 넣고, `status`가 바뀌었으면 끝으로 알린다(`statusChanged`).
/// - `disconnected`: 로그만 남긴다. `.running` 뒤 끊겨도 상태는 그대로다(동작 B).
///
/// 계약 `docs/contracts/SwiftailEngine.md` 노드 API 동작 1~4와 "M4에서 바뀌는 것" N2·N3·N5·N6,
/// `docs/contracts/SwiftailTunnel.md` 동작 B·E.
extension TailnetNode {
    /// 제어 사건을 끝까지 따라간다. 계속할 수 없는 실패면 그것을 돌려준다.
    func follow(_ control: ControlClient) async -> NodeError? {
        for await event in control.events {
            do throws(ControlError) {
                try handle(event)
            } catch {
                return NodeError(error)
            }
        }
        return nil
    }

    private func handle(_ event: ControlClient.Event) throws(ControlError) {
        switch event {
        case let .loginRequired(url):
            announce(stateMachine.loginRequired(url))
        case let .registered(key):
            try adoptNodeKey(key)
            Self.log.info("제어: 등록됨")
            announce(stateMachine.registered())
        case let .netmap(netmap):
            if isControlDisconnected {
                isControlDisconnected = false
                Self.log.info("제어: 다시 이어짐")
            }
            apply(netmap)
        case .disconnected:
            isControlDisconnected = true
            Self.log.info("제어: 연결 끊김, 다시 잇는 중")
        }
    }

    /// 등록을 마친 node 키로 데이터면을 준비한다. `ControlClient`는 `registered`를 내기 전에 신원 파일에 키를 저장한다.
    private func adoptNodeKey(_ key: NodePublicKey) throws(ControlError) {
        if let nodeKey, NodePublicKey(nodeKey.publicKey) == key { return }
        guard let privateKey = try identityStore.load()?.nodeKey, NodePublicKey(privateKey.publicKey) == key else {
            throw .storage("등록한 node 키가 신원 파일에 없다")
        }
        // 제어 사건은 `run()` 안에서만 온다.
        guard isRunning else { return }
        nodeKey = privateKey
        // 새 키는 새 WireGuard 신원이다. 이전 세션과 경로 상태, 옛 키로 연 DERP 연결은 쓸 수 없으므로 모두 새로 만든다.
        let now = ContinuousClock.now
        // 옛 `Magicsock`을 버리기 전에 피어를 비워, 앱에 알렸던 경로를 nil로 거둔다. 새 `Magicsock`의 피어는 유휴(nil)로
        // 시작하고 사건을 내지 않으므로, 이렇게 하지 않으면 앱의 마지막 사건이 옛 경로로 남는다.
        process(magicsock?.setPeers([], at: now) ?? [], at: now)
        closeAllDERPLinks()
        engine = TailnetEngine(nodeKey: privateKey, discoKey: DiscoPublicKey(discoKey.publicKey), now: now, wallClock: Date())
        magicsock = Magicsock(
            discoKey: discoKey,
            nodeKey: key,
            // 재결속 중이라 소켓이 없으면 0이다. 새 소켓을 열면 `rebind`가 포트를 알린다.
            localPort: socket?.localPort ?? 0,
            localAddresses: interfaceAddresses.regular,
            loopbackAddresses: interfaceAddresses.loopback,
            now: now
        )
        // 새 Magicsock은 홈이 없다. 다시 정해지면 그 지역에 연결하고 올린다.
        homeRegion = 0
        if let lastNetmap {
            configureDataPlane(lastNetmap)
        }
        rearmTimer()
    }

    func apply(_ netmap: Netmap) {
        let previousLock = lastNetmap?.tailnetLock ?? TailnetLockStatus()
        // `status`를 먼저 고치고 사건을 낸다. lock 사건은 이 netmap의 다른 사건보다 앞선다(F2 1).
        lastNetmap = netmap
        if netmap.tailnetLock != previousLock {
            eventQueue.push(.tailnetLockChanged(netmap.tailnetLock))
        }
        configureDataPlane(netmap)
        publishSettings(for: netmap)
        announce(stateMachine.receivedNetmap(machineAuthorized: netmap.selfNode.machineAuthorized))
        // 상태가 그대로여도 이름·주소·피어 수·설정이 바뀌었을 수 있다. 이 netmap의 사건 가운데 맨 뒤다.
        announceStatusIfChanged()
        publishCertificateFacts()
    }

    /// 터널 설정을 산출해 마지막으로 낸 것과 다르면 낸다(동작 E). 자기 주소가 없으면 내지 않는다.
    private func publishSettings(for netmap: Netmap) {
        let settings = TunnelNetworkSettings(netmap: netmap, mtu: device.mtu, at: Date())
        guard let settings = settingsPublisher.publish(settings) else { return }
        Self.log.info("""
            터널 설정 산출: 주소 \(settings.addresses.count, privacy: .public)개, 경로 \(settings.routes.count, privacy: .public)개, \
            DNS 서버 \(settings.dnsServers.count, privacy: .public)개, match 도메인 \(settings.dnsMatchDomains.count, privacy: .public)개
            """)
        settingsContinuation.yield(settings)
    }

    /// netmap을 엔진과 `Magicsock`에 넣는다. DERPMap에서 사라졌거나 서버 정의가 바뀐 지역의 연결을 닫는다. 끝으로 엔진이
    /// 피어와 함께 만든 주인 표를 받아 쥐고 스택에 넘긴다(`updateAddressOwners(for:)`).
    ///
    /// 피어가 빠지면 `Magicsock`이 그 피어의 경로 사건(nil)을 낸다. 그 사건에는 표를 바꾸기 전의 이름을 쓴다(N6).
    private func configureDataPlane(_ netmap: Netmap) {
        let now = ContinuousClock.now
        let wallClock = Date()
        let regions = netmap.derpMap?.regions ?? [:]
        // 연결은 만들 때의 서버 목록으로만 다시 붙으므로, 정의가 바뀐 지역은 닫아야 새 서버로 간다(Go `derp.go`의
        // `derp-region-redefined`). 홈은 곧바로 다시 열고, 나머지는 다음에 보낼 때 열린다.
        for (region, link) in derpLinks where DERPServer.servers(of: regions[region]) != link.servers {
            closeDERPLink(to: region)
            if region == homeRegion {
                openDERPLink(to: region)
            }
        }

        process(engine?.apply(netmap, at: now, wallClock: wallClock) ?? [], at: now)
        let peers = EnginePeer.peers(in: netmap, at: wallClock)
        let directory = PeerDirectory(peers: peers)
        peerDirectory = directory.keepingNames(of: peerDirectory)
        // 순서는 node ID 오름차순이다. disco 키의 주인을 정한다(magicsock 계약 B1).
        let sockPeers = peers.map {
            Magicsock.Peer(key: $0.key, discoKey: $0.discoKey, homeDERP: $0.homeDERP, endpoints: $0.endpoints)
        }
        process(magicsock?.setPeers(sockPeers, at: now) ?? [], at: now)
        peerDirectory = directory
        pathEventTally.retainPeers(Set(peers.map(\.key)))
        // shortcut: 키 만료로 엔진이 `advance`에서 내린 피어는 다음 netmap까지 `Magicsock`에 남는다. 엔진이 그 피어에게
        // 데이터그램을 내지 않으므로 heartbeat는 45초 뒤 멈추고, 받은 WireGuard는 장치가 버린다(계약 N5).
        process(magicsock?.setRegions(Magicsock.Region.homeCandidates(in: netmap.derpMap), at: now) ?? [], at: now)
        updateAddressOwners(for: netmap)
    }

    // MARK: 제어 서버에 올리기 (N4)

    /// 자기 엔드포인트가 바뀌었다. 상태를 올린다.
    func endpointsChanged(_ endpoints: [Magicsock.Endpoint]) {
        localStatus.setEndpoints(endpoints)
        statusUploadContinuation.yield(localStatus)
    }

    /// 홈 지역이 바뀌었다. 올리고(올리지 않으면 Go 피어가 이 노드에게 보낼 DERP 지역을 모른다, 노트 derp-stun 4.8 4)
    /// 그 지역에 연결한다. 옛 홈 연결은 닫지 않는다(아직 그리로 보내는 피어가 있을 수 있다, magicsock 계약 E6).
    func homeRegionChanged(to region: Int64) {
        homeRegion = region
        localStatus.netInfo = NetInfo(preferredDERP: region)
        statusUploadContinuation.yield(localStatus)
        Self.log.info("홈 DERP 지역: \(region, privacy: .public)")
        openDERPLink(to: region)
        if connectedDERPRegions.contains(region) {
            announce(stateMachine.connected())
        }
    }
}
