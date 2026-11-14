import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailWireGuard

/// 한 노드의 데이터면: netmap, WireGuard, 패킷 필터를 묶은 상태 기계.
///
/// 입출력이 없다. 소켓·시계·actor를 갖지 않고, 시각을 인자로 받아 "피어에게 보낼 WireGuard 데이터그램"과
/// "위로 올릴 IP 패킷"을 돌려준다. 모든 진입점은 던지지 않는다. 버린 것은 `.dropped`로 알린다.
///
/// 엔진은 경로를 모른다. 데이터그램을 UDP로 보낼지 어느 DERP 지역으로 보낼지는 부르는 쪽(`Magicsock`)이 고르고,
/// 받는 데이터그램도 `Magicsock`이 WireGuard로 분류한 것만 온다(WireGuard 장치가 주소를 모르는 것과 같은 원칙이다).
/// 지원하지 않는 패킷과 피어는 닫힌 쪽으로 처리한다.
///
/// 이 파일은 상태와 netmap 적용, 타이머를 담는다. 패킷의 송수신은 `TailnetEngine+Packets.swift`,
/// 서비스 IP와 자기 주소로 가는 패킷의 로컬 처리는 `TailnetEngine+LocalDelivery.swift`에 있다.
/// `docs/protocol-notes/netmap-engine.md` 4.2·6.1, `docs/contracts/SwiftailEngine.md` 동작 3·7과 "M4에서 바뀌는 것",
/// `docs/contracts/SwiftailTunnel.md` 동작 D·L.
public struct TailnetEngine: Sendable {
    /// 상태 기계가 내놓는 일.
    public enum Output: Sendable, Equatable {
        /// 피어에게 보낼 WireGuard 메시지. 경로는 부르는 쪽(`Magicsock`)이 고른다.
        case datagram([UInt8], to: NodePublicKey)
        /// 필터를 통과해 위로 올릴 IP 패킷.
        case ipPacket([UInt8])
        /// 버린 패킷. 진단과 시험용이다.
        case dropped(Drop)
        /// 방금 `receive`한 데이터그램의 출처로 그 길 그대로 되돌릴 WireGuard cookie reply. 보낸 피어를 아직 모르므로
        /// 피어 경로 선택을 거치지 않는다. `receive`의 출력에만 나온다.
        case cookieReply([UInt8])
    }

    /// 받은 데이터그램이 온 곳. 부르는 쪽이 경로(UDP 주소, DERP 보낸 쪽)에서 만든 불투명한 값이다. 엔진은 WireGuard
    /// 장치에 넘기기만 한다(부하 상태의 cookie와 출처별 속도 제한).
    public typealias Source = WireGuardDevice.Source

    /// 버린 까닭.
    public enum Drop: Sendable, Equatable {
        /// 받은 패킷을 필터가 버렸다.
        case inbound(PacketFilter.DropReason)
        /// IP 패킷으로 해석할 수 없다.
        case malformedPacket
        /// 조각, IPv6 확장 헤더.
        case unsupportedPacket
        /// TSMP. 엔진이 소비하고 위로 올리지 않는다.
        case consumedControlPacket
        /// 서비스 IP로 간 패킷 가운데 노드가 답하지 않는 것(UDP 53·ICMP echo·TCP 밖, 답이 없는 RST, 형식이 틀린 UDP).
        /// 응답도 ICMP unreachable도 보내지 않는다.
        case serviceIPPacket
        /// 목적지 주소를 가진 피어가 없다.
        case noPeerForDestination
        /// WireGuard가 받거나 보내지 못했다.
        case wireGuard(WireGuardError)
    }

    /// 키 만료를 다시 볼 때까지의 최대 간격. 아주 먼 만료 시각을 단조 시각으로 바꾸다 넘치지 않게 한다.
    private static let maximumExpiryCheckInterval = Duration.seconds(24 * 60 * 60)

    /// node 개인 키와 WireGuard 세션을 쥔다. `customMirror`가 감춘다.
    var device: WireGuardDevice
    var filter = PacketFilter.allowNone
    /// 데이터면에 올린 피어. 키 → 피어.
    var peers: [NodePublicKey: EnginePeer] = [:]
    /// 피어의 한 주소짜리 `addresses` → 그 피어. 보낼 피어를 고른다.
    var peerByAddress: [IPAddress: NodePublicKey] = [:]
    /// 마지막으로 적용한 netmap. 키 만료 시각에 피어를 다시 계산할 때 쓴다.
    private var netmap: Netmap?
    /// 다음으로 키가 만료되는 노드(피어 또는 자기)가 생기는 시각.
    private var keyExpiryDeadline: ContinuousClock.Instant?
    /// 서비스 IP의 UDP 53 질의에 답하는 응답기. netmap이 없거나 자기 키가 만료되면 비어 있다(모든 이름이 SERVFAIL).
    var resolver = MagicDNSResolver(netmap: nil, localZones: [])
    /// 자기 tailnet 주소(한 주소짜리 접두만). 이 주소로 가는 패킷은 장치로 되돌린다.
    var localAddresses: Set<IPAddress> = []
    /// 단조 시각을 벽시계로 바꾸는 기준점: `clockAnchor` 시점의 벽시계는 `wallClockAnchor`다.
    private var clockAnchor: ContinuousClock.Instant
    private var wallClockAnchor: Date

    /// - Parameters:
    ///   - nodeKey: 이 노드의 node 개인 키. WireGuard 정적 키다.
    ///   - now: 지금의 단조 시각.
    ///   - wallClock: `now` 시점의 벽시계 시각.
    public init(nodeKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date) {
        device = WireGuardDevice(privateKey: nodeKey, now: now, wallClock: wallClock)
        clockAnchor = now
        wallClockAnchor = wallClock
    }

    /// netmap을 적용한다: 피어를 더하고 빼고, 필터를 바꾸고, MagicDNS 응답기를 새 netmap으로 다시 만든다. 나가야 할 것이
    /// 있으면 돌려준다.
    ///
    /// 올릴 수 있는 피어는 모두 미리 WireGuard에 올린다(Go의 지연 생성은 하지 않는다). 사라졌거나 올릴 수
    /// 없게 된 키는 내린다. 같은 키의 AllowedIPs가 바뀌어도 세션은 이어진다. 필터는 규칙만 바꾸고 UDP 흐름
    /// 기록은 잇는다. 피어를 더하고 빼는 일은 메시지를 만들지 않으므로 지금은 늘 빈 목록이다.
    ///
    /// - Parameter wallClock: `now` 시점의 벽시계 시각. 피어와 자기 노드의 키 만료를 이것으로 판단한다.
    public mutating func apply(_ netmap: Netmap, at now: ContinuousClock.Instant, wallClock: Date) -> [Output] {
        clockAnchor = now
        wallClockAnchor = wallClock
        self.netmap = netmap
        let localAddresses = netmap.selfNode.addresses.filter(EnginePeer.isSingleAddress).map(\.address)
        self.localAddresses = Set(localAddresses)
        filter.replaceRules(netmap.packetFilter, localAddresses: localAddresses)
        applyKeyExpiry(at: now)
        return []
    }

    /// now까지 기한이 지난 타이머를 처리한다(WireGuard 타이머, 피어와 자기 노드의 키 만료).
    ///
    /// 자기 키가 만료되면 새 netmap이 오지 않아도 응답기를 비운다(모든 이름이 SERVFAIL). 그 시각은 `nextDeadline`에
    /// 들어 있으므로 부르는 쪽이 그때 `advance`를 불러야 한다.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        if let deadline = keyExpiryDeadline, deadline <= now {
            applyKeyExpiry(at: now)
        }
        return route(device.advance(to: now))
    }

    /// 다음에 advance를 불러야 하는 시각. 노드가 처리마다 부르므로 배열을 만들지 않는다.
    public var nextDeadline: ContinuousClock.Instant? {
        guard let deviceDeadline = device.nextDeadline else { return keyExpiryDeadline }
        guard let keyExpiryDeadline else { return deviceDeadline }
        return min(deviceDeadline, keyExpiryDeadline)
    }

    // MARK: - 피어와 응답기 동기화

    /// 마지막 netmap에서 now 시점의 피어와 응답기를 다시 계산하고 다음 키 만료 시각을 정한다.
    private mutating func applyKeyExpiry(at now: ContinuousClock.Instant) {
        guard let netmap else { return }
        let wallNow = wallClock(at: now)
        configurePeers(in: netmap, wallNow: wallNow)
        installResolver(for: netmap, wallNow: wallNow)
        keyExpiryDeadline = nextExpiry(in: netmap, after: wallNow).map { now + $0 }
    }

    /// 응답기를 now 시점의 netmap으로 다시 만든다. 자기 키가 만료됐으면 빈 응답기다(동작 D7, 닫힌 쪽).
    private mutating func installResolver(for netmap: Netmap, wallNow: Date) {
        if TunnelNetworkSettings.isExpired(netmap.selfNode, at: wallNow) {
            resolver = MagicDNSResolver(netmap: nil, localZones: [])
        } else {
            resolver = MagicDNSResolver(netmap: netmap, localZones: TunnelNetworkSettings.localZones(in: netmap, at: wallNow))
        }
    }

    /// netmap에서 wallNow 시점의 피어를 계산해 WireGuard와 송신 색인을 맞춘다.
    private mutating func configurePeers(in netmap: Netmap, wallNow: Date) {
        var current: [NodePublicKey: EnginePeer] = [:]
        var addressIndex: [IPAddress: NodePublicKey] = [:]
        // 키와 접두의 주인은 `eligibleNodes`가 하나로 정해 준다. 송신 색인도 같은 규칙(node ID가 작은 쪽)이다.
        for (node, peer) in EnginePeer.eligibleNodes(in: netmap, at: wallNow) {
            current[peer.key] = peer
            for prefix in node.addresses where EnginePeer.isSingleAddress(prefix) && addressIndex[prefix.address] == nil {
                addressIndex[prefix.address] = peer.key
            }
        }

        for key in peers.keys where current[key] == nil {
            device.removePeer(PublicKey(key))
        }
        for peer in current.values {
            device.addPeer(PublicKey(peer.key), allowedIPs: peer.allowedIPs)
        }
        peers = current
        peerByAddress = addressIndex
    }

    /// wallNow 뒤에 오는 피어와 자기 노드의 가장 이른 키 만료까지의 시간. 하루보다 멀면 하루 뒤에 다시 본다.
    private func nextExpiry(in netmap: Netmap, after wallNow: Date) -> Duration? {
        let upcoming = (netmap.peers + [netmap.selfNode]).compactMap(\.keyExpiry).filter { $0 > wallNow }.min()
        return upcoming.map { min(.seconds($0.timeIntervalSince(wallNow)), Self.maximumExpiryCheckInterval) }
    }

    /// 단조 시각 now의 벽시계 시각.
    func wallClock(at now: ContinuousClock.Instant) -> Date {
        let elapsed = (now - clockAnchor).components
        return wallClockAnchor.addingTimeInterval(Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18)
    }
}

extension TailnetEngine: CustomReflectable {
    /// node 개인 키와 WireGuard 세션 키가 `dump`·디버거에 나오지 않도록 자식을 감추고 공개된 값만 보인다.
    public var customMirror: Mirror {
        Mirror(
            self,
            children: ["publicKey": NodePublicKey(device.publicKey), "peerCount": peers.count],
            displayStyle: .struct
        )
    }
}
