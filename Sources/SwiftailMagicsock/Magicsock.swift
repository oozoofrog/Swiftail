import CryptoKit
import SwiftailBase
import SwiftailCrypto

/// 피어 사이의 직접 경로를 찾고 유지하는 상태 기계. 소켓·시계·actor를 갖지 않는다.
///
/// 노드는 받은 UDP 데이터그램, DERP로 받은 패킷, 엔진이 낸 WireGuard 데이터그램, netmap에서 뽑은 피어 정보,
/// 그리고 지금 시각을 넣는다. `Magicsock`은 상태를 바꾸고 "UDP·DERP로 보낼 것", "WireGuard 장치에 넣을 것",
/// "제어 서버에 올릴 것", "경로가 바뀐 피어"를 돌려준다. 모든 진입점은 던지지 않는다. 버린 것은 `.dropped`로 알린다.
///
/// 난수(disco nonce, TxID, ReSTUN 간격)는 이 타입이 시스템 난수로 뽑는다(`WireGuardDevice`와 같다). 그 아래의
/// 단계(`PeerPathState`, `Netcheck`, `DiscoPacket.seal`)는 난수를 인자로 받는다. 시험은 같은 이름에 `using:`이
/// 붙은 내부 진입점으로 고정 시드 난수를 넘긴다.
///
/// 호출 규칙: `now`는 호출마다 줄어들지 않아야 한다. 노드는 `nextDeadline`에 맞춰 `advance(to:)`를 부르고,
/// 진입점이 돌려준 출력을 목록의 순서대로 처리한다.
///
/// 파일: 여기는 상태·출력·조회, `+Peers`는 피어 표와 disco 키, `+Receiving`은 받은 것의 분류와 disco 받기,
/// `+Sending`은 WireGuard 송신과 disco 보내기·CallMeMaybe, `+Timers`는 기한과 STUN 회차, `+Rebind`는 망이 바뀐 뒤의
/// 재결속과 STUN 다시 하기다.
/// `docs/contracts/SwiftailMagicsock.md` "공개 API"·동작 A~I, `docs/protocol-notes/disco-magicsock.md` 4절.
public struct Magicsock: Sendable {
    /// 상태 기계가 내놓는 일.
    public enum Output: Sendable, Equatable {
        /// UDP 소켓으로 보낸다(WireGuard, disco, STUN 모두 같은 소켓이다).
        case udp([UInt8], to: IPEndpoint)
        /// DERP 지역 `region`의 연결로 피어에게 보낸다. 그 지역에 연결이 없으면 노드가 연다.
        case derp([UInt8], to: NodePublicKey, region: Int64)
        /// WireGuard 장치(엔진의 `receive`)에 넣을 데이터그램과 그것이 온 길. 장치가 이 데이터그램에 답하는 cookie
        /// reply는 피어 경로 선택 없이 이 길로 되돌린다.
        case wireGuard([UInt8], from: Source)
        /// 제어 서버에 올릴 자기 엔드포인트가 바뀌었다(순서가 의미 있다. 노트 4.9 1).
        case endpointsChanged([Endpoint])
        /// 홈 DERP 지역이 바뀌었다. `NetInfo.preferredDERP`로 올리고 그 지역에 연결한다.
        case homeRegionChanged(Int64)
        /// 피어의 경로가 바뀌었다. nil은 그 피어가 빠졌거나 유휴라는 뜻이다(동작 G3).
        case pathChanged(NodePublicKey, PeerPath?)
        /// 버린 것. 진단과 시험용이다.
        case dropped(Drop)
    }

    /// 버린 까닭.
    public enum Drop: Sendable, Equatable {
        /// 보낸 쪽 disco 키가 아는 피어의 것이 아니다.
        case unknownDiscoKey
        /// 열리지 않거나 해석할 수 없는 disco 메시지.
        case malformedDisco
        /// 처리하지 않는 disco 종류(peer relay 0x04–0x09), Geneve로 감싼 데이터그램.
        case unsupportedDisco
        /// 경로 규칙을 어긴 disco(UDP로 온 CallMeMaybe, 키가 맞지 않는 CallMeMaybe, 모르는 DERP 보낸 쪽).
        case misroutedDisco
        /// 진행 중인 회차의 것이 아니거나 해석할 수 없는 STUN 응답.
        case unexpectedSTUN
        /// DERP 보낸 쪽 키가 아는 피어가 아니다.
        case unknownDERPSender
        /// 직접 주소도 DERP 지역도 없어 보낼 곳이 없다.
        case noRouteToPeer
        /// 받을 수 없는 출처(IPv6, 포트 0).
        case unsupportedSource
    }

    /// 피어 하나의 상태.
    struct PeerEntry: Sendable {
        /// 이 피어와 disco를 하면 그 disco 키(동작 B1의 주인이고 공유 키가 있다). nil이면 DERP만 쓴다.
        var discoKey: DiscoPublicKey?
        var path: PeerPathState
        /// 마지막으로 `.pathChanged`로 알린 경로. nil은 아직 알리지 않았거나 유휴를 알렸다는 뜻이다.
        /// 같은 값은 다시 알리지 않는다(동작 G2).
        var reportedPath: PeerPath?
    }

    /// disco 키 하나의 주인과 공유 키. 공유 키는 `setPeers`에서 키마다 한 번만 계산한다(동작 B2).
    struct DiscoPeer: Sendable {
        let node: NodePublicKey
        let sharedKey: DiscoSharedKey
    }

    /// 이 노드의 disco 공개 키. 보내는 disco 메시지의 겉 형식에 실려 상대가 공유 키를 고른다.
    public let discoPublicKey: DiscoPublicKey
    /// 비밀이다. `customMirror`가 감춘다.
    let discoPrivateKey: Curve25519.KeyAgreement.PrivateKey
    /// 보내는 Ping에 넣는 자기 node 키(노트 4.6 1).
    let nodeKey: NodePublicKey

    /// 피어 표. 키 → 상태.
    var peers: [NodePublicKey: PeerEntry] = [:]
    /// `setPeers`가 받은 순서. 출력의 순서를 입력열마다 같게 한다.
    var peerOrder: [NodePublicKey] = []
    /// disco 키 → 주인과 공유 키. 받은 disco의 보낸 쪽 키는 이 표에서만 찾는다(받을 때마다 X25519를 하지 않는다).
    var discoPeers: [DiscoPublicKey: DiscoPeer] = [:]
    /// 자기 엔드포인트, STUN 회차, 홈 지역.
    var netcheck: Netcheck
    /// 엔드포인트가 낡아 회차가 끝난 뒤 CallMeMaybe를 보낼 피어. 피어당 한 칸이다(동작 F2).
    var pendingCallMeMaybe: [NodePublicKey] = []

    /// - Parameters:
    ///   - discoKey: 이 노드의 disco 개인 키. 노드가 시작할 때 만들고 저장하지 않는다.
    ///   - nodeKey: 이 노드의 node 공개 키. 보내는 Ping에 넣는다(노트 4.6 1).
    ///   - localPort: UDP 소켓이 묶인 포트.
    ///   - localAddresses: 인터페이스의 IPv4 주소(loopback 제외). `LocalInterfaceAddresses`가 고른다.
    ///   - loopbackAddresses: loopback IPv4 주소. 다른 엔드포인트가 하나도 없을 때만 쓴다(노트 4.9 1.7).
    ///   - now: 지금 시각. 다른 상태 기계와 같은 모양으로 받는다. 피어와 지역이 오기 전에는 걸 타이머가 없다.
    public init(
        discoKey: Curve25519.KeyAgreement.PrivateKey,
        nodeKey: NodePublicKey,
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        now: ContinuousClock.Instant
    ) {
        discoPrivateKey = discoKey
        discoPublicKey = DiscoPublicKey(discoKey.publicKey)
        self.nodeKey = nodeKey
        netcheck = Netcheck(localPort: localPort, localAddresses: localAddresses, loopbackAddresses: loopbackAddresses)
    }

    /// 피어의 지금 경로. 데이터면에 없거나 유휴인 피어면 nil(동작 G3).
    public func path(to peer: NodePublicKey, at now: ContinuousClock.Instant) -> PeerPath? {
        peers[peer].flatMap { Self.path(of: $0, at: now) }
    }

    // MARK: 경로 사건 (동작 G)

    /// 피어 하나의 지금 경로. 마지막 WireGuard 송신 뒤 45초가 넘었거나 아직 보낸 적이 없으면 유휴라서 nil이다(동작 G3).
    ///
    /// 유휴 피어를 `.relayed`로 보이면, 트래픽이 생기면 직접으로 붙을 연결이 "중계"로 표시된다. 그래서 경로는 실제로
    /// 주고받는 동안만 알린다. 유휴 판단은 heartbeat·주기 STUN을 멈추는 것과 같은 기준(`sessionActiveTimeout`)이다.
    static func path(of entry: PeerEntry, at now: ContinuousClock.Instant) -> PeerPath? {
        guard let lastSend = entry.path.lastSend, now - lastSend <= PeerPathState.sessionActiveTimeout else { return nil }
        return entry.path.path(at: now)
    }

    /// 알린 경로가 유휴로 nil이 되는 시각. 이미 nil을 알렸으면 기한이 없다(지난 시각을 계속 내지 않는다).
    static func idleDeadline(of entry: PeerEntry) -> ContinuousClock.Instant? {
        guard entry.reportedPath != nil, let lastSend = entry.path.lastSend else { return nil }
        return lastSend + PeerPathState.sessionActiveTimeout + .nanoseconds(1)
    }

    /// 피어의 지금 경로가 마지막으로 알린 것과 다르면 `.pathChanged`를 더하고 기억한다.
    mutating func reportPathChange(of key: NodePublicKey, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard let entry = peers[key] else { return }
        let current = Self.path(of: entry, at: now)
        guard entry.reportedPath != current else { return }
        peers[key]?.reportedPath = current
        outputs.append(.pathChanged(key, current))
    }

    // MARK: disco 봉하기

    /// `message`를 disco 키 `discoKey`의 공유 키로 봉한다. 그 키와 disco를 하지 않으면 nil.
    func seal(
        _ message: DiscoMessage,
        to discoKey: DiscoPublicKey,
        using generator: inout some RandomNumberGenerator
    ) -> [UInt8]? {
        guard let discoPeer = discoPeers[discoKey] else { return nil }
        let nonce = (0..<NaClSecretBox.nonceByteCount).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return DiscoPacket.seal(message, sender: discoPublicKey, sharedKey: discoPeer.sharedKey, nonce: nonce)
    }
}

extension Magicsock: CustomReflectable {
    /// disco 개인 키와 공유 키가 `dump`·디버거에 나오지 않도록 자식을 감추고 공개된 값만 보인다(동작 I1).
    public var customMirror: Mirror {
        Mirror(
            self,
            children: ["discoPublicKey": discoPublicKey, "peerCount": peers.count, "homeRegion": netcheck.homeRegion],
            displayStyle: .struct
        )
    }
}
