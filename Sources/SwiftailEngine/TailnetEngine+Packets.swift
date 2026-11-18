import SwiftailBase
import SwiftailWireGuard

/// 패킷의 송수신: 위에서 내려온 IP 패킷을 피어에게, 받은 WireGuard 데이터그램을 필터를 거쳐 위로.
///
/// 받는 쪽의 층 순서는 Go와 같다. WireGuard의 인증·재전송 방지 → 그 인증된 피어의 AllowedIPs로 출발지 검사 →
/// TSMP 소비(disco 키 광고는 위로 알림) → 수신 필터. 보낸 피어는 WireGuard 세션이 정하고, 데이터그램의 출처(주소나 DERP 보낸 쪽)는 피어를
/// 정하는 데 쓰지 않는다. 출처는 WireGuard의 부하 방어(cookie, 출처별 속도 제한)에만 넘긴다.
///
/// `docs/protocol-notes/netmap-engine.md` 4.2·4.6·6.1, `docs/contracts/SwiftailEngine.md` 동작 4·5와 M-E1·M-E2,
/// `docs/contracts/SwiftailTunnel.md` 동작 L.
extension TailnetEngine {

    /// 위에서 내려온 IP 패킷 하나를 보낸다.
    ///
    /// 서비스 IP로 가는 패킷과 자기 주소로 가는 패킷, 장치에서 온 TSMP는 WireGuard로 보내지 않고 엔진이 처리한다
    /// (`TailnetEngine+LocalDelivery.swift`). 나머지는 목적지 주소를 AllowedIPs로 가진 피어에게 보낸다.
    /// 나가는 패킷에는 ACL을 적용하지 않고(Go와 같다) UDP 응답을 받으려고 흐름만 기록한다.
    ///
    /// 로컬 응답은 `.ipPacket`으로 나온다. 장치로 되써야 할 패킷이다.
    public mutating func send(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output] {
        let packet: IPPacket
        do {
            packet = try IPPacket(parsing: ipPacket)
        } catch {
            return [.dropped(Drop(error))]
        }
        if let local = deliverLocally(packet, at: now) {
            return [local]
        }
        guard let key = addressOwners[packet.destination]?.key else {
            return [.dropped(.noPeerForDestination)]
        }
        filter.recordOutbound(packet)
        do {
            return route(try device.send(packet.bytes, to: PublicKey(key), at: now))
        } catch {
            return [.dropped(.wireGuard(error))]
        }
    }

    /// `Magicsock`이 WireGuard로 분류한 데이터그램 하나를 처리한다(`.wireGuard` 출력).
    ///
    /// disco·STUN은 여기에 오지 않는다. 보낸 피어는 WireGuard 세션이 인증하고, 출발 주소는 그 피어의 AllowedIPs가
    /// 검사한다. `source`는 WireGuard가 부하 상태일 때만 쓴다. 그때 나오는 `.cookieReply`는 `source`로 되돌린다.
    public mutating func receive(_ datagram: [UInt8], from source: Source, at now: ContinuousClock.Instant) -> [Output] {
        do {
            return route(try device.receive(datagram, from: source, at: now))
        } catch {
            return [.dropped(.wireGuard(error))]
        }
    }

    /// 장치의 출력을 엔진의 출력으로 바꾼다. 데이터그램은 그대로 내보내고(경로는 `Magicsock`이 고른다), 올라온 IP
    /// 패킷은 필터에 건다. 핸드셰이크 응답·재시도·keepalive도 같은 길이다.
    mutating func route(_ outputs: [WireGuardDevice.Output]) -> [Output] {
        outputs.map { output in
            switch output {
            case let .datagram(bytes, to: wireGuardKey):
                return .datagram(bytes, to: NodePublicKey(wireGuardKey))
            case let .ipPacket(bytes, from: wireGuardKey):
                return deliverInbound(bytes, from: NodePublicKey(wireGuardKey))
            case let .rejectedIPPacket(error, from: _):
                return .dropped(.wireGuard(error))
            case let .cookieReply(bytes):
                return .cookieReply(bytes)
            }
        }
    }

    /// 복호화와 AllowedIPs 출발지 검사를 통과한 패킷을 해석하고 필터에 건다. `peer`는 그 패킷을 보낸 WireGuard 피어다.
    ///
    /// TSMP는 위로 올리지 않는다. 그 가운데 0이 아닌 disco 키 광고는 보낸 피어와 함께 `.discoKeyAdvertised`로 낸다(Go
    /// `net/tstun/wrap.go`가 광고를 버리면서 알리는 것과 같다. Go는 출발 주소로 피어를 찾고, 여기서는 출발지 검사를 이미
    /// 통과했으므로 그 주소의 주인인 WireGuard 피어를 바로 쓴다).
    private mutating func deliverInbound(_ bytes: [UInt8], from peer: NodePublicKey) -> Output {
        let packet: IPPacket
        do {
            packet = try IPPacket(parsing: bytes)
        } catch {
            return .dropped(Drop(error))
        }
        // shortcut: TSMP의 ping에 pong을 보내지 않고 거절도 보내지 않는다. disco 광고 밖의 TSMP는 소비만 한다.
        if packet.transportProtocol == .tsmp {
            if let advertisement = TSMPDiscoKeyAdvertisement(parsing: packet), !advertisement.key.isZero {
                return .discoKeyAdvertised(advertisement.key, from: peer)
            }
            return .dropped(.consumedControlPacket)
        }
        switch filter.checkInbound(packet) {
        case .accept:
            return .ipPacket(packet.bytes)
        case let .drop(reason):
            return .dropped(.inbound(reason))
        }
    }
}

private extension TailnetEngine.Drop {
    init(_ error: IPPacket.ParseError) {
        switch error {
        case .malformed: self = .malformedPacket
        case .fragment, .extensionHeader: self = .unsupportedPacket
        }
    }
}
