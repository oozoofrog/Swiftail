import SwiftailBase
import SwiftailWireGuard

/// 패킷의 송수신: 위에서 내려온 IP 패킷을 피어에게, 받은 WireGuard 데이터그램을 필터를 거쳐 위로.
///
/// 받는 쪽의 층 순서는 Go와 같다. WireGuard의 인증·재전송 방지 → 그 인증된 피어의 AllowedIPs로 출발지 검사 →
/// TSMP 소비 → 수신 필터. 데이터그램이 어느 주소나 DERP 보낸 쪽에서 왔는지는 보지 않는다. 보낸 피어는 WireGuard
/// 세션이 정한다.
///
/// `docs/protocol-notes/netmap-engine.md` 4.2·4.6·6.1, `docs/contracts/SwiftailEngine.md` 동작 4·5와 M-E1·M-E2,
/// `docs/contracts/SwiftailTunnel.md` 동작 L.
extension TailnetEngine {

    /// 위에서 내려온 IP 패킷 하나를 보낸다.
    ///
    /// 서비스 IP로 가는 패킷과 자기 주소로 가는 패킷, 장치에서 온 TSMP는 WireGuard로 보내지 않고 엔진이 처리한다
    /// (`TailnetEngine+LocalDelivery.swift`). 나머지는 목적지가 어느 피어의 한 주소짜리 `addresses`인지로 피어를
    /// 고른다. 나가는 패킷에는 ACL을 적용하지 않고(Go와 같다) UDP 응답을 받으려고 흐름만 기록한다.
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
        guard let key = peerByAddress[packet.destination], peers[key] != nil else {
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
    /// 검사한다.
    public mutating func receive(_ datagram: [UInt8], at now: ContinuousClock.Instant) -> [Output] {
        do {
            return route(try device.receive(datagram, at: now))
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
            case let .ipPacket(bytes, from: _):
                return deliverInbound(bytes)
            case let .rejectedIPPacket(error, from: _):
                return .dropped(.wireGuard(error))
            }
        }
    }

    /// 복호화와 AllowedIPs 출발지 검사를 통과한 패킷을 해석하고 필터에 건다.
    private mutating func deliverInbound(_ bytes: [UInt8]) -> Output {
        let packet: IPPacket
        do {
            packet = try IPPacket(parsing: bytes)
        } catch {
            return .dropped(Drop(error))
        }
        // shortcut: TSMP의 ping에 pong을 보내지 않고, 거절·disco 광고도 보내지 않는다. 받은 것은 소비만 한다.
        if packet.transportProtocol == .tsmp {
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
