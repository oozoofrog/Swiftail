import SwiftailBase
import SwiftailWireGuard

/// 패킷의 송수신: 위에서 내려온 IP 패킷을 피어에게, DERP에서 받은 메시지를 필터를 거쳐 위로.
///
/// 받는 쪽의 층 순서는 Go와 같다. WireGuard의 인증·재전송 방지 → 그 인증된 피어의 AllowedIPs로 출발지 검사 →
/// TSMP 소비 → 수신 필터. DERP 프레임에 적힌 보낸 쪽 키는 출발지 검사를 대신하지 않는다.
///
/// `docs/protocol-notes/netmap-engine.md` 4.2·4.6·6.1, `docs/contracts/SwiftailEngine.md` 동작 4·5.
extension TailnetEngine {
    /// disco 메시지의 첫 6바이트 `"TS💬"`. 이 뒤에 보낸 쪽 disco 키 32바이트와 nonce 24바이트가 온다.
    private static let discoMagic: [UInt8] = [0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC]
    /// magic, disco 키, nonce를 합친 disco 메시지의 최소 길이.
    private static let discoHeaderLength = 62

    /// 위에서 내려온 IP 패킷 하나를 보낸다.
    ///
    /// 목적지가 어느 피어의 한 주소짜리 `addresses`인지로 피어를 고른다. 나가는 패킷에는 ACL을 적용하지 않고
    /// (Go와 같다) UDP 응답을 받으려고 흐름만 기록한다.
    public mutating func send(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output] {
        let packet: IPPacket
        do {
            packet = try IPPacket(parsing: ipPacket)
        } catch {
            return [.dropped(Drop(error))]
        }
        guard let key = peerByAddress[packet.destination], let peer = peers[key] else {
            return [.dropped(.noPeerForDestination)]
        }
        guard isReachable(peer) else {
            return [.dropped(.noRouteToPeer)]
        }
        filter.recordOutbound(packet)
        do {
            return route(try device.send(packet.bytes, to: PublicKey(key), at: now))
        } catch {
            return [.dropped(.wireGuard(error))]
        }
    }

    /// DERP에서 받은 패킷 하나를 처리한다.
    ///
    /// - Parameter peer: DERP 프레임의 보낸 쪽 키. 출발지 검사에 쓰지 않는다. 보낸 피어는 WireGuard 세션이
    ///   인증하고, 출발 주소는 그 피어의 AllowedIPs가 검사한다.
    public mutating func receive(_ packet: [UInt8], from _: NodePublicKey, at now: ContinuousClock.Instant) -> [Output] {
        // shortcut: disco(경로 탐색)는 M4다. 지금은 알아보고 버린다.
        if packet.count >= Self.discoHeaderLength, packet.starts(with: Self.discoMagic) {
            return [.dropped(.discoMessage)]
        }
        do {
            return route(try device.receive(packet, at: now))
        } catch {
            return [.dropped(.wireGuard(error))]
        }
    }

    /// 장치의 출력을 엔진의 출력으로 바꾼다. 데이터그램에는 DERP 지역을 붙이고, 올라온 IP 패킷은 필터에 건다.
    mutating func route(_ outputs: [WireGuardDevice.Output]) -> [Output] {
        outputs.map { output in
            switch output {
            case let .datagram(bytes, to: wireGuardKey):
                // 핸드셰이크 응답·재시도·keepalive도 이 피어의 홈 지역으로만 나간다. M3은 다른 지역에 연결하지 않는다.
                let key = NodePublicKey(wireGuardKey)
                guard let peer = peers[key], isReachable(peer) else { return .dropped(.noRouteToPeer) }
                return .datagram(bytes, to: key, derpRegion: peer.homeDERP)
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

    /// 우리 홈 DERP 지역으로 닿는 피어인가. 둘 다 0(모름)이어도 닿지 않는다.
    // shortcut: 홈이 아닌 DERP 지역과 직접 UDP는 M4다.
    private func isReachable(_ peer: EnginePeer) -> Bool {
        peer.homeDERP != 0 && peer.homeDERP == homeDERP
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
