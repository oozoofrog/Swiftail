// TSMP disco 키 광고의 형식은 Go 구현을 옮겼다.
// 출처: tailscale.com v1.104.7 `net/packet/tsmp.go` (`TSMPDiscoKeyAdvertisement`, `Marshal`,
// `AsTSMPDiscoAdvertisement`), `net/packet/ip4.go`·`ip6.go` (`Marshal`), `wgengine/magicsock/magicsock.go`
// (`selfIPMatchingFamily`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 노드가 WireGuard 세션이 설 때마다 피어에게 터널 안으로 보내는 자기 disco 공개 키 알림(노트 `disco-magicsock.md` 3.8).
///
/// IP 머리(IPv4 20바이트 또는 IPv6 40바이트, protocol 99 TSMP, TTL 64, ID 0) 뒤에 `'a'`와 disco 키 32바이트가 온다.
/// 받는 쪽은 netmap을 기다리지 않고 이 키로 disco를 연다(`SwiftailMagicsock` 계약 "TSMP disco 키 광고").
struct TSMPDiscoKeyAdvertisement: Sendable, Equatable {
    /// IP protocol 번호 99(Go `ipproto.TSMP`).
    static let protocolNumber: UInt8 = 99
    /// TSMP 종류 바이트 `'a'`(Go `TSMPTypeDiscoAdvertisement`).
    static let type = UInt8(ascii: "a")
    /// IP 머리 뒤의 길이: 종류 1 + 키 32.
    static let payloadLength = 33

    /// 보내는 노드의 tailnet 주소.
    var source: IPAddress
    /// 받는 피어의 tailnet 주소. `source`와 계열이 같다.
    var destination: IPAddress
    /// 보내는 노드의 disco 공개 키.
    var key: DiscoPublicKey

    /// 피어 `destination`에게 보낼 광고. 자기 주소 가운데 계열이 같은 첫 한 주소짜리 주소를 출발지로 쓴다(Go
    /// `selfIPMatchingFamily`). 그런 주소가 없거나 키가 0이면 nil(Go는 그때 보내지 않는다).
    ///
    /// - Parameters:
    ///   - selfAddresses: netmap의 자기 `Addresses` 순서 그대로.
    ///   - destination: 피어의 첫 `Addresses` 주소(Go `endpoint.nodeAddr`).
    init?(selfAddresses: [IPPrefix], destination: IPAddress, key: DiscoPublicKey) {
        guard !key.isZero,
              let source = selfAddresses.first(where: {
                  $0.length == $0.address.bytes.count * 8 && $0.address.isIPv4 == destination.isIPv4
              })?.address
        else { return nil }
        self.source = source
        self.destination = destination
        self.key = key
    }

    /// 엔진이 해석한 받은 패킷이 광고면 그 내용. TSMP가 아니거나, 종류가 `'a'`가 아니거나, 33바이트보다 짧으면 nil.
    /// 키가 0일 수 있다(받는 쪽이 버린다).
    init?(parsing packet: IPPacket) {
        guard packet.transportProtocol == .tsmp else { return nil }
        let payload = packet.bytes[packet.transportOffset...]
        guard payload.count >= Self.payloadLength, payload.first == Self.type,
              let key = DiscoPublicKey(rawValue: payload.dropFirst().prefix(DiscoPublicKey.byteCount))
        else { return nil }
        source = packet.source
        destination = packet.destination
        self.key = key
    }

    /// 보낼 IP 패킷(Go `TSMPDiscoKeyAdvertisement.Marshal`과 같은 바이트). IPv4 53바이트, IPv6 73바이트.
    var bytes: [UInt8] {
        let payload = [Self.type] + key.rawValue
        if source.isIPv4 {
            let totalLength = 20 + payload.count
            var header: [UInt8] = [
                0x45, 0x00, UInt8(totalLength >> 8), UInt8(totalLength & 0xFF),
                0x00, 0x00, 0x00, 0x00,
                64, Self.protocolNumber, 0x00, 0x00,
            ]
            header += source.bytes + destination.bytes
            let checksum = InternetChecksum.checksum(of: header)
            header[10] = UInt8(checksum >> 8)
            header[11] = UInt8(checksum & 0xFF)
            return header + payload
        }
        let header: [UInt8] = [0x60, 0x00, 0x00, 0x00, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF), Self.protocolNumber, 64]
        return header + source.bytes + destination.bytes + payload
    }
}
