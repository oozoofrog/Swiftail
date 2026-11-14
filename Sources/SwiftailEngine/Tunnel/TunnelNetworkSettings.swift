import Foundation
import SwiftailBase
import SwiftailControl

/// 앱이 `NEPacketTunnelNetworkSettings`로 옮겨 적용할 값. 라이브러리는 NetworkExtension에 의존하지 않는다.
/// 목록의 순서는 정해져 있다(같은 netmap이면 같은 값이 나온다).
///
/// netmap 하나에서 순수하게 계산한다. 소켓·시계가 없고, 시각은 인자로 받는다. 노드는 netmap을 적용할 때마다
/// 이 값을 다시 계산해, 마지막으로 낸 값과 `==`로 견줘 다를 때만 앱에 낸다(계약 동작 E).
///
/// 값은 파일 셋에 나뉘어 있다: 주소와 이 파일의 조립, 경로(`TunnelNetworkSettings+Routes.swift`),
/// DNS(`TunnelNetworkSettings+DNS.swift`).
///
/// `docs/contracts/SwiftailTunnel.md` 동작 S, `docs/protocol-notes/netmap-engine.md` 4.8,
/// `docs/protocol-notes/dns-state-node.md` 4.1.4.
public struct TunnelNetworkSettings: Sendable, Equatable {
    /// 자기 주소. IPv4는 /32, IPv6는 /128. 비어 있지 않다.
    public var addresses: [IPPrefix]
    /// 터널로 보낼 경로. 피어 경로(정렬) 뒤에 서비스 IP 경로. 자기 주소가 없는 계열의 경로는 없다.
    public var routes: [IPPrefix]
    /// 비어 있으면 DNS를 설정하지 않는다. 있으면 IPv4 서비스 IP가 먼저다.
    public var dnsServers: [IPAddress]
    /// 끝 점 없는 소문자 이름. `dnsServers`가 비어 있지 않으면 이것도 비어 있지 않다.
    public var dnsMatchDomains: [String]
    /// 장치의 MTU. 산출에 넘긴 값 그대로이고, 앱은 이 값을 터널 설정에 그대로 적용한다.
    public var mtu: Int

    /// netmap에서 설정을 산출한다(계약 동작 S). 자기 주소가 없으면 nil.
    ///
    /// 값은 제어 서버가 준 것이라 믿지 않는다. 자기 주소는 한 주소짜리 접두만 받고, DNS 이름은 match 도메인으로 쓸 수
    /// 있는 것만 받는다(`TunnelNetworkSettings+DNS.swift`).
    ///
    /// - Parameters:
    ///   - mtu: 장치의 MTU. 그대로 담는다. 범위(1280…1420) 검사는 장치를 받는 곳의 몫이다(계약 동작 U1).
    ///   - now: 피어와 자기 노드의 키 만료를 판단할 시각(엔진 계약 M3 동작 2와 같은 시계).
    public init?(netmap: Netmap, mtu: Int, at now: Date) {
        // Go는 자기 주소 목록을 그대로 쓰지만, OS의 터널 주소는 호스트 주소 하나여야 한다(계약 동작 S1).
        var addresses: [IPPrefix] = []
        for prefix in netmap.selfNode.addresses where EnginePeer.isSingleAddress(prefix) && !addresses.contains(prefix) {
            addresses.append(prefix)
        }
        guard !addresses.isEmpty else { return nil }
        let hasIPv4 = addresses.contains { $0.address.isIPv4 }
        let hasIPv6 = addresses.contains { !$0.address.isIPv4 }

        self.addresses = addresses
        routes = Self.routes(
            for: EnginePeer.peers(in: netmap, at: now),
            oneCGNAT: Self.hasCapability(Self.oneCGNATCapability, in: netmap),
            hasIPv4: hasIPv4, hasIPv6: hasIPv6)
        dnsServers = []
        dnsMatchDomains = []
        self.mtu = mtu

        let zones = Self.localZones(in: netmap, at: now)
        if !zones.isEmpty {
            dnsServers = Self.dnsServers(
                hasIPv4: hasIPv4, hasIPv6: hasIPv6,
                ipv4Only: Self.hasCapability(Self.ipv4OnlyDNSCapability, in: netmap))
            dnsMatchDomains = zones.map { String($0.dropLast()) }
        }
    }

    /// 자기 노드의 `CapMap`에 있는 속성. 옛 `Capabilities` 목록은 세션이 `CapMap`에 합쳐 두었다.
    static func hasCapability(_ name: String, in netmap: Netmap) -> Bool {
        netmap.selfNode.capMap[name] != nil
    }
}
