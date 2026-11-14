// 규칙 변환과 일치 함수의 흐름은 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `wgengine/filter/tailcfg.go` (`MatchesFromFilterRules`, `parseIPSet`),
// `wgengine/filter/match.go` (`match`, `matchIPsOnly`, `matchProtoAndIPsOnlyIfAllPorts`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl

/// 해석을 마친 허용 규칙 하나. 제어 서버가 준 `FilterRule`의 문자열을 경계에서 한 번 풀어 둔 것이다.
///
/// 규칙들은 허용의 합이다. 거부 규칙과 우선순위는 없다. 해석할 수 없는 주소 항목은 그 항목만 버리므로
/// 규칙은 넓어지지 않고 좁아질 뿐이다(닫힌 쪽으로 실패).
///
/// `docs/protocol-notes/netmap-engine.md` 4.4, `docs/contracts/SwiftailEngine.md` 동작 6.
struct FilterMatch: Sendable {
    /// 목적지 주소와 포트 범위 하나.
    struct Destination: Sendable {
        let addresses: AddressRange
        /// 양 끝 포함. `first > last`면 어떤 포트도 맞지 않는다(Go와 같다).
        let firstPort: UInt16
        let lastPort: UInt16

        func contains(port: UInt16) -> Bool { firstPort <= port && port <= lastPort }
        var coversAllPorts: Bool { firstPort == 0 && lastPort == .max }
    }

    /// 허용하는 IP 프로토콜 번호.
    let protocols: Set<UInt8>
    /// 출발 주소. 이 가운데 하나에 들면 된다. 출발 포트는 보지 않는다.
    let sources: [AddressRange]
    let destinations: [Destination]

    /// `IPProto`가 비었을 때의 기본: TCP, UDP, ICMPv4, ICMPv6.
    private static let defaultProtocols: Set<UInt8> = [6, 17, 1, 58]

    /// TCP SYN·UDP·SCTP용: 프로토콜, 출발 주소, 목적 주소와 목적 포트가 모두 맞는가.
    func matches(_ packet: IPPacket) -> Bool {
        protocols.contains(packet.protocolNumber)
            && containsSource(of: packet)
            && destinations.contains { $0.addresses.contains(packet.destination) && $0.contains(port: packet.destinationPort) }
    }

    /// ICMP용: 출발·목적 주소만 본다. 프로토콜과 포트는 보지 않는다(어느 포트든 열려 있는 주소에는 ICMP도 허용).
    func matchesAddresses(of packet: IPPacket) -> Bool {
        containsSource(of: packet) && destinations.contains { $0.addresses.contains(packet.destination) }
    }

    /// 그 밖의 프로토콜용: 프로토콜과 주소가 맞고 포트 범위가 0…65535 전체인 목적지가 있는가.
    func matchesAllPorts(of packet: IPPacket) -> Bool {
        protocols.contains(packet.protocolNumber)
            && containsSource(of: packet)
            && destinations.contains { $0.coversAllPorts && $0.addresses.contains(packet.destination) }
    }

    private func containsSource(of packet: IPPacket) -> Bool {
        sources.contains { $0.contains(packet.source) }
    }
}

extension FilterMatch {
    /// 규칙 목록을 해석한다.
    ///
    /// 옛 형식의 `SrcBits`나 `DstPorts[].Bits`가 하나라도 있으면 빈 목록(모두 차단)이다. Go도 이때 변환 결과
    /// 전체를 버린다. 옛 규칙의 일부만 살려 뜻이 달라지는 것보다 모두 막는 쪽이 안전하다.
    /// 출발지나 목적지가 하나도 남지 않은 규칙(예: `CapGrant`만 있는 규칙)은 패킷을 열지 않으므로 뺀다.
    static func matches(from rules: [FilterRule]) -> [FilterMatch] {
        guard rules.allSatisfy({ $0.srcBits.isEmpty && $0.dstPorts.allSatisfy { $0.bits == nil } }) else {
            return []
        }
        return rules.compactMap(FilterMatch.init(rule:))
    }

    private init?(rule: FilterRule) {
        let sources = rule.srcIPs.flatMap(AddressRange.ranges(parsing:))
        let destinations = rule.dstPorts.flatMap { port in
            AddressRange.ranges(parsing: port.ip).map {
                Destination(addresses: $0, firstPort: port.ports.first, lastPort: port.ports.last)
            }
        }
        guard !sources.isEmpty, !destinations.isEmpty else { return nil }
        self.sources = sources
        self.destinations = destinations
        // 명시한 목록에서는 0…255만 남긴다. 모두 범위 밖이면 빈 집합이며 기본 집합으로 되돌리지 않는다.
        protocols = rule.ipProto.isEmpty ? Self.defaultProtocols : Set(rule.ipProto.compactMap(UInt8.init(exactly:)))
    }
}
