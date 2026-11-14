// 판정 순서는 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `wgengine/filter/filter.go` (`pre`, `runIn4`, `runIn6`, `UpdateOutboundFlowState`),
// `net/packet/packet.go` (`IsEchoResponse`, `IsError`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl

/// 들어오는 패킷을 받을지 정한다. tailcfg 필터 규칙과 자기 주소에서 만든다.
///
/// 나가는 패킷에는 규칙을 적용하지 않고 UDP 흐름만 기록한다(Go와 같다). 들어오는 패킷은 다음 순서로 본다.
/// 1. 목적지가 multicast·link-local이면 버린다.
/// 2. 목적지가 자기 주소가 아니면 버린다. 허용 규칙이 넓어도 그렇다(피어가 다른 목적지를 노리는 것을 막는다).
/// 3. 프로토콜별 판정. TCP는 새 연결(SYN, ACK 없음)만 규칙을 보고, UDP·SCTP는 먼저 보낸 흐름의 응답이면 받고,
///    ICMP는 echo reply와 오류를 받고 그 밖에는 주소만 맞는 규칙을 본다.
///
/// `docs/protocol-notes/netmap-engine.md` 4.4~4.6, `docs/contracts/SwiftailEngine.md` 동작 6.
public struct PacketFilter: Sendable {
    /// 판정.
    public enum Verdict: Sendable, Equatable {
        case accept
        case drop(DropReason)
    }

    /// 버린 까닭.
    public enum DropReason: Sendable, Equatable {
        /// 목적지가 자기 주소가 아니다.
        case notForUs
        /// 맞는 허용 규칙이 없다.
        case noRuleMatched
        /// 목적지가 multicast 또는 link-local이다.
        case multicastOrLinkLocal
    }

    private var matches: [FilterMatch]
    private var localAddresses: Set<IPAddress>
    private var flows = FlowTable()

    /// 규칙이 없다. 모든 새 흐름을 버린다(netmap을 받기 전의 상태).
    public static var allowNone: PacketFilter {
        PacketFilter(matches: [], localAddresses: [])
    }

    /// - Parameters:
    ///   - rules: `Netmap.packetFilter` 그대로. 해석할 수 없는 항목은 그 항목만 버린다.
    ///     옛 형식(`SrcBits`, `DstPorts[].Bits`)이 하나라도 있으면 규칙이 하나도 없는 필터가 된다.
    ///   - localAddresses: 자기 노드의 주소. 목적지가 여기에 없으면 버린다.
    public init(rules: [FilterRule], localAddresses: [IPAddress]) {
        self.init(matches: FilterMatch.matches(from: rules), localAddresses: Set(localAddresses))
    }

    private init(matches: [FilterMatch], localAddresses: Set<IPAddress>) {
        self.matches = matches
        self.localAddresses = localAddresses
    }

    /// 받은 패킷을 판정한다. 먼저 보낸 UDP·SCTP의 응답이면 규칙이 없어도 받는다.
    public mutating func checkInbound(_ packet: IPPacket) -> Verdict {
        if Self.isMulticastOrLinkLocal(packet.destination) {
            return .drop(.multicastOrLinkLocal)
        }
        guard localAddresses.contains(packet.destination) else {
            return .drop(.notForUs)
        }
        return isAllowed(packet) ? .accept : .drop(.noRuleMatched)
    }

    /// 내보낸 패킷을 적어 둔다(UDP 응답을 받기 위해서다). UDP·SCTP가 아니면 아무것도 하지 않는다.
    public mutating func recordOutbound(_ packet: IPPacket) {
        guard packet.transportProtocol == .udp || packet.transportProtocol == .sctp else { return }
        flows.recordReply(to: packet)
    }

    /// 규칙만 바꾸고 UDP 흐름 기록은 이어 간다.
    public mutating func replaceRules(_ rules: [FilterRule], localAddresses: [IPAddress]) {
        matches = FilterMatch.matches(from: rules)
        self.localAddresses = Set(localAddresses)
    }

    // MARK: - 프로토콜별 판정

    private mutating func isAllowed(_ packet: IPPacket) -> Bool {
        switch packet.transportProtocol {
        case .tcp:
            // 연결 추적이 아니다. 새 연결은 SYN 없이 시작할 수 없으므로 SYN이 아닌 것은 모두 받는다.
            return !packet.isTCPSYN || matches.contains { $0.matches(packet) }
        case .udp, .sctp:
            return flows.containsFlow(of: packet) || matches.contains { $0.matches(packet) }
        case .icmpv4, .icmpv6:
            return Self.isICMPReplyOrError(packet) || matches.contains { $0.matchesAddresses(of: packet) }
        case .tsmp:
            // 엔진은 TSMP를 필터 앞에서 소비한다. 여기까지 오면 Go처럼 받는다.
            return true
        case .other:
            return matches.contains { $0.matchesAllPorts(of: packet) }
        }
    }

    /// echo reply(v4 type 0·v6 type 129, code 0) 또는 오류 메시지인가.
    ///
    /// 오류 type은 v4 3(도달 불가)·11(시간 초과)·12(매개변수 문제), v6 1·2·3·4다. Go의 v4 상수는 12 대신
    /// 0x12(18)인데, RFC 792의 Parameter Problem은 12이므로 12를 쓴다(계약에 적은 알려진 차이).
    private static func isICMPReplyOrError(_ packet: IPPacket) -> Bool {
        guard let (type, code) = packet.icmpTypeAndCode else { return false }
        if packet.transportProtocol == .icmpv4 {
            return (type == 0 && code == 0) || [3, 11, 12].contains(type)
        }
        return (type == 129 && code == 0) || (1...4).contains(type)
    }

    /// IPv4 `224.0.0.0/4`·`169.254.0.0/16`, IPv6 `ff00::/8`·`fe80::/10`.
    private static func isMulticastOrLinkLocal(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        if address.isIPv4 {
            return bytes[0] & 0xF0 == 224 || (bytes[0] == 169 && bytes[1] == 254)
        }
        return bytes[0] == 0xFF || (bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80)
    }
}
