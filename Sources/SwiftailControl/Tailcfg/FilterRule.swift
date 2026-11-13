import SwiftailBase

/// 수신 패킷 필터의 규칙 하나. Go `tailcfg.FilterRule`.
///
/// 맵 응답의 `PacketFilter`·`PacketFilters`로 온다. 규칙 목록은 "허용"의 합이다: 어느 규칙에도 맞지 않는
/// 패킷은 버린다. 그래서 빈 목록은 "모두 차단"이다. 규칙의 해석과 집행은 데이터면(M5)이 맡는다.
/// 이 계층은 서버가 보낸 표현(`srcIPs`의 `"*"`, CIDR, 범위, `"cap:"` 등)을 그대로 보관한다.
///
/// `dstPorts`는 네트워크 접근 허용이고, `capGrant`는 WhoIs가 돌려줄 애플리케이션 권한이다. 둘은 한 규칙에
/// 함께 오지 않는다.
/// `docs/protocol-notes/control-map.md` 4.3 (출처: tailscale.com `tailcfg/tailcfg.go` `FilterRule`).
public struct FilterRule: Decodable, Sendable, Equatable {
    /// 출발지 표현: IP, CIDR, `"a-b"` 범위, `"*"`, `"cap:…"` 가운데 하나씩.
    public internal(set) var srcIPs: [String]
    /// 옛 형식: `srcIPs`의 같은 자리 IP에 붙일 접두 길이.
    public internal(set) var srcBits: [Int]
    /// 허용하는 목적지와 포트 범위.
    public internal(set) var dstPorts: [NetPortRange]
    /// 허용하는 IP 프로토콜 번호. 비면 TCP·UDP·ICMP다.
    public internal(set) var ipProto: [Int]
    /// 출발지에게 주는 애플리케이션 권한.
    public internal(set) var capGrant: [CapGrant]

    private enum CodingKeys: String, CodingKey {
        case srcIPs = "SrcIPs"
        case srcBits = "SrcBits"
        case dstPorts = "DstPorts"
        case ipProto = "IPProto"
        case capGrant = "CapGrant"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        srcIPs = try container.decodeIfPresent([String].self, forKey: .srcIPs) ?? []
        srcBits = try container.decodeIfPresent([Int].self, forKey: .srcBits) ?? []
        dstPorts = try container.decodeIfPresent([NetPortRange].self, forKey: .dstPorts) ?? []
        ipProto = try container.decodeIfPresent([Int].self, forKey: .ipProto) ?? []
        capGrant = try container.decodeIfPresent([CapGrant].self, forKey: .capGrant) ?? []
    }
}

/// 목적지 주소 표현과 포트 범위. Go `tailcfg.NetPortRange`.
public struct NetPortRange: Decodable, Sendable, Equatable {
    /// 목적지 표현. `FilterRule.srcIPs`와 같은 형식이다.
    public internal(set) var ip: String
    /// 옛 형식: `ip`에 붙일 접두 길이. 없으면 `nil`.
    public internal(set) var bits: Int?
    /// 허용하는 포트 범위.
    public internal(set) var ports: PortRange

    private enum CodingKeys: String, CodingKey {
        case ip = "IP"
        case bits = "Bits"
        case ports = "Ports"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ip = try container.decodeIfPresent(String.self, forKey: .ip) ?? ""
        bits = try container.decodeIfPresent(Int.self, forKey: .bits)
        ports = try container.decodeIfPresent(PortRange.self, forKey: .ports) ?? PortRange(first: 0, last: 0)
    }
}

/// 양 끝을 포함하는 포트 범위. Go `tailcfg.PortRange`.
///
/// `ClosedRange<UInt16>`를 쓰지 않는 까닭: Go는 `first > last`(어떤 포트도 맞지 않는 범위)를 막지 않는다.
/// 그런 규칙 하나 때문에 맵 응답 전체를 거절하지 않도록 받은 그대로 둔다.
public struct PortRange: Decodable, Sendable, Equatable {
    public internal(set) var first: UInt16
    public internal(set) var last: UInt16

    init(first: UInt16, last: UInt16) {
        self.first = first
        self.last = last
    }

    private enum CodingKeys: String, CodingKey {
        case first = "First"
        case last = "Last"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        first = try container.decodeIfPresent(UInt16.self, forKey: .first) ?? 0
        last = try container.decodeIfPresent(UInt16.self, forKey: .last) ?? 0
    }
}

/// 출발지에게 주는 애플리케이션 권한. Go `tailcfg.CapGrant`.
public struct CapGrant: Decodable, Sendable, Equatable {
    /// 권한이 적용되는 목적지 접두.
    public internal(set) var dsts: [IPPrefix]
    /// 옛 형식의 권한 이름 목록.
    public internal(set) var caps: [String]
    /// 권한 이름 → 인자.
    public internal(set) var capMap: [String: [JSONValue]]

    private enum CodingKeys: String, CodingKey {
        case dsts = "Dsts"
        case caps = "Caps"
        case capMap = "CapMap"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        dsts = try container.decodeIfPresent([IPPrefix].self, forKey: .dsts) ?? []
        caps = try container.decodeIfPresent([String].self, forKey: .caps) ?? []
        capMap = try container.decodeCapMapIfPresent(forKey: .capMap) ?? [:]
    }
}
