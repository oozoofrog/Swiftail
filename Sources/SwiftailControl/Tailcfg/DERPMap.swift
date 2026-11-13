/// DERP 중계 서버의 지도. Go `tailcfg.DERPMap`. 맵 응답의 `DERPMap`으로 온다.
///
/// 증분에서는 하위 필드마다 "그대로"가 있다(노트 4.3의 8, `MapSession`이 적용한다).
/// - `regions`: `nil`(키 없음·`null`)이면 이전 지역 목록과 `omitDefaultRegions`를 그대로 둔다.
///   빈 객체는 "지역 없음"이다. 해독할 때 값이 `null`인 지역은 버린다(Go 클라이언트도 지운다).
/// - `homeParams`: `nil`이면 이전 것을 그대로 둔다.
///
/// `docs/protocol-notes/control-map.md` 3.7 (출처: tailscale.com `tailcfg/derpmap.go`).
public struct DERPMap: Decodable, Sendable, Equatable {
    /// 홈 지역을 고를 때의 가중치. `nil`이면 이전 것을 그대로 둔다.
    public internal(set) var homeParams: DERPHomeParams?
    /// 지역 ID → 지역. `nil`이면 이전 것을 그대로 둔다.
    public internal(set) var regions: [Int64: DERPRegion]?
    /// 클라이언트가 내장 기본 지역을 쓰지 말아야 한다. `regions`가 있을 때만 뜻이 있다.
    public internal(set) var omitDefaultRegions: Bool

    private enum CodingKeys: String, CodingKey {
        case homeParams = "HomeParams"
        case regions = "Regions"
        case omitDefaultRegions = "omitDefaultRegions"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        homeParams = try container.decodeIfPresent(DERPHomeParams.self, forKey: .homeParams)
        regions = try container.decodeIntegerKeyedIfPresent(DERPRegion?.self, forKey: .regions)?.compactMapValues { $0 }
        omitDefaultRegions = try container.decodeIfPresent(Bool.self, forKey: .omitDefaultRegions) ?? false
    }
}

/// 홈 DERP 지역 선택의 가중치. Go `tailcfg.DERPHomeParams`.
public struct DERPHomeParams: Decodable, Sendable, Equatable {
    /// 지역 ID → 지연에 곱할 배수. 없는 지역은 1.0, 0 이하는 무시한다.
    /// `nil`이면 이전 점수를 그대로 두고, 빈 객체는 점수를 모두 지운다.
    public internal(set) var regionScore: [Int64: Double]?

    private enum CodingKeys: String, CodingKey {
        case regionScore = "RegionScore"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        regionScore = try container.decodeIntegerKeyedIfPresent(Double.self, forKey: .regionScore)
    }
}

/// DERP 지역 하나. 같은 지역의 서버들은 서로 중계를 나눈다. Go `tailcfg.DERPRegion`.
public struct DERPRegion: Decodable, Sendable, Equatable {
    /// 지역 ID. `DERPMap.regions`의 키와 같다.
    public internal(set) var regionID: Int64
    /// 짧은 지역 코드(`"nyc"`).
    public internal(set) var regionCode: String
    /// 사람이 읽는 지역 이름.
    public internal(set) var regionName: String
    /// 측정하지도 홈으로 고르지도 않는다. 피어의 홈이면 연결은 한다.
    public internal(set) var noMeasureNoHome: Bool
    /// 지역의 서버들. 앞의 것을 먼저 쓴다.
    public internal(set) var nodes: [DERPNode]

    private enum CodingKeys: String, CodingKey {
        case regionID = "RegionID"
        case regionCode = "RegionCode"
        case regionName = "RegionName"
        case noMeasureNoHome = "NoMeasureNoHome"
        case nodes = "Nodes"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        regionID = try container.decodeIfPresent(Int64.self, forKey: .regionID) ?? 0
        regionCode = try container.decodeIfPresent(String.self, forKey: .regionCode) ?? ""
        regionName = try container.decodeIfPresent(String.self, forKey: .regionName) ?? ""
        noMeasureNoHome = try container.decodeIfPresent(Bool.self, forKey: .noMeasureNoHome) ?? false
        nodes = try container.decodeIfPresent([DERPNode].self, forKey: .nodes) ?? []
    }
}

/// DERP 서버(또는 STUN 서버) 하나. Go `tailcfg.DERPNode`.
public struct DERPNode: Decodable, Sendable, Equatable {
    /// 서버 이름. 지역 안에서 고유하다.
    public internal(set) var name: String
    /// 속한 지역 ID.
    public internal(set) var regionID: Int64
    /// 접속할 호스트 이름.
    public internal(set) var hostName: String
    /// TLS 인증서에서 확인할 이름. 비면 `hostName`. `"sha256-raw:"`로 시작하면 인증서 해시 고정이다.
    public internal(set) var certName: String
    /// IPv4 주소 강제 지정. 빈 문자열은 DNS로 찾음, `"none"`은 IPv4를 쓰지 않음.
    public internal(set) var ipv4: String
    /// IPv6 주소 강제 지정. 규칙은 `ipv4`와 같다.
    public internal(set) var ipv6: String
    /// STUN 포트. 0은 3478, −1은 STUN 없음.
    public internal(set) var stunPort: Int
    /// STUN 전용 서버(DERP가 아님).
    public internal(set) var stunOnly: Bool
    /// DERP의 HTTPS 포트. 0은 443.
    public internal(set) var derpPort: Int
    /// 시험용: TLS 인증서를 검사하지 않는다.
    public internal(set) var insecureForTests: Bool
    /// 시험용 STUN 주소.
    public internal(set) var stunTestIP: String
    /// 80번 포트로 캡티브 포털 검사를 할 수 있다.
    public internal(set) var canPort80: Bool

    private enum CodingKeys: String, CodingKey {
        case name = "Name"
        case regionID = "RegionID"
        case hostName = "HostName"
        case certName = "CertName"
        case ipv4 = "IPv4"
        case ipv6 = "IPv6"
        case stunPort = "STUNPort"
        case stunOnly = "STUNOnly"
        case derpPort = "DERPPort"
        case insecureForTests = "InsecureForTests"
        case stunTestIP = "STUNTestIP"
        case canPort80 = "CanPort80"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        regionID = try container.decodeIfPresent(Int64.self, forKey: .regionID) ?? 0
        hostName = try container.decodeIfPresent(String.self, forKey: .hostName) ?? ""
        certName = try container.decodeIfPresent(String.self, forKey: .certName) ?? ""
        ipv4 = try container.decodeIfPresent(String.self, forKey: .ipv4) ?? ""
        ipv6 = try container.decodeIfPresent(String.self, forKey: .ipv6) ?? ""
        stunPort = try container.decodeIfPresent(Int.self, forKey: .stunPort) ?? 0
        stunOnly = try container.decodeIfPresent(Bool.self, forKey: .stunOnly) ?? false
        derpPort = try container.decodeIfPresent(Int.self, forKey: .derpPort) ?? 0
        insecureForTests = try container.decodeIfPresent(Bool.self, forKey: .insecureForTests) ?? false
        stunTestIP = try container.decodeIfPresent(String.self, forKey: .stunTestIP) ?? ""
        canPort80 = try container.decodeIfPresent(Bool.self, forKey: .canPort80) ?? false
    }
}
