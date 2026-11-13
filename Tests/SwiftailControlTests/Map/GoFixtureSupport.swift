import Foundation
import SwiftailControl
import Testing

// 비교하지 못하는 표현은 여기서만 제외한다.
// - DNSConfig.Nameservers: 계약에서 제외한 구 필드이며 공개 DNSConfig에 없다.
// - Node.CapMap의 null/{} 및 각 인자의 null/[]: 공개 타입이 이미 합친다. 키와 실제 인자는 비교한다.
// - Node.LastSeen·KeyExpiry의 원래 오프셋과 나노초: Date가 보존하지 않는다. 순간을 1µs 이내로 비교한다.
// ControlTime은 애초에 Go 자료의 투영 대상이 아니다.

/// Double을 거치지 않는 시험 전용 JSON. 불·숫자·null·빈 컨테이너와 키 존재를 구분한다.
indirect enum GoFixtureJSON: Codable, Sendable, Equatable, CustomStringConvertible {
    case null, bool(Bool), number(Decimal), string(String)
    case array([Self]), object([String: Self])
    // 투영한 시각은 Decimal로 왕복하지 않아 Date의 정밀도를 그대로 보존한다.
    case instant(Date)

    init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Decimal.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([Self].self) { self = .array(v) }
        else { self = .object(try c.decode([String: Self].self)) }
    }

    func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        case .instant(let v): try c.encode("Unix초: \(v.timeIntervalSince1970)")
        }
    }

    var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(self) else { return "<부호화 실패>" }
        return String(decoding: data, as: UTF8.self)
    }

    func field<T: Decodable>(_ key: String, default fallback: T) throws -> T {
        guard case .object(let fields) = self, let value = fields[key], value != .null else { return fallback }
        return try JSONDecoder().decode(T.self, from: JSONEncoder().encode(value))
    }

    static func integer(_ value: some BinaryInteger) -> Self {
        // 정수의 십진 문자열을 사용해 큰 ID를 부동소수점으로 바꾸지 않는다.
        .number(Decimal(string: String(value)) ?? 0)
    }

    static func strings(_ values: [String]) -> Self { .array(values.map(Self.string)) }
}

struct GoMapScenario: Decodable, Sendable, CustomStringConvertible {
    struct Step: Decodable, Sendable {
        let name: String
        let response: String
        let netmap: GoFixtureJSON
    }
    let name: String
    let steps: [Step]
    var description: String { name }
}

struct GoRequestCase: Decodable, Sendable, CustomStringConvertible {
    let name: String
    let type: String
    let input: GoFixtureJSON
    let json: String
    var description: String { name }
}

func loadGoFixtures<T: Decodable>(_ name: String, as: T.Type) throws -> T {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
}

func goFixtureDate(_ text: String) throws -> Date {
    // 구현의 GoTime을 사용하지 않고 Foundation으로 독립 해독한다.
    // Foundation의 역사적 달력 전환 영향을 피한다. Go zero 시각은 전향 그레고리력의 Unix초로 고정한다.
    if text == "0001-01-01T00:00:00Z" { return Date(timeIntervalSince1970: -62_135_596_800) }
    let style = Date.ISO8601FormatStyle(includingFractionalSeconds: text.contains("."))
    return try style.parse(text)
}

/// 객체 키는 정렬해 순서 없이, 배열은 자료 순서 그대로, 나머지는 타입까지 비교한다.
func compareGoJSON(_ expected: GoFixtureJSON?, _ actual: GoFixtureJSON?, context: String,
                   path: String = "$", netmap: Bool = false) throws {
    if netmap, path == "$.DNSConfig.Nameservers" { return }
    if netmap, path.hasSuffix(".LastSeen") || path.hasSuffix(".KeyExpiry"),
       case .string(let text) = expected, case .instant(let actualDate) = actual {
        let expectedDate = try goFixtureDate(text)
        let difference = abs(expectedDate.timeIntervalSince(actualDate))
        #expect(difference <= 0.000_001,
                "\(context) \(path): 기대=\(text), 실제=\(actualDate.timeIntervalSince1970) (Unix초), 차이=\(difference)초")
        return
    }
    if case .object(let lhs) = expected, case .object(let rhs) = actual {
        for key in Set(lhs.keys).union(rhs.keys).sorted() {
            try compareGoJSON(lhs[key], rhs[key], context: context, path: path + "." + key, netmap: netmap)
        }
    } else if case .array(let lhs) = expected, case .array(let rhs) = actual {
        #expect(lhs.count == rhs.count, "\(context) \(path).count: 기대=\(lhs.count), 실제=\(rhs.count)")
        for index in 0..<max(lhs.count, rhs.count) {
            try compareGoJSON(index < lhs.count ? lhs[index] : nil, index < rhs.count ? rhs[index] : nil,
                              context: context, path: "\(path)[\(index)]", netmap: netmap)
        }
    } else {
        #expect(expected == actual,
                "\(context) \(path): 기대=\(expected?.description ?? "<키 없음>"), 실제=\(actual?.description ?? "<키 없음>")")
    }
}

/// 공개 Netmap을 README의 투영으로 옮긴다. 상태를 보충하거나 증분 규칙을 다시 적용하지 않는다.
func projectGoNetmap(_ map: Netmap) -> GoFixtureJSON {
    .object([
        "SelfNode": projectGoNode(map.selfNode),
        // Swift가 정렬했는지도 검사하므로 시험에서 다시 정렬하지 않는다.
        "Peers": .array(map.peers.map(projectGoNode)),
        "DERPMap": map.derpMap.map(projectGoDERP) ?? .null,
        // Go의 초기 DNS는 zero 객체다. Swift의 미수신 nil도 이 투영에서는 zero로 옮긴다.
        "DNSConfig": map.dnsConfig.map(projectGoDNS) ?? .object([:]),
        "PacketFilter": .array(map.packetFilter.map(projectGoFilter)),
        "UserProfiles": .object(Dictionary(uniqueKeysWithValues: map.userProfiles.map { id, p in
            var fields: [String: GoFixtureJSON] = ["ID": .integer(p.id), "DisplayName": .string(p.displayName)]
            if !p.loginName.isEmpty { fields["LoginName"] = .string(p.loginName) }
            if !p.profilePicURL.isEmpty { fields["ProfilePicURL"] = .string(p.profilePicURL) }
            return (String(id), .object(fields))
        })),
        "Domain": .string(map.domain), "TKAEnabled": .bool(map.tailnetLockEnabled)
    ])
}

private func projectGoNode(_ node: Node) -> GoFixtureJSON {
    func time(_ date: Date?) -> GoFixtureJSON {
        date.map(GoFixtureJSON.instant) ?? .null
    }
    return .object([
        "ID": .integer(node.id), "StableID": .string(node.stableID), "Name": .string(node.name),
        "Key": .string(node.key.description), "DiscoKey": .string(node.discoKey.description),
        "Addresses": .strings(node.addresses.map(\.description)),
        "AllowedIPs": .strings(node.allowedIPs.map(\.description)),
        "Endpoints": .strings(node.endpoints.map(\.description)),
        "HomeDERP": .integer(node.homeDERP), "Online": node.online.map(GoFixtureJSON.bool) ?? .null,
        "LastSeen": time(node.lastSeen),
        "KeyExpiry": time(node.keyExpiry ?? Date(timeIntervalSince1970: -62_135_596_800)),
        "Expired": .bool(node.expired), "Cap": .integer(node.cap),
        "CapMap": .object(node.capMap.mapValues { .array($0.map(projectGoRawJSON)) }),
        "User": .integer(node.user), "Sharer": .integer(node.sharer),
        "MachineAuthorized": .bool(node.machineAuthorized)
    ])
}

private func projectGoRawJSON(_ value: JSONValue) -> GoFixtureJSON {
    switch value {
    case .null: .null
    case .bool(let v): .bool(v)
    case .number(let v): .number(Decimal(v))
    case .string(let v): .string(v)
    case .array(let v): .array(v.map(projectGoRawJSON))
    case .object(let v): .object(v.mapValues(projectGoRawJSON))
    }
}

/// 공개 타입에서 잃어버린 CapMap 표현만 맞춘다(대상 필드 목록은 파일 머리).
func comparableGoNetmap(_ value: GoFixtureJSON) -> GoFixtureJSON {
    guard case .object(var fields) = value else { return value }
    func node(_ value: GoFixtureJSON) -> GoFixtureJSON {
        guard case .object(var fields) = value else { return value }
        if case .object(let caps) = fields["CapMap"] {
            fields["CapMap"] = .object(caps.mapValues { $0 == .null ? .array([]) : $0 })
        } else if fields["CapMap"] == .null {
            fields["CapMap"] = .object([:])
        }
        return .object(fields)
    }
    if let selfNode = fields["SelfNode"] { fields["SelfNode"] = node(selfNode) }
    if case .array(let peers) = fields["Peers"] { fields["Peers"] = .array(peers.map(node)) }
    return .object(fields)
}

private func projectGoDERP(_ map: DERPMap) -> GoFixtureJSON {
    var fields: [String: GoFixtureJSON] = ["Regions": map.regions.map { regions in
        .object(Dictionary(uniqueKeysWithValues: regions.map { id, region in
            var fields: [String: GoFixtureJSON] = [
                "RegionID": .integer(region.regionID), "RegionCode": .string(region.regionCode),
                "RegionName": .string(region.regionName), "Nodes": .array(region.nodes.map { node in
                    var fields: [String: GoFixtureJSON] = ["Name": .string(node.name),
                        "RegionID": .integer(node.regionID), "HostName": .string(node.hostName)]
                    for (key, value) in [("CertName", node.certName), ("IPv4", node.ipv4),
                                         ("IPv6", node.ipv6), ("STUNTestIP", node.stunTestIP)] where !value.isEmpty {
                        fields[key] = .string(value)
                    }
                    for (key, value) in [("STUNPort", node.stunPort), ("DERPPort", node.derpPort)] where value != 0 {
                        fields[key] = .integer(value)
                    }
                    for (key, value) in [("STUNOnly", node.stunOnly), ("InsecureForTests", node.insecureForTests),
                                         ("CanPort80", node.canPort80)] where value { fields[key] = .bool(true) }
                    return .object(fields)
                })]
            if region.noMeasureNoHome { fields["NoMeasureNoHome"] = .bool(true) }
            return (String(id), .object(fields))
        }))
    } ?? .null]
    if map.omitDefaultRegions { fields["omitDefaultRegions"] = .bool(true) }
    if let home = map.homeParams {
        let scores = home.regionScore ?? [:]
        fields["HomeParams"] = .object(scores.isEmpty ? [:] : ["RegionScore": .object(
            Dictionary(uniqueKeysWithValues: scores.map { (String($0.key), .number(Decimal($0.value))) }))])
    }
    return .object(fields)
}

private func projectGoDNS(_ config: DNSConfig) -> GoFixtureJSON {
    func resolver(_ r: DNSResolver) -> GoFixtureJSON {
        var fields: [String: GoFixtureJSON] = ["Addr": .string(r.addr)]
        if !r.bootstrapResolution.isEmpty { fields["BootstrapResolution"] = .strings(r.bootstrapResolution.map(\.description)) }
        return .object(fields)
    }
    var fields: [String: GoFixtureJSON] = [:]
    for (key, values) in [("Resolvers", config.resolvers), ("FallbackResolvers", config.fallbackResolvers)] where !values.isEmpty {
        fields[key] = .array(values.map(resolver))
    }
    if !config.routes.isEmpty { fields["Routes"] = .object(config.routes.mapValues { .array($0.map(resolver)) }) }
    if !config.domains.isEmpty { fields["Domains"] = .strings(config.domains) }
    if !config.certDomains.isEmpty { fields["CertDomains"] = .strings(config.certDomains) }
    if config.proxied { fields["Proxied"] = .bool(true) }
    if !config.extraRecords.isEmpty {
        fields["ExtraRecords"] = .array(config.extraRecords.map { record in
            var fields: [String: GoFixtureJSON] = ["Name": .string(record.name), "Value": .string(record.value)]
            if !record.type.isEmpty { fields["Type"] = .string(record.type) }
            return .object(fields)
        })
    }
    return .object(fields)
}

private func projectGoFilter(_ rule: FilterRule) -> GoFixtureJSON {
    var fields: [String: GoFixtureJSON] = ["SrcIPs": .strings(rule.srcIPs)]
    if !rule.srcBits.isEmpty { fields["SrcBits"] = .array(rule.srcBits.map { .integer($0) }) }
    if !rule.ipProto.isEmpty { fields["IPProto"] = .array(rule.ipProto.map { .integer($0) }) }
    if !rule.dstPorts.isEmpty {
        fields["DstPorts"] = .array(rule.dstPorts.map { range in
            var fields: [String: GoFixtureJSON] = ["IP": .string(range.ip), "Ports": .object([
                "First": .integer(range.ports.first), "Last": .integer(range.ports.last)])]
            if let bits = range.bits { fields["Bits"] = .integer(bits) }
            return .object(fields)
        })
    }
    if !rule.capGrant.isEmpty {
        fields["CapGrant"] = .array(rule.capGrant.map { grant in
            var fields: [String: GoFixtureJSON] = ["Dsts": .strings(grant.dsts.map(\.description))]
            if !grant.caps.isEmpty { fields["Caps"] = .strings(grant.caps) }
            if !grant.capMap.isEmpty { fields["CapMap"] = .object(grant.capMap.mapValues { .array($0.map(projectGoRawJSON)) }) }
            return .object(fields)
        })
    }
    return .object(fields)
}
