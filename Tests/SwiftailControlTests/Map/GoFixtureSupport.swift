import Foundation
import SwiftailControl
import Testing

// This is the only place that excludes representations that cannot be compared.
// - DNSConfig.Nameservers: A legacy field excluded by the contract and absent from the public DNSConfig.
// - Node.CapMap null/{} and null/[] for each argument: The public type already treats them alike. Compare the keys and actual arguments.
// - Original offset and nanoseconds in Node.LastSeen and KeyExpiry: Date does not preserve them. Compare instants within 1µs.
// ControlTime is outside the scope of the Go fixture projection.

/// Test-only JSON that avoids Double. Distinguishes Booleans, numbers, null, empty containers, and key presence.
indirect enum GoFixtureJSON: Codable, Sendable, Equatable, CustomStringConvertible {
    case null, bool(Bool), number(Decimal), string(String)
    case array([Self]), object([String: Self])
    // Projected instants avoid a round trip through Decimal, preserving Date's precision.
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
        case .instant(let v): try c.encode("Unix seconds: \(v.timeIntervalSince1970)")
        }
    }

    var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(self) else { return "<encoding failed>" }
        return String(decoding: data, as: UTF8.self)
    }

    func field<T: Decodable>(_ key: String, default fallback: T) throws -> T {
        guard case .object(let fields) = self, let value = fields[key], value != .null else { return fallback }
        return try JSONDecoder().decode(T.self, from: JSONEncoder().encode(value))
    }

    static func integer(_ value: some BinaryInteger) -> Self {
        // Uses decimal strings for integers to avoid converting large IDs to floating point.
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
    // Independently decodes with Foundation without using the implementation's GoTime.
    // Avoids Foundation's historical calendar transition. Fixes the Go zero time at its proleptic Gregorian value in Unix seconds.
    if text == "0001-01-01T00:00:00Z" { return Date(timeIntervalSince1970: -62_135_596_800) }
    let style = Date.ISO8601FormatStyle(includingFractionalSeconds: text.contains("."))
    return try style.parse(text)
}

/// Sorts object keys for order-independent comparison, preserves fixture order for arrays, and compares types as well for everything else.
func compareGoJSON(_ expected: GoFixtureJSON?, _ actual: GoFixtureJSON?, context: String,
                   path: String = "$", netmap: Bool = false) throws {
    if netmap, path == "$.DNSConfig.Nameservers" { return }
    if netmap, path.hasSuffix(".LastSeen") || path.hasSuffix(".KeyExpiry"),
       case .string(let text) = expected, case .instant(let actualDate) = actual {
        let expectedDate = try goFixtureDate(text)
        let difference = abs(expectedDate.timeIntervalSince(actualDate))
        #expect(difference <= 0.000_001,
                "\(context) \(path): expected=\(text), actual=\(actualDate.timeIntervalSince1970) (Unix seconds), difference=\(difference) seconds")
        return
    }
    if case .object(let lhs) = expected, case .object(let rhs) = actual {
        for key in Set(lhs.keys).union(rhs.keys).sorted() {
            try compareGoJSON(lhs[key], rhs[key], context: context, path: path + "." + key, netmap: netmap)
        }
    } else if case .array(let lhs) = expected, case .array(let rhs) = actual {
        #expect(lhs.count == rhs.count, "\(context) \(path).count: expected=\(lhs.count), actual=\(rhs.count)")
        for index in 0..<max(lhs.count, rhs.count) {
            try compareGoJSON(index < lhs.count ? lhs[index] : nil, index < rhs.count ? rhs[index] : nil,
                              context: context, path: "\(path)[\(index)]", netmap: netmap)
        }
    } else {
        #expect(expected == actual,
                "\(context) \(path): expected=\(expected?.description ?? "<missing key>"), actual=\(actual?.description ?? "<missing key>")")
    }
}

/// Converts the public Netmap to the projection in the README. Does not fill in state or reapply delta rules.
/// Go's `TKAEnabled` is in the server's lock state, which the session emits separately (`MapSession.Update.serverLock`), outside the netmap.
func projectGoNetmap(_ map: Netmap, tkaEnabled: Bool) -> GoFixtureJSON {
    .object([
        "SelfNode": projectGoNode(map.selfNode),
        // Do not sort again in the test because it also checks whether Swift sorted the values.
        "Peers": .array(map.peers.map(projectGoNode)),
        "DERPMap": map.derpMap.map(projectGoDERP) ?? .null,
        // Go starts with a zero DNS object. In this projection, Swift's nil before receiving DNS also maps to zero.
        "DNSConfig": map.dnsConfig.map(projectGoDNS) ?? .object([:]),
        "PacketFilter": .array(map.packetFilter.map(projectGoFilter)),
        "UserProfiles": .object(Dictionary(uniqueKeysWithValues: map.userProfiles.map { id, p in
            var fields: [String: GoFixtureJSON] = ["ID": .integer(p.id), "DisplayName": .string(p.displayName)]
            if !p.loginName.isEmpty { fields["LoginName"] = .string(p.loginName) }
            if !p.profilePicURL.isEmpty { fields["ProfilePicURL"] = .string(p.profilePicURL) }
            return (String(id), .object(fields))
        })),
        "Domain": .string(map.domain), "TKAEnabled": .bool(tkaEnabled)
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
    case .integer(let v): .integer(v)
    case .unsignedInteger(let v): .integer(v)
    case .number(let v): .number(Decimal(v))
    case .string(let v): .string(v)
    case .array(let v): .array(v.map(projectGoRawJSON))
    case .object(let v): .object(v.mapValues(projectGoRawJSON))
    }
}

/// Aligns only the CapMap representations lost in the public type (the file header lists the affected fields).
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
