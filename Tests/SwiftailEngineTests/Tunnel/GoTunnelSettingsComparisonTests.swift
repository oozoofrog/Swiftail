// Independent comparison with Go tunnel settings computation.
//
// The fixture (`tunnel-settings-fixtures.json`) contains values from actual runs of Go's `LocalBackend.authReconfigLocked`, `routemanager`, and `dns.Manager(ios)`.
// Each step's `input` is a separate, complete netmap, and `settings` narrows the Go result to the form of contract behavior S
// (applying only S1, S4, S5, and D1–D3). This test builds a `Netmap` from `input` and compares the result of `TunnelNetworkSettings(netmap:mtu:at:)`
// with `settings`. Expected values are independent of the implementation's internals.
//
// Fixture-to-netmap conversion follows the input description in the README's "tunnelfixtures" section.
// - Copy the node table's `addresses`, `allowedIPs` (CIDR), `expired`, and `keyExpiry` directly to `Addresses`, `AllowedIPs`, `Expired`, and `KeyExpiry`.
// - The fixture provides no disco key, and `homeDERP` determines data plane candidacy (README). Include a fixed
//   disco key and home DERP only for peers with `homeDERP != 0`. At 0, omit both (Go also excludes the peer as a candidate).
// - `input.dnsConfig` is control `tailcfg.DNSConfig` JSON, so copy it into `DNSConfig` as is. Put the keys from `input.capMap`
//   into the local node's `CapMap` (Go emits `null` values).
// - Use `now` at the head of the fixture (`2026-01-02T03:04:05Z`) as the map response receipt time and for `at:`.
//
// Difference markers
// - Steps without `swiftailDiffers` must match Go. Also verify that `settings` matches the original Go result.
// - For marked steps, compare with `settings` (the contract expectation) and separately verify that applying the contract sections
//   named in the reason string (D1–D3, S1, S4, S5) to the original `go` result yields the same value using a computation independent of the fixture tool.
// - Remaining unmarked difference. Go's route computation keeps peers with `Expired=false` when only their `KeyExpiry` has passed
//   (RouteManager `peerViewOf` checks only `Expired`). In Go's full flow, `ipn/ipnlocal/expiry.go` (`flagExpiredPeers`)
//   marks peers whose `KeyExpiry` has passed as `Expired=true` before computing routes. Swiftail itself excludes peers with
//   `keyExpiry <= now` under contract behavior S2 (`EnginePeer.peers(in:at:)`, engine contract M3 behavior 2), so this step expects `settings`
//   with that peer's routes removed (`lapsedPeerRoutes`).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("Independent comparison with Go tunnel settings computation")
struct GoTunnelSettingsComparisonTests {
    @Test("The same netmap input yields the same settings (addresses, routes, and DNS)", arguments: try loadGoTunnelFixture().scenarios)
    func compareSettings(_ scenario: GoTunnelScenario) throws {
        let fixture = try loadGoTunnelFixture()
        let now = try parseGoFixtureDate(fixture.now)
        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) step \(index + 1) [\(step.name)]"
            let netmap = try makeNetmap(step.input, now: now)
            let actual = TunnelNetworkSettings(netmap: netmap, mtu: step.input.mtu, at: now).map(GoSettingsValue.init)
            let expected = try swiftailExpectation(step, scenario: scenario, now: now, context: context)
            let differences = Self.differences(expected: expected, actual: actual)
            #expect(differences.isEmpty, "\(context): \(differences.joined(separator: "; "))")
        }
    }

    @Test("Fixture settings match the original Go result, with marked differences matching the result of applying the contract sections to Go")
    func verifyFixtureConsistency() throws {
        for scenario in try loadGoTunnelFixture().scenarios {
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) step \(index + 1) [\(step.name)]"
                // Applying the contract sections to the original Go result must yield `settings` regardless of markers.
                let derived = Self.contractSettings(fromGo: step.go)
                let differences = Self.differences(expected: step.settings, actual: derived)
                #expect(differences.isEmpty, "\(context), expected settings, got the contract applied to the original Go result (\(differences.joined(separator: "; ")))")

                guard let reason = step.swiftailDiffers else {
                    // An unmarked step should compare directly against the original Go result.
                    if let settings = step.settings {
                        #expect(step.go.addresses == settings.addresses, "\(context), expected Go addresses \(step.go.addresses), got settings \(settings.addresses)")
                        #expect(step.go.routes == settings.routes, "\(context), expected Go routes \(step.go.routes), got settings \(settings.routes)")
                        #expect(step.go.dns.servers == settings.dnsServers, "\(context), expected Go DNS servers \(step.go.dns.servers), got settings \(settings.dnsServers)")
                        #expect(step.go.dns.matchDomains == settings.dnsMatchDomains, "\(context), expected Go match domains, got settings (counts \(step.go.dns.matchDomains.count) vs. \(settings.dnsMatchDomains.count))")
                    }
                    continue
                }
                try Self.checkReason(reason, step: step, context: context)
            }
        }
    }

    @Test("Verify the fixture reference version and scenario, step, and marker counts")
    func verifyFixtureCoverage() throws {
        let fixture = try loadGoTunnelFixture()
        #expect(fixture.reference == "tailscale.com v1.104.6")
        #expect(fixture.now == "2026-01-02T03:04:05Z")
        #expect(fixture.baseResolvers == ["192.0.2.54"])
        #expect(fixture.scenarioCount == 27)
        #expect(fixture.scenarios.count == 27)
        #expect(Set(fixture.scenarios.map(\.name)).count == fixture.scenarios.count)
        let steps = fixture.scenarios.flatMap(\.steps)
        #expect(fixture.stepCount == 32)
        #expect(steps.count == 32)
        #expect(steps.filter { $0.swiftailDiffers != nil }.count == 16)
        #expect(steps.filter { $0.settings == nil }.count == 1)
        for scenario in fixture.scenarios {
            #expect(!scenario.steps.isEmpty, "\(scenario.name), expected steps, got none")
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) step \(index + 1)"
                #expect(step.input.mtu == 1280, "\(context), expected MTU 1280, got \(step.input.mtu)")
                #expect(step.input.routeAll == false, "\(context), expected routeAll false, got \(step.input.routeAll)")
                #expect(step.input.exitNode.isEmpty, "\(context), expected no exit node, got \(step.input.exitNode)")
                if let reason = step.swiftailDiffers { #expect(!reason.isEmpty, "\(context), expected a reason for the difference, got an empty string") }
            }
        }
    }

    // MARK: - Expected values

    /// The value Swiftail should produce. Use `settings` for unmarked steps (the Go result) and for marked steps (the contract expectation).
    /// Only for the remaining unmarked difference (peers whose `KeyExpiry` has passed), remove their routes from `settings`.
    private func swiftailExpectation(
        _ step: GoTunnelStep, scenario: GoTunnelScenario, now: Date, context: String
    ) throws -> GoSettingsValue? {
        guard var expected = step.settings else { return nil }
        let lapsed = try Self.lapsedPeerRoutes(step.input, now: now)
        guard !lapsed.isEmpty else { return expected }
        // Go keeps routes for peers with a past KeyExpiry and Expired=false, while Swiftail removes them (see the file header).
        #expect(step.swiftailDiffers == nil, "\(context), expected an unmarked difference, got a marker")
        for route in lapsed {
            #expect(expected.routes.contains(route), "\(context), expected \(route) among Go routes, got \(expected.routes)")
        }
        expected.routes.removeAll { lapsed.contains($0) }
        return expected
    }

    /// Candidate routes (`allowedIPs`) for peers with `Expired=false` and `KeyExpiry <= now`.
    private static func lapsedPeerRoutes(_ input: GoTunnelInput, now: Date) throws -> [String] {
        try input.peers.filter { peer in
            guard !peer.expired, let text = peer.keyExpiry else { return false }
            return try parseGoFixtureDate(text) <= now
        }.flatMap(\.allowedIPs)
    }

    // MARK: - Netmap conversion

    private func makeNetmap(_ input: GoTunnelInput, now: Date) throws -> Netmap {
        func node(_ value: GoTunnelNode, isSelf: Bool) -> GoFixtureNode {
            GoFixtureNode(
                id: value.id, name: value.name, addresses: value.addresses, allowedIPs: value.allowedIPs,
                expired: value.expired, keyExpiry: value.keyExpiry, reachable: !isSelf && value.homeDERP != 0,
                capabilities: isSelf ? input.capMap.keys.sorted() : [])
        }
        return try makeGoFixtureNetmap(
            selfNode: node(input.selfNode, isSelf: true), peers: input.peers.map { node($0, isSelf: false) },
            dnsConfigJSON: try input.dnsConfig.json, receivedAt: now)
    }

    // MARK: - Comparison

    private static func differences(expected: GoSettingsValue?, actual: GoSettingsValue?) -> [String] {
        switch (expected, actual) {
        case (nil, nil): return []
        case (nil, let actual?): return ["Expected nil (no local address), got settings \(actual.addresses)"]
        case (let expected?, nil): return ["Expected settings \(expected.addresses), got nil"]
        case (let expected?, let actual?):
            var result: [String] = []
            if expected.addresses != actual.addresses { result.append("Addresses expected \(expected.addresses), got \(actual.addresses)") }
            if expected.routes != actual.routes { result.append("Routes expected \(expected.routes), got \(actual.routes)") }
            if expected.dnsServers != actual.dnsServers { result.append("DNS servers expected \(expected.dnsServers), got \(actual.dnsServers)") }
            if expected.dnsMatchDomains != actual.dnsMatchDomains {
                let missing = Set(expected.dnsMatchDomains).subtracting(actual.dnsMatchDomains).sorted()
                let extra = Set(actual.dnsMatchDomains).subtracting(expected.dnsMatchDomains).sorted()
                result.append("Match domains expected \(expected.dnsMatchDomains.count), got \(actual.dnsMatchDomains.count) (missing \(missing), extra \(extra), order \(Set(expected.dnsMatchDomains) == Set(actual.dnsMatchDomains) ? "differs" : "matches"))")
            }
            if expected.mtu != actual.mtu { result.append("MTU expected \(expected.mtu), got \(actual.mtu)") }
            return result
        }
    }

    // MARK: - Applying the contract to the original Go result

    /// Applies only the contract's policies to the original Go result, using a computation independent of the fixture tool.
    /// - S1: Return nil if there is no local address.
    /// - S4 and S5: Omit routes and DNS servers for families without a local address.
    /// - D1 and D2: DNS match domains come only from the actual Go resolver's `LocalDomains`. No DNS if empty. Servers are the service IPs.
    /// - D3: Settings contain no search domains.
    private static func contractSettings(fromGo go: GoTunnelGo) -> GoSettingsValue? {
        let addresses = go.addresses.filter { $0.hasSuffix("/32") || $0.hasSuffix("/128") }
        guard !addresses.isEmpty else { return nil }
        let hasIPv4 = addresses.contains { !$0.contains(":") }
        let hasIPv6 = addresses.contains { $0.contains(":") }
        func keepsFamily(_ text: String) -> Bool { text.contains(":") ? hasIPv6 : hasIPv4 }

        let zones = go.dns.localDomains.sorted { ($0 + ".").utf8.lexicographicallyPrecedes(($1 + ".").utf8) }
        let servers = zones.isEmpty ? [] : go.dns.servers.filter(keepsFamily)
        return GoSettingsValue(
            addresses: addresses, routes: go.routes.filter(keepsFamily), dnsServers: servers, dnsMatchDomains: zones, mtu: 1280)
    }

    /// Verifies that each contract section cited by the marker reason corresponds to a difference in the original Go result (that the reason is true).
    private static func checkReason(_ reason: String, step: GoTunnelStep, context: String) throws {
        let tags = Set(reason.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
            .filter { $0.count == 2 && ($0.hasPrefix("D") || $0.hasPrefix("S")) && $0.last?.isNumber == true })
        #expect(!tags.isEmpty, "\(context), expected contract section IDs in the reason (D1–D3, S1, S4, S5), got \(reason)")
        let known: Set<String> = ["D1", "D2", "D3", "S1", "S4", "S5"]
        let go = step.go
        let settings = step.settings
        let selfHasIPv4 = go.addresses.contains { !$0.contains(":") }
        let selfHasIPv6 = go.addresses.contains { $0.contains(":") }
        for tag in tags.sorted() {
            #expect(known.contains(tag), "\(context), expected a section in the contract, got \(tag)")
            switch tag {
            case "D3":
                #expect(!go.dns.searchDomains.isEmpty, "\(context), expected Go search domains (D3), got \(go.dns.searchDomains)")
            case "S4", "S5":
                // The fixture reason groups "S4·S5" together. Either a route or a DNS server is sufficient.
                let foreign = go.routes.contains { $0.contains(":") ? !selfHasIPv6 : !selfHasIPv4 }
                    || go.dns.servers.contains { $0.contains(":") ? !selfHasIPv6 : !selfHasIPv4 }
                #expect(foreign, "\(context), expected a family without a local address in Go routes or DNS servers (\(tag)), got \(go.routes) \(go.dns.servers)")
            case "D1", "D2":
                let narrowed = go.dns.servers != (settings?.dnsServers ?? []) || go.dns.matchDomains != (settings?.dnsMatchDomains ?? [])
                #expect(narrowed, "\(context), expected Go DNS and settings to differ (D1 and D2), got matching values")
            case "S1":
                #expect(settings == nil, "\(context), expected nil settings (S1), got settings")
            default:
                break
            }
        }
    }
}

// MARK: - Fixture models

private func loadGoTunnelFixture() throws -> GoTunnelFixture {
    try JSONDecoder().decode(GoTunnelFixture.self, from: loadGoFixtureData("tunnel-settings-fixtures"))
}

struct GoTunnelFixture: Decodable, Sendable {
    let reference: String
    let scenarioCount: Int
    let stepCount: Int
    let now: String
    let baseResolvers: [String]
    let scenarios: [GoTunnelScenario]
}

struct GoTunnelScenario: Decodable, Sendable, CustomTestStringConvertible {
    let name: String
    let steps: [GoTunnelStep]
    var testDescription: String { name }
}

struct GoTunnelStep: Decodable, Sendable {
    let name: String
    let input: GoTunnelInput
    let go: GoTunnelGo
    /// The Go result narrowed to the form of contract S. Nil if there is no local address.
    let settings: GoSettingsValue?
    let swiftailDiffers: String?
}

struct GoTunnelInput: Decodable, Sendable {
    let selfNode: GoTunnelNode
    let peers: [GoTunnelNode]
    let dnsConfig: GoRawJSON
    let capMap: [String: GoRawJSON]
    let routeAll: Bool
    let exitNode: String
    let mtu: Int

    enum CodingKeys: String, CodingKey {
        case peers, dnsConfig, capMap, routeAll, exitNode, mtu
        case selfNode = "self"
    }
}

struct GoTunnelNode: Decodable, Sendable {
    let id: Int64
    let name: String
    let addresses: [String]
    let allowedIPs: [String]
    let expired: Bool
    let keyExpiry: String?
    let homeDERP: Int
}

struct GoTunnelGo: Decodable, Sendable {
    let addresses: [String]
    let peerRoutes: [String]
    let routes: [String]
    let dns: GoTunnelGoDNS
}

struct GoTunnelGoDNS: Decodable, Sendable {
    let servers: [String]
    let matchDomains: [String]
    let searchDomains: [String]
    let localDomains: [String]
}

/// Settings in the form specified by the contract. Allows comparison of fixture values and `TunnelNetworkSettings` in the same string representation.
struct GoSettingsValue: Decodable, Equatable, Sendable {
    var addresses: [String]
    var routes: [String]
    var dnsServers: [String]
    var dnsMatchDomains: [String]
    var mtu: Int

    init(addresses: [String], routes: [String], dnsServers: [String], dnsMatchDomains: [String], mtu: Int) {
        self.addresses = addresses
        self.routes = routes
        self.dnsServers = dnsServers
        self.dnsMatchDomains = dnsMatchDomains
        self.mtu = mtu
    }

    init(_ settings: TunnelNetworkSettings) {
        addresses = settings.addresses.map(\.description)
        routes = settings.routes.map(\.description)
        dnsServers = settings.dnsServers.map(\.description)
        dnsMatchDomains = settings.dnsMatchDomains
        mtu = settings.mtu
    }
}

/// An arbitrary JSON value used to emit `input.dnsConfig` unchanged.
enum GoRawJSON: Codable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([GoRawJSON])
    case object([String: GoRawJSON])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([GoRawJSON].self) { self = .array(value) }
        else { self = .object(try container.decode([String: GoRawJSON].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// JSON text with sorted keys.
    var json: String {
        get throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            return String(decoding: try encoder.encode(self), as: UTF8.self)
        }
    }
}
