// Go 터널 설정 산출과의 독립 대조 시험.
//
// 자료(`tunnel-settings-fixtures.json`)는 Go의 `LocalBackend.authReconfigLocked`·`routemanager`·`dns.Manager(ios)`를
// 실제로 돌려 얻은 값이다. 각 단계의 `input`은 독립된 전체 netmap이고, `settings`는 Go 결과를 계약 동작 S의 형태로
// 좁힌 것이다(S1·S4·S5·D1~D3만 적용). 이 시험은 `input`에서 `Netmap`을 만들어 `TunnelNetworkSettings(netmap:mtu:at:)`
// 의 결과를 `settings`와 견준다. 구현 안쪽을 보고 기대값을 정하지 않는다.
//
// 자료 → netmap 변환(README "tunnelfixtures"의 입력 설명을 따른다):
// - 노드 표의 `addresses`·`allowedIPs`(CIDR)·`expired`·`keyExpiry`를 그대로 `Addresses`·`AllowedIPs`·`Expired`·`KeyExpiry`로 옮긴다.
// - 자료는 disco 키를 주지 않고 `homeDERP`가 데이터면 후보 여부를 정한다(README). 그래서 `homeDERP != 0`인 피어에만 고정
//   disco 키와 홈 DERP를 싣는다. 0이면 둘 다 싣지 않는다(Go도 후보로 보지 않는 피어).
// - `input.dnsConfig`는 제어의 `tailcfg.DNSConfig` JSON이라 그대로 `DNSConfig` 필드로 싣는다. `input.capMap`의 키는
//   자기 노드의 `CapMap`(값은 Go가 내보낸 `null`)으로 싣는다.
// - 시각은 자료 머리의 `now`(`2026-01-02T03:04:05Z`)를 맵 응답 수신 시각과 `at:`에 쓴다.
//
// 표시 규칙:
// - `swiftailDiffers`가 없는 단계는 Go와 같아야 한다(`settings`가 Go 원본과 같다는 것도 확인한다).
// - 표시가 있는 단계는 `settings`(계약의 기대값)와 견주고, 이유 문자열이 가리키는 계약 절(D1~D3, S1·S4·S5)을 Go 원본
//   `go`에 적용해 같은 값이 나오는지 따로 확인한다(자료 도구와 독립된 계산).
// - 표시 없이 남은 차이: Go의 경로 산출은 `Expired=false`인 피어를 지난 `KeyExpiry`만으로는 빼지 않는다
//   (RouteManager `peerViewOf`는 `Expired`만 본다). Go의 전체 흐름에서는 `ipn/ipnlocal/expiry.go`(`flagExpiredPeers`)가
//   지난 `KeyExpiry`의 피어에 `Expired=true`를 먼저 단 뒤 경로를 뽑는다. Swiftail은 계약 동작 S2(`EnginePeer.peers(in:at:)`,
//   엔진 계약 M3 동작 2)에 따라 `keyExpiry <= now`인 피어를 스스로 뺀다. 그래서 이 단계는 `settings`에서 그 피어의 경로를
//   뺀 것을 기대값으로 둔다(`lapsedPeerRoutes`).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("Go 터널 설정 산출과의 독립 대조")
struct GoTunnelSettingsComparisonTests {
    @Test("같은 netmap 입력에서 설정(주소·경로·DNS)이 같다", arguments: try loadGoTunnelFixture().scenarios)
    func 설정을대조한다(_ scenario: GoTunnelScenario) throws {
        let fixture = try loadGoTunnelFixture()
        let now = try parseGoFixtureDate(fixture.now)
        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)]"
            let netmap = try makeNetmap(step.input, now: now)
            let actual = TunnelNetworkSettings(netmap: netmap, mtu: step.input.mtu, at: now).map(GoSettingsValue.init)
            let expected = try swiftailExpectation(step, scenario: scenario, now: now, context: context)
            let differences = Self.differences(expected: expected, actual: actual)
            #expect(differences.isEmpty, "\(context): \(differences.joined(separator: "; "))")
        }
    }

    @Test("자료의 settings가 Go 원본과 일치하고, 표시된 차이는 계약 절을 Go 원본에 적용한 값과 같다")
    func 자료내부일관성을확인한다() throws {
        for scenario in try loadGoTunnelFixture().scenarios {
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)]"
                // 계약 절을 Go 원본에 적용한 값은 표시 유무와 관계없이 `settings`와 같아야 한다.
                let derived = Self.contractSettings(fromGo: step.go)
                let differences = Self.differences(expected: step.settings, actual: derived)
                #expect(differences.isEmpty, "\(context): 기대=settings 실제=Go 원본에 계약 적용(\(differences.joined(separator: "; ")))")

                guard let reason = step.swiftailDiffers else {
                    // 표시가 없으면 Go 원본을 그대로 비교한 것이어야 한다.
                    if let settings = step.settings {
                        #expect(step.go.addresses == settings.addresses, "\(context): 기대=Go 주소 \(step.go.addresses) 실제=settings \(settings.addresses)")
                        #expect(step.go.routes == settings.routes, "\(context): 기대=Go 경로 \(step.go.routes) 실제=settings \(settings.routes)")
                        #expect(step.go.dns.servers == settings.dnsServers, "\(context): 기대=Go DNS 서버 \(step.go.dns.servers) 실제=settings \(settings.dnsServers)")
                        #expect(step.go.dns.matchDomains == settings.dnsMatchDomains, "\(context): 기대=Go match 도메인 실제=settings(개수 \(step.go.dns.matchDomains.count) 대 \(settings.dnsMatchDomains.count))")
                    }
                    continue
                }
                try Self.checkReason(reason, step: step, context: context)
            }
        }
    }

    @Test("자료의 기준 버전과 시나리오·단계·표시 수를 확인한다")
    func 자료범위를확인한다() throws {
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
            #expect(!scenario.steps.isEmpty, "\(scenario.name): 기대=단계 있음 실제=없음")
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) 단계 \(index + 1)"
                #expect(step.input.mtu == 1280, "\(context): 기대=MTU 1280 실제=\(step.input.mtu)")
                #expect(step.input.routeAll == false, "\(context): 기대=routeAll false 실제=\(step.input.routeAll)")
                #expect(step.input.exitNode.isEmpty, "\(context): 기대=exit node 없음 실제=\(step.input.exitNode)")
                if let reason = step.swiftailDiffers { #expect(!reason.isEmpty, "\(context): 기대=차이 이유 실제=빈 문자열") }
            }
        }
    }

    // MARK: - 기대값

    /// Swiftail이 내야 하는 값. 표시가 없는 단계는 `settings`(Go와 같음), 표시가 있는 단계도 `settings`(계약의 기대값)다.
    /// 표시 없이 남은 차이(지난 `KeyExpiry`의 피어)만 `settings`에서 그 경로를 뺀다.
    private func swiftailExpectation(
        _ step: GoTunnelStep, scenario: GoTunnelScenario, now: Date, context: String
    ) throws -> GoSettingsValue? {
        guard var expected = step.settings else { return nil }
        let lapsed = try Self.lapsedPeerRoutes(step.input, now: now)
        guard !lapsed.isEmpty else { return expected }
        // 지난 KeyExpiry와 Expired=false인 피어: Go는 경로에 남기고 Swiftail은 뺀다(파일 머리 주석).
        #expect(step.swiftailDiffers == nil, "\(context): 기대=표시 없는 차이 실제=표시 있음")
        for route in lapsed {
            #expect(expected.routes.contains(route), "\(context): 기대=Go 경로에 \(route) 있음 실제=\(expected.routes)")
        }
        expected.routes.removeAll { lapsed.contains($0) }
        return expected
    }

    /// `Expired=false`이고 `KeyExpiry <= now`인 피어의 경로 후보(`allowedIPs`).
    private static func lapsedPeerRoutes(_ input: GoTunnelInput, now: Date) throws -> [String] {
        try input.peers.filter { peer in
            guard !peer.expired, let text = peer.keyExpiry else { return false }
            return try parseGoFixtureDate(text) <= now
        }.flatMap(\.allowedIPs)
    }

    // MARK: - netmap 변환

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

    // MARK: - 비교

    private static func differences(expected: GoSettingsValue?, actual: GoSettingsValue?) -> [String] {
        switch (expected, actual) {
        case (nil, nil): return []
        case (nil, let actual?): return ["기대=nil(자기 주소 없음) 실제=설정 \(actual.addresses)"]
        case (let expected?, nil): return ["기대=설정 \(expected.addresses) 실제=nil"]
        case (let expected?, let actual?):
            var result: [String] = []
            if expected.addresses != actual.addresses { result.append("주소 기대=\(expected.addresses) 실제=\(actual.addresses)") }
            if expected.routes != actual.routes { result.append("경로 기대=\(expected.routes) 실제=\(actual.routes)") }
            if expected.dnsServers != actual.dnsServers { result.append("DNS 서버 기대=\(expected.dnsServers) 실제=\(actual.dnsServers)") }
            if expected.dnsMatchDomains != actual.dnsMatchDomains {
                let missing = Set(expected.dnsMatchDomains).subtracting(actual.dnsMatchDomains).sorted()
                let extra = Set(actual.dnsMatchDomains).subtracting(expected.dnsMatchDomains).sorted()
                result.append("match 도메인 기대 \(expected.dnsMatchDomains.count)개 실제 \(actual.dnsMatchDomains.count)개(빠짐 \(missing), 더함 \(extra), 순서 \(Set(expected.dnsMatchDomains) == Set(actual.dnsMatchDomains) ? "다름" : "같음"))")
            }
            if expected.mtu != actual.mtu { result.append("MTU 기대=\(expected.mtu) 실제=\(actual.mtu)") }
            return result
        }
    }

    // MARK: - 계약을 Go 원본에 적용

    /// Go 원본 결과에 계약의 정책만 적용한다(자료 도구와 독립된 계산).
    /// - S1: 자기 주소가 없으면 nil.
    /// - S4·S5: 자기 주소가 없는 계열의 경로와 DNS 서버를 뺀다.
    /// - D1·D2: DNS match 도메인은 Go의 실제 리졸버 `LocalDomains`만이다. 비면 DNS 없음. 서버는 서비스 IP.
    /// - D3: 검색 도메인은 설정에 없다.
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

    /// 표시 이유가 가리키는 계약 절마다, 그 차이가 Go 원본에 실제로 있는지 확인한다(이유가 사실인지).
    private static func checkReason(_ reason: String, step: GoTunnelStep, context: String) throws {
        let tags = Set(reason.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
            .filter { $0.count == 2 && ($0.hasPrefix("D") || $0.hasPrefix("S")) && $0.last?.isNumber == true })
        #expect(!tags.isEmpty, "\(context): 기대=이유에 계약 절 번호(D1~D3, S1·S4·S5) 실제=\(reason)")
        let known: Set<String> = ["D1", "D2", "D3", "S1", "S4", "S5"]
        let go = step.go
        let settings = step.settings
        let selfHasIPv4 = go.addresses.contains { !$0.contains(":") }
        let selfHasIPv6 = go.addresses.contains { $0.contains(":") }
        for tag in tags.sorted() {
            #expect(known.contains(tag), "\(context): 기대=계약에 있는 절 실제=\(tag)")
            switch tag {
            case "D3":
                #expect(!go.dns.searchDomains.isEmpty, "\(context): 기대=Go 검색 도메인 있음(D3) 실제=\(go.dns.searchDomains)")
            case "S4", "S5":
                // 자료의 이유는 "S4·S5"를 한 묶음으로 적는다(경로 또는 DNS 서버 중 하나만 걸려도 된다).
                let foreign = go.routes.contains { $0.contains(":") ? !selfHasIPv6 : !selfHasIPv4 }
                    || go.dns.servers.contains { $0.contains(":") ? !selfHasIPv6 : !selfHasIPv4 }
                #expect(foreign, "\(context): 기대=Go 경로·DNS 서버에 자기 주소 없는 계열(\(tag)) 실제=\(go.routes) \(go.dns.servers)")
            case "D1", "D2":
                let narrowed = go.dns.servers != (settings?.dnsServers ?? []) || go.dns.matchDomains != (settings?.dnsMatchDomains ?? [])
                #expect(narrowed, "\(context): 기대=Go DNS와 settings가 다름(D1·D2) 실제=같음")
            case "S1":
                #expect(settings == nil, "\(context): 기대=settings nil(S1) 실제=설정 있음")
            default:
                break
            }
        }
    }
}

// MARK: - 자료 모델

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
    /// Go 결과를 계약 S의 형태로 좁힌 것. 자기 주소가 없으면 nil.
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

/// 계약 형태의 설정. 자료와 `TunnelNetworkSettings`를 같은 문자열 표기로 견주기 위한 값이다.
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

/// 임의의 JSON 값. `input.dnsConfig`를 그대로 다시 내보내기 위해 쓴다.
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

    /// JSON 텍스트. 키는 정렬한다.
    var json: String {
        get throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            return String(decoding: try encoder.encode(self), as: UTF8.self)
        }
    }
}
