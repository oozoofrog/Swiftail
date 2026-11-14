// Go MagicDNS 응답기와의 독립 대조 시험.
//
// 자료(`magicdns-fixtures.json`)는 Go `net/dns/resolver`의 `Query`가 돌려준 실제 UDP 응답 바이트다. 이 시험은 단계마다
// 질의 바이트를 `MagicDNSResolver.response(to:at:)`에 넣고 응답을 두 수준으로 견준다.
//   (1) 뜻: RCODE·16비트 머리 플래그·질문 절·답/권한/추가 레코드의 종류·이름·클래스·TTL·값. 이름은 대소문자를 구별하지
//       않고 레코드는 순서를 구별하지 않으며 SOA의 SERIAL은 뺀다(차이가 나면 (2)에서 무엇이 다른지 밝힌다).
//   (2) 응답 바이트 전체. (1)이 같은데 (2)가 다르면 대소문자·레코드 순서·SOA SERIAL·인코딩 중 무엇이 다른지 메시지에 적는다.
// SOA SERIAL은 자료가 고정한 시각(`soaSerial`)을 `now`로 넘겨 바이트까지 견준다.
//
// 자료 → netmap 변환(README "dnsfixtures"를 확인했다):
// - 자료의 노드 색인은 Go의 `ipnlocal` 규칙(D7: IPv4가 있는 대상의 IPv6는 `magicdns-aaaa` 능력이 있어야 답함, 자기가
//   IPv6 전용이면 IPv6만)이 이미 적용된 **고정 표**다. `nodes[].answerAddresses`가 그 결과이고 `addresses`가 원래 주소다.
//   이 시험은 원래 주소(`addresses`)와 능력(`capabilities`)만 netmap에 싣고, 응답기가 netmap에서 스스로 D7을 적용해
//   `answerAddresses`와 같은 답에 이르는지를 본다. `answerAddresses`와 `aliases`는 변환에 쓰지 않는다(Go 쪽 기대 표라서
//   `decoded`에 이미 결과가 있다).
// - 첫 노드(`self: true`)가 자기 노드, 나머지가 피어다. 이름은 자료의 FQDN 그대로(끝 점 포함). 주소 없는 노드는 `Addresses: []`.
// - `capabilities`는 자기 노드의 `CapMap` 키(값 null)로 싣는다. 옛 `Capabilities` 목록으로 싣는 변형도 한 번 확인한다.
// - `hosts`는 `ExtraRecords`(끝 점을 뗀 이름, 형식 `""`=A·AAAA 자동)로 싣는다. 노드 `subdomain` 표시는 쓰지 않는다
//   (M5가 `dns-subdomain-resolve`를 생략하므로 netmap에 그 능력을 싣지 않는다).
// - 응답기의 `localZones`는 자료의 `localDomains`(Go 리졸버에 준 실제 값)를 그대로 넘긴다. Swiftail이 netmap에서 산출하는
//   영역(`TunnelNetworkSettings.localZones(in:at:)`)이 이것과 같은지는 따로 확인한다(`영역을대조한다`). 그 확인을 위한
//   `DNSConfig`는 `localDomains`에서 MagicDNS 영역(접미사·`ip6.arpa`·`64`~`127.100.in-addr.arpa`)을 뺀 나머지를 빈
//   리졸버 `Routes`로, `Proxied`는 접미사 영역이 `localDomains`에 있는지로 정한다(7번 시나리오는 `proxied: true`이지만
//   영역 표에는 긴 영역 하나뿐이라서 `proxied` 필드를 쓰지 않는다).
// - "자기 키 만료 또는 netmap 없음"(6번)은 `MagicDNSResolver(netmap: nil, localZones: [])`다(계약: 그런 경우 nil을 넘긴다).
//
// 표시(`swiftailDiffers`)가 없는 단계는 Go와 같아야 한다. 표시가 있는 3단계(동작 D8·제외: 4via6 이름과 서브도메인)는
// 계약이 정한 Swiftail의 응답을 기대값으로 따로 만든다: 영역 밖 4via6 이름은 질문 포함 SERVFAIL(동작 D5), 영역 안의
// 알 수 없는 이름은 NXDOMAIN + SOA(동작 D2). 이 기대값을 만드는 방법은 Go가 같은 형태의 질의에 낸 바이트(1번 시나리오의
// "영역 밖 라우트 없음"·"모르는 로컬 이름")로 보정해 확인한다.
// 표시 없이 남은 차이(계약 D7과 달리 Go는 빈 색인에서도 서비스 이름의 A와 서비스 IP의 PTR에 답함)는 계약의 "응답기
// 구현에서 정해진 것"이 Go와 같게 정했으므로 Go 값을 그대로 견준다(6번 시나리오 3·4단계).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine

@Suite("Go MagicDNS 응답기와의 독립 대조")
struct GoMagicDNSComparisonTests {
    @Test("같은 질의에 대한 응답의 뜻과 바이트가 같다", arguments: try loadGoDNSFixture().scenarios)
    func 응답을대조한다(_ scenario: GoDNSScenario) throws {
        let fixture = try loadGoDNSFixture()
        try compareScenario(scenario, fixture: fixture, legacyCapabilities: false)
    }

    @Test("능력을 옛 Capabilities 목록으로 실어도 응답이 같다")
    func 옛능력목록으로도대조한다() throws {
        let fixture = try loadGoDNSFixture()
        let scenario = try #require(fixture.scenarios.first { !$0.capabilities.isEmpty }, "기대=능력이 있는 시나리오 실제=없음")
        try compareScenario(scenario, fixture: fixture, legacyCapabilities: true)
    }

    @Test("Swiftail이 netmap에서 산출한 영역이 Go 리졸버의 LocalDomains와 같다")
    func 영역을대조한다() throws {
        let fixture = try loadGoDNSFixture()
        let now = Date(timeIntervalSince1970: TimeInterval(fixture.soaSerial))
        for scenario in fixture.scenarios where !scenario.nodes.isEmpty {
            let netmap = try makeNetmap(scenario, now: now, legacyCapabilities: false, forZones: true)
            let zones = TunnelNetworkSettings.localZones(in: netmap, at: now)
            // Go의 `LocalDomains`는 만든 순서(접미사, `ip6.arpa`, `64`~`127`)이고 정렬되어 있지 않다. 계약 동작 S5는 끝 점 포함
            // 문자열의 바이트 순 정렬을 정하므로(자료의 tunnel `settings`도 그렇다) 같은 집합을 그 순서로 놓은 것이 기대값이다.
            let expected = scenario.localDomains.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            #expect(zones == expected,
                    "\(scenario.name): 기대=Go LocalDomains \(expected.count)개(계약 순서) 실제=Swift \(zones.count)개, 빠짐 \(Set(expected).subtracting(zones).sorted()), 더함 \(Set(zones).subtracting(expected).sorted())")
        }
    }

    @Test("자료의 decoded가 응답 hex를 따로 쓴 해석기로 읽은 것과 같다(해석기 보정)")
    func 해석기를보정한다() throws {
        for scenario in try loadGoDNSFixture().scenarios {
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)]"
                let bytes = try #require([UInt8](hex: step.response), "\(context): 기대=올바른 응답 hex 실제=\(step.response)")
                let parsed = try GoDNSMessage(parsing: bytes)
                let decoded = GoDNSMessage(decoded: step.decoded)
                #expect(parsed == decoded, "\(context): 기대=자료 decoded \(decoded.rendered) 실제=hex 해석 \(parsed.rendered)")
                #expect(step.decoded.rcode == parsed.flags & 0xF, "\(context): 기대=decoded.rcode 실제=플래그 RCODE")
            }
        }
    }

    @Test("계약 기대값을 만드는 방법이 Go가 같은 형태에 낸 바이트와 같다(보정)")
    func 계약기대값을보정한다() throws {
        let fixture = try loadGoDNSFixture()
        let base = try #require(fixture.scenarios.first, "기대=시나리오 실제=없음")
        let servfail = try #require(base.steps.first { $0.name == "영역 밖 라우트 없음" }, "기대=영역 밖 단계 실제=없음")
        let nxdomain = try #require(base.steps.first { $0.name == "모르는 로컬 이름" }, "기대=모르는 로컬 이름 단계 실제=없음")
        let servfailQuery = try #require([UInt8](hex: servfail.query))
        let servfailResponse = try #require([UInt8](hex: servfail.response))
        #expect(Self.servfailShape(query: servfailQuery) == servfailResponse, "기대=Go SERVFAIL 바이트 실제=보정 기대값 불일치")
        let nxdomainQuery = try #require([UInt8](hex: nxdomain.query))
        let nxdomainResponse = try #require([UInt8](hex: nxdomain.response))
        #expect(try Self.nxdomainShape(query: nxdomainQuery, reference: nxdomain) == nxdomainResponse, "기대=Go NXDOMAIN+SOA 바이트 실제=보정 기대값 불일치")
    }

    @Test("표시 없이 남은 차이: Go가 앞 질의의 질문을 싣는 단계는 하나뿐이다")
    func 질문누출단계를확인한다() throws {
        var found: [String] = []
        for scenario in try loadGoDNSFixture().scenarios {
            for step in scenario.steps where step.swiftailDiffers == nil {
                let query = try #require([UInt8](hex: step.query))
                let response = try #require([UInt8](hex: step.response))
                if try Self.hasStaleQuestion(query: query, goResponse: response) { found.append("\(scenario.name) [\(step.name)]") }
            }
        }
        #expect(found == ["기본 노드·질의 형식 [머리 비트 8100]"], "기대=질문 누출 단계 1개 실제=\(found)")
    }

    @Test("자료의 기준 버전과 시나리오·단계·표시 수를 확인한다")
    func 자료범위를확인한다() throws {
        let fixture = try loadGoDNSFixture()
        #expect(fixture.reference == "tailscale.com v1.104.6")
        #expect(fixture.soaSerial == 1_767_323_045)
        #expect(fixture.scenarioCount == 8)
        #expect(fixture.scenarios.count == 8)
        #expect(Set(fixture.scenarios.map(\.name)).count == fixture.scenarios.count)
        #expect(fixture.stepCount == 85)
        let steps = fixture.scenarios.flatMap(\.steps)
        #expect(steps.count == 85)
        #expect(steps.filter { $0.swiftailDiffers != nil }.count == 3)
        #expect(fixture.scenarios.map(\.steps.count) == [61, 3, 4, 3, 3, 4, 4, 3])
        for scenario in fixture.scenarios {
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)]"
                #expect([UInt8](hex: step.query) != nil, "\(context): 기대=질의 hex 실제=\(step.query)")
                #expect([UInt8](hex: step.response) != nil, "\(context): 기대=응답 hex 실제=\(step.response)")
                if let reason = step.swiftailDiffers { #expect(!reason.isEmpty, "\(context): 기대=차이 이유 실제=빈 문자열") }
            }
        }
    }

    // MARK: - 시나리오 대조

    private func compareScenario(_ scenario: GoDNSScenario, fixture: GoDNSFixture, legacyCapabilities: Bool) throws {
        let now = Date(timeIntervalSince1970: TimeInterval(fixture.soaSerial))
        let netmap = scenario.nodes.isEmpty
            ? nil : try makeNetmap(scenario, now: now, legacyCapabilities: legacyCapabilities, forZones: false)
        let resolver = MagicDNSResolver(netmap: netmap, localZones: scenario.localDomains)

        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)]"
            let query = try #require([UInt8](hex: step.query), "\(context): 기대=질의 hex 실제=\(step.query)")
            let actual = resolver.response(to: query, at: now)
            let expected: [UInt8]
            if let reason = step.swiftailDiffers {
                expected = try contractResponse(reason: reason, query: query, fixture: fixture, context: context)
            } else {
                let goResponse = try #require([UInt8](hex: step.response), "\(context): 기대=응답 hex 실제=\(step.response)")
                expected = try Self.hasStaleQuestion(query: query, goResponse: goResponse)
                    ? Self.droppingQuestion(from: goResponse) : goResponse
            }
            for difference in Self.differences(expected: expected, actual: actual) {
                Issue.record("\(context): \(difference)")
            }
        }
    }

    // MARK: - netmap 변환

    private func makeNetmap(_ scenario: GoDNSScenario, now: Date, legacyCapabilities: Bool, forZones: Bool) throws -> Netmap {
        func node(_ value: GoDNSNode, id: Int64, isSelf: Bool) -> GoFixtureNode {
            GoFixtureNode(
                id: id, name: value.name, addresses: value.addresses.map(Self.cidr), allowedIPs: nil,
                capabilities: isSelf && !legacyCapabilities ? scenario.capabilities : [],
                legacyCapabilities: isSelf && legacyCapabilities ? scenario.capabilities : [])
        }
        let selfIndex = try #require(scenario.nodes.firstIndex { $0.isSelf == true }, "\(scenario.name): 기대=자기 노드 실제=없음")
        let peers = scenario.nodes.enumerated().filter { $0.offset != selfIndex }
        return try makeGoFixtureNetmap(
            selfNode: node(scenario.nodes[selfIndex], id: Int64(selfIndex + 1), isSelf: true),
            peers: peers.map { node($0.element, id: Int64($0.offset + 1), isSelf: false) },
            dnsConfigJSON: dnsConfigJSON(scenario), receivedAt: now)
    }

    /// 자료의 `hosts`·`localDomains`를 뜻하는 `DNSConfig` JSON.
    private func dnsConfigJSON(_ scenario: GoDNSScenario) -> String {
        let suffix = scenario.magicDNSSuffix
        let magicZones: Set<String> = Set([suffix, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."] + (64...127).map { "\($0).100.in-addr.arpa." })
        let proxied = scenario.localDomains.contains(suffix)
        let routes = scenario.localDomains.filter { !(proxied && magicZones.contains($0)) }
            .map { "\"\($0.dropLast())\":[]" }.joined(separator: ",")
        let records = scenario.hosts.sorted { $0.key < $1.key }.flatMap { name, values in
            values.map { #"{"Name":"\#(name.dropLast())","Value":"\#($0)"}"# }
        }.joined(separator: ",")
        return #"{"Proxied":\#(proxied),"Routes":{\#(routes)},"ExtraRecords":[\#(records)]}"#
    }

    private static func cidr(_ address: String) -> String {
        address.contains(":") ? "\(address)/128" : "\(address)/32"
    }

    // MARK: - 계약이 정한 기대값(표시가 있는 단계)

    /// 표시 이유가 가리키는 계약 동작(D8)에 따른 Swiftail의 응답 바이트.
    private func contractResponse(reason: String, query: [UInt8], fixture: GoDNSFixture, context: String) throws -> [UInt8] {
        guard reason.contains("D8") else {
            Issue.record("\(context): 기대값을 정할 근거 없음(이유=\(reason))")
            return []
        }
        if reason.contains("SERVFAIL") {
            // 영역 밖의 이름: 로컬 답이 없고 `localZones` 밖이면 SERVFAIL(질문 포함, AA=1, RA는 질의 값). 동작 D5.
            return Self.servfailShape(query: query)
        }
        if reason.contains("NXDOMAIN") {
            // 영역 안의 알 수 없는 이름: NXDOMAIN + 영역의 SOA. 동작 D2. SOA는 같은 영역의 Go 응답에서 가져온다.
            let base = try #require(fixture.scenarios.first, "기대=시나리오 실제=없음")
            let reference = try #require(base.steps.first { $0.name == "모르는 로컬 이름" }, "기대=모르는 로컬 이름 단계 실제=없음")
            return try Self.nxdomainShape(query: query, reference: reference)
        }
        Issue.record("\(context): 기대값을 정할 근거 없음(이유=\(reason))")
        return []
    }

    /// 질의 머리를 복사해 QR=1, AA=1, RCODE=2로 바꾸고 질문을 실은 응답. 질의는 머리 + 질문 하나여야 한다.
    private static func servfailShape(query: [UInt8]) -> [UInt8] {
        let flags = (UInt16(query[2]) << 8 | UInt16(query[3])) & ~0x000F | 0x8000 | 0x0400 | 0x0002
        return [query[0], query[1], UInt8(flags >> 8), UInt8(flags & 0xFF), 0, 1, 0, 0, 0, 0, 0, 0] + query[12...]
    }

    /// 질의 머리를 복사해 QR=1, AA=1, RD면 RA=1, RCODE=3으로 바꾸고 질문과 `reference` 응답의 권한 구역(SOA)을 실은 응답.
    private static func nxdomainShape(query: [UInt8], reference: GoDNSStep) throws -> [UInt8] {
        let referenceQuery = try #require([UInt8](hex: reference.query), "기대=기준 질의 hex 실제=\(reference.query)")
        let referenceResponse = try #require([UInt8](hex: reference.response), "기대=기준 응답 hex 실제=\(reference.response)")
        var flags = (UInt16(query[2]) << 8 | UInt16(query[3])) & ~0x000F | 0x8000 | 0x0400 | 0x0003
        if flags & 0x0100 != 0 { flags |= 0x0080 }
        // 기준 응답 = 머리 + 질문 + 권한 구역이고 기준 질의 = 머리 + 질문이다.
        return [query[0], query[1], UInt8(flags >> 8), UInt8(flags & 0xFF), 0, 1, 0, 0, 0, 1, 0, 0]
            + query[12...] + referenceResponse[referenceQuery.count...]
    }

    // MARK: - 표시 없는 차이: Go가 앞 질의의 질문을 싣는 경우

    /// 응답 비트(QR)가 켜졌거나 12바이트보다 짧은 질의에 대한 Go 응답이 질문을 싣고 있는가.
    ///
    /// Go는 그런 질의에 FORMERR로 답할 때 다시 쓰는 파서에 남아 있던 **앞 질의의 질문**을 응답에 싣는다(다른 앱의 질의 이름이
    /// 새어 나갈 수 있다). Swiftail은 질문 없이 답한다: 계약 "응답기 구현에서 정해진 것"(M5-1)이 Go와 일부러 다르게 한 것으로
    /// 적었다. 자료는 이 단계에 `swiftailDiffers`를 달지 않았다(표시 누락). 그래서 계약의 기대값(질문 없는 응답)을 쓴다.
    private static func hasStaleQuestion(query: [UInt8], goResponse: [UInt8]) throws -> Bool {
        let short = query.count < 12
        let responseBit = query.count >= 3 && query[2] & 0x80 != 0
        guard short || responseBit else { return false }
        return try !GoDNSMessage(parsing: goResponse).questions.isEmpty
    }

    /// 응답에서 질문 하나(압축 없는 이름 + TYPE + CLASS)를 빼고 QDCOUNT를 0으로 한 것.
    private static func droppingQuestion(from response: [UInt8]) -> [UInt8] {
        var end = 12
        while end < response.count, response[end] != 0 { end += Int(response[end]) + 1 }
        end += 1 + 4
        return Array(response[0..<4]) + [0, 0] + Array(response[6..<12]) + Array(response[end...])
    }

    // MARK: - 비교

    /// 응답 하나의 차이 목록. 비어 있으면 바이트까지 같다.
    private static func differences(expected: [UInt8], actual: [UInt8]) -> [String] {
        if expected == actual { return [] }
        let expectedMessage: GoDNSMessage
        let actualMessage: GoDNSMessage
        do {
            expectedMessage = try GoDNSMessage(parsing: expected)
        } catch {
            return ["기대 응답을 해석하지 못함(\(error)) 기대=\(expected.hex)"]
        }
        do {
            actualMessage = try GoDNSMessage(parsing: actual)
        } catch {
            return ["실제 응답을 해석하지 못함(\(error)) 기대=\(expectedMessage.rendered) 실제 hex=\(actual.hex)"]
        }
        let meaning = expectedMessage.meaningDifferences(from: actualMessage)
        if !meaning.isEmpty {
            return ["뜻이 다름: \(meaning.joined(separator: "; ")) | 기대=\(expectedMessage.rendered) 실제=\(actualMessage.rendered)"]
        }
        // 뜻은 같고 바이트가 다르다: 무엇이 다른지 가른다.
        var kinds = expectedMessage.byteDifferenceKinds(from: actualMessage)
        if kinds.isEmpty { kinds = ["인코딩(압축·필드 배치)"] }
        let offset = zip(expected, actual).enumerated().first { $0.element.0 != $0.element.1 }?.offset ?? min(expected.count, actual.count)
        return ["뜻은 같고 바이트가 다름[\(kinds.joined(separator: ", "))]: 길이 기대=\(expected.count) 실제=\(actual.count), 첫 차이 오프셋 \(offset), 기대=\(expectedMessage.rendered) 실제=\(actualMessage.rendered)"]
    }
}

// MARK: - DNS 메시지 해석(시험 전용, 코덱과 무관하게 따로 씀)

struct GoDNSParseError: Error, CustomStringConvertible {
    let description: String
}

struct GoDNSMessage: Equatable {
    struct Question: Equatable {
        var name: String
        var type: Int
        var cls: Int
    }

    struct Record: Equatable {
        var name: String
        var type: Int
        var cls: Int
        var ttl: Int
        /// A·AAAA는 정규 표기 주소, PTR은 이름, SOA는 `ns mbox serial refresh retry expire minimum`, 그 밖은 hex.
        var value: String
    }

    var id: Int
    var flags: Int
    var questions: [Question]
    var answers: [Record]
    var authorities: [Record]
    var additionals: [Record]

    init(parsing bytes: [UInt8]) throws {
        guard bytes.count >= 12 else { throw GoDNSParseError(description: "머리 12바이트보다 짧음(\(bytes.count))") }
        func u16(_ at: Int) -> Int { Int(bytes[at]) << 8 | Int(bytes[at + 1]) }
        id = u16(0)
        flags = u16(2)
        let counts = [u16(4), u16(6), u16(8), u16(10)]
        var offset = 12

        questions = []
        for _ in 0..<counts[0] {
            let (name, next) = try Self.readName(bytes, at: offset)
            guard next + 4 <= bytes.count else { throw GoDNSParseError(description: "질문이 잘림") }
            questions.append(Question(name: name, type: u16(next), cls: u16(next + 2)))
            offset = next + 4
        }
        var sections: [[Record]] = []
        for count in counts[1...] {
            var records: [Record] = []
            for _ in 0..<count {
                let (name, next) = try Self.readName(bytes, at: offset)
                guard next + 10 <= bytes.count else { throw GoDNSParseError(description: "레코드 머리가 잘림") }
                let type = u16(next)
                let ttl = u16(next + 4) << 16 | u16(next + 6)
                let length = u16(next + 8)
                let start = next + 10
                guard start + length <= bytes.count else { throw GoDNSParseError(description: "RDATA가 잘림") }
                let value = try Self.readValue(bytes, type: type, start: start, length: length)
                records.append(Record(name: name, type: type, cls: u16(next + 2), ttl: ttl, value: value))
                offset = start + length
            }
            sections.append(records)
        }
        answers = sections[0]
        authorities = sections[1]
        additionals = sections[2]
        guard offset == bytes.count else { throw GoDNSParseError(description: "구역 뒤에 \(bytes.count - offset)바이트가 남음") }
    }

    /// 자료의 `decoded`와 같은 메시지.
    init(decoded: GoDNSDecoded) {
        id = decoded.id
        flags = decoded.flags
        questions = decoded.questions.map { Question(name: $0.name, type: $0.type, cls: $0.class) }
        func records(_ values: [GoDNSDecodedRecord]) -> [Record] {
            values.map { Record(name: $0.name, type: $0.type, cls: $0.class, ttl: $0.ttl, value: $0.value.canonical(type: $0.type)) }
        }
        answers = records(decoded.answers)
        authorities = records(decoded.authorities)
        additionals = records(decoded.additionals)
    }

    var rcode: Int { flags & 0xF }

    /// 사람이 읽는 한 줄.
    var rendered: String {
        func records(_ values: [Record]) -> String {
            values.map { "\($0.type) \($0.name) c\($0.cls) ttl\($0.ttl) \($0.value)" }.joined(separator: " | ")
        }
        return "{id=\(id) flags=0x\(String(flags, radix: 16)) rcode=\(rcode) Q=[\(questions.map { "\($0.name) t\($0.type) c\($0.cls)" }.joined(separator: " | "))] AN=[\(records(answers))] NS=[\(records(authorities))] AR=[\(records(additionals))]}"
    }

    // MARK: 뜻 비교

    /// 뜻의 차이: ID·플래그·질문(이름은 대소문자 무시)·레코드 묶음(순서 무시, SOA SERIAL 제외).
    func meaningDifferences(from other: GoDNSMessage) -> [String] {
        var result: [String] = []
        if id != other.id { result.append("ID 기대=\(id) 실제=\(other.id)") }
        if flags != other.flags { result.append("플래그 기대=0x\(String(flags, radix: 16)) 실제=0x\(String(other.flags, radix: 16))(\(flagDifference(other.flags)))") }
        if questions.map(\.normalized) != other.questions.map(\.normalized) { result.append("질문 다름") }
        for (label, mine, theirs) in [("답", answers, other.answers), ("권한", authorities, other.authorities), ("추가", additionals, other.additionals)]
        where mine.map(\.normalized).sorted() != theirs.map(\.normalized).sorted() {
            result.append("\(label) 레코드 다름")
        }
        return result
    }

    private func flagDifference(_ other: Int) -> String {
        let names: [(Int, String)] = [(0x8000, "QR"), (0x0400, "AA"), (0x0200, "TC"), (0x0100, "RD"), (0x0080, "RA"), (0x0040, "Z"), (0x0020, "AD"), (0x0010, "CD")]
        var parts = names.filter { (flags ^ other) & $0.0 != 0 }.map { "\($0.1) 기대=\(flags & $0.0 != 0 ? 1 : 0)" }
        if (flags ^ other) & 0x7800 != 0 { parts.append("Opcode 기대=\((flags >> 11) & 0xF) 실제=\((other >> 11) & 0xF)") }
        if flags & 0xF != other & 0xF { parts.append("RCODE 기대=\(flags & 0xF) 실제=\(other & 0xF)") }
        return parts.joined(separator: ", ")
    }

    // MARK: 바이트 차이의 종류

    /// 뜻이 같은 두 메시지가 어떻게 다른지: 이름 대소문자, 레코드 순서, SOA SERIAL.
    func byteDifferenceKinds(from other: GoDNSMessage) -> [String] {
        var kinds: [String] = []
        let names = questions.map(\.name) + (answers + authorities + additionals).map(\.name)
        let otherNames = other.questions.map(\.name) + (other.answers + other.authorities + other.additionals).map(\.name)
        if names != otherNames, names.map({ $0.lowercased() }) == otherNames.map({ $0.lowercased() }) { kinds.append("이름 대소문자") }
        if answers != other.answers || authorities != other.authorities {
            let sameSet = answers.map(\.normalized).sorted() == other.answers.map(\.normalized).sorted()
            if sameSet, answers.map(\.normalized) != other.answers.map(\.normalized) { kinds.append("레코드 순서") }
        }
        let serial = { (message: GoDNSMessage) in message.authorities.filter { $0.type == 6 }.map(\.value) }
        if serial(self) != serial(other) { kinds.append("SOA 값(SERIAL)") }
        return kinds
    }

    // MARK: 바이트 읽기

    private static func readName(_ bytes: [UInt8], at start: Int) throws -> (String, Int) {
        var labels: [String] = []
        var position = start
        var end: Int?
        var jumps = 0
        while true {
            guard position < bytes.count else { throw GoDNSParseError(description: "이름이 잘림") }
            let length = Int(bytes[position])
            if length == 0 {
                position += 1
                break
            }
            if length & 0xC0 == 0xC0 {
                guard position + 1 < bytes.count else { throw GoDNSParseError(description: "포인터가 잘림") }
                let target = (length & 0x3F) << 8 | Int(bytes[position + 1])
                if end == nil { end = position + 2 }
                jumps += 1
                guard jumps <= 16, target < bytes.count else { throw GoDNSParseError(description: "포인터 오류") }
                position = target
                continue
            }
            guard length < 64, position + 1 + length <= bytes.count else { throw GoDNSParseError(description: "레이블 오류") }
            labels.append(String(decoding: bytes[position + 1..<position + 1 + length], as: UTF8.self))
            position += 1 + length
        }
        return (labels.isEmpty ? "." : labels.joined(separator: ".") + ".", end ?? position)
    }

    private static func readValue(_ bytes: [UInt8], type: Int, start: Int, length: Int) throws -> String {
        let data = Array(bytes[start..<start + length])
        switch type {
        case 1, 28:
            guard let address = IPAddress(bytes: data) else { throw GoDNSParseError(description: "주소 길이 \(length)") }
            return address.description
        case 12:
            return try readName(bytes, at: start).0
        case 6:
            let (ns, afterNS) = try readName(bytes, at: start)
            let (mbox, afterMbox) = try readName(bytes, at: afterNS)
            guard afterMbox + 20 <= bytes.count else { throw GoDNSParseError(description: "SOA가 잘림") }
            let numbers = (0..<5).map { index -> UInt32 in
                bytes[afterMbox + index * 4..<afterMbox + index * 4 + 4].reduce(0) { $0 << 8 | UInt32($1) }
            }
            return "\(ns) \(mbox) " + numbers.map(String.init).joined(separator: " ")
        default:
            return data.hex
        }
    }
}

private extension GoDNSMessage.Question {
    var normalized: String { "\(name.lowercased()) \(type) \(cls)" }
}

private extension GoDNSMessage.Record {
    /// 이름(대소문자 무시)·종류·클래스·TTL·값. SOA는 SERIAL(셋째 항목)을 뺀다.
    var normalized: String {
        var text = value.lowercased()
        if type == 6 {
            var parts = text.split(separator: " ").map(String.init)
            if parts.count == 7 { parts[2] = "*" }
            text = parts.joined(separator: " ")
        }
        return "\(name.lowercased()) \(type) \(cls) \(ttl) \(text)"
    }
}

// MARK: - 자료 모델

private func loadGoDNSFixture() throws -> GoDNSFixture {
    try JSONDecoder().decode(GoDNSFixture.self, from: loadGoFixtureData("magicdns-fixtures"))
}

struct GoDNSFixture: Decodable, Sendable {
    let reference: String
    let scenarioCount: Int
    let stepCount: Int
    let soaSerial: Int
    let scenarios: [GoDNSScenario]
}

struct GoDNSScenario: Decodable, Sendable, CustomTestStringConvertible {
    let name: String
    let magicDNSSuffix: String
    let proxied: Bool
    let capabilities: [String]
    let nodes: [GoDNSNode]
    let localDomains: [String]
    let hosts: [String: [String]]
    let steps: [GoDNSStep]
    var testDescription: String { name }
}

struct GoDNSNode: Decodable, Sendable {
    let name: String
    let isSelf: Bool?
    let addresses: [String]

    enum CodingKeys: String, CodingKey {
        case name, addresses
        case isSelf = "self"
    }
}

struct GoDNSStep: Decodable, Sendable {
    let name: String
    let query: String
    let response: String
    let decoded: GoDNSDecoded
    let swiftailDiffers: String?
}

struct GoDNSDecoded: Decodable, Sendable {
    struct Question: Decodable, Sendable {
        let name: String
        let type: Int
        let `class`: Int
    }

    let id: Int
    let rcode: Int
    let flags: Int
    let questions: [Question]
    let answers: [GoDNSDecodedRecord]
    let authorities: [GoDNSDecodedRecord]
    let additionals: [GoDNSDecodedRecord]
}

struct GoDNSDecodedRecord: Decodable, Sendable {
    let type: Int
    let name: String
    let `class`: Int
    let ttl: Int
    let value: GoDNSValue
}

/// 레코드의 `value`: A·AAAA·PTR은 문자열, SOA는 객체.
enum GoDNSValue: Decodable, Sendable {
    struct SOA: Decodable, Sendable {
        let ns: String
        let mbox: String
        let serial: Int
        let refresh: Int
        let retry: Int
        let expire: Int
        let minimum: Int
    }

    case text(String)
    case soa(SOA)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let text = try? container.decode(String.self) {
            self = .text(text)
        } else {
            self = .soa(try container.decode(SOA.self))
        }
    }

    /// 해석기의 `Record.value`와 같은 표기.
    func canonical(type: Int) -> String {
        switch self {
        case .text(let text):
            return type == 1 || type == 28 ? (IPAddress(text)?.description ?? text) : text
        case .soa(let soa):
            return "\(soa.ns) \(soa.mbox) \(soa.serial) \(soa.refresh) \(soa.retry) \(soa.expire) \(soa.minimum)"
        }
    }
}
