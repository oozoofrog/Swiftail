// Independent comparison with the Go MagicDNS responder.
//
// The fixture (`magicdns-fixtures.json`) contains actual UDP response bytes from `Query` in Go's `net/dns/resolver`. For each step, the test
// passes query bytes to `MagicDNSResolver.response(to:at:)` and compares the response at two levels.
//   (1) Meaning. Compare RCODE, 16-bit header flags, the question section, and the type, name, class, TTL, and value of answer, authority, and additional records. Ignore
//       name case and record order, and omit the SOA SERIAL (if there is a difference, level (2) shows what differs).
//   (2) All response bytes. If (1) matches and (2) differs, report which of case, record order, SOA SERIAL, or encoding differs.
// Pass the time fixed by the fixture (`soaSerial`) as `now` to compare the SOA SERIAL byte for byte.
//
// Fixture-to-netmap conversion follows the README's "dnsfixtures" section.
// - The fixture node index is a **fixed table** that already incorporates Go's `ipnlocal` rules (D7: Answer with IPv6 for targets that have IPv4 only if
//   the `magicdns-aaaa` capability is present. If self is IPv6-only, answer with IPv6 only). `nodes[].answerAddresses` holds the result, and `addresses` holds the original addresses.
//   The test puts only the original addresses (`addresses`) and capabilities (`capabilities`) in the netmap, and checks that the responder applies D7 to the netmap itself
//   to reach the same answers as `answerAddresses`. The conversion skips `answerAddresses` and `aliases` because they are Go expectations and
//   `decoded` already contains the result.
// - The first node (`self: true`) is the local node, and the rest are peers. Use the fixture FQDNs as is (with trailing dots). Nodes with no addresses use `Addresses: []`.
// - Include `capabilities` as the local node's `CapMap` keys (with null values). Also check a variant that sends the legacy `Capabilities` list once.
// - Include `hosts` as `ExtraRecords` (names without trailing dots, type `""` = automatic A or AAAA). Skip node `subdomain` markers
//   because M5 omits `dns-subdomain-resolve`, so the netmap excludes that capability.
// - Pass the fixture's `localDomains` (the actual values given to the Go resolver) directly as the responder's `localZones`. Separately verify that the
//   zones Swiftail derives from the netmap (`TunnelNetworkSettings.localZones(in:at:)`) match (`compareZones`). For that check,
//   construct `DNSConfig` with resolver-free `Routes` from `localDomains` after removing the MagicDNS zones (suffix, `ip6.arpa`, and `64` through `127.100.in-addr.arpa`).
//   Set `Proxied` according to whether the suffix zone is in `localDomains` (scenario 7 has `proxied: true`, but
//   its zone table has only one long zone, so the test skips the `proxied` field).
// - For "Local key expired or no netmap" (scenario 6), use `MagicDNSResolver(netmap: nil, localZones: [])` (the contract calls for nil in these cases).
//
// Steps without `swiftailDiffers` must match Go. For the 3 marked steps (behavior D8 and exclusions for 4via6 names and subdomains),
// build separate expectations for the Swiftail responses specified by the contract. Out-of-zone 4via6 names return SERVFAIL with the question (behavior D5), and
// unknown in-zone names return NXDOMAIN + SOA (behavior D2). Verify how these expectations are built by calibrating them against Go's bytes for queries of the same shape
// ("Out of zone with no route" and "Unknown local name" in scenario 1).
// One unmarked difference remains. Unlike contract D7, Go answers A for the service name and PTR for the service IP even with an empty index. The contract's section
// "Decisions made in the responder implementation" follows Go here, so compare directly against Go's values (steps 3 and 4 of scenario 6).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine

@Suite("Independent comparison with the Go MagicDNS responder")
struct GoMagicDNSComparisonTests {
    @Test("The same queries produce responses with the same meaning and bytes", arguments: try loadGoDNSFixture().scenarios)
    func compareResponses(_ scenario: GoDNSScenario) throws {
        let fixture = try loadGoDNSFixture()
        try compareScenario(scenario, fixture: fixture, legacyCapabilities: false)
    }

    @Test("Sending capabilities in the legacy Capabilities list yields the same responses")
    func compareWithLegacyCapabilities() throws {
        let fixture = try loadGoDNSFixture()
        let scenario = try #require(fixture.scenarios.first { !$0.capabilities.isEmpty }, "Expected a scenario with capabilities, got none")
        try compareScenario(scenario, fixture: fixture, legacyCapabilities: true)
    }

    @Test("The zones Swiftail computes from the netmap match the Go resolver's LocalDomains")
    func compareZones() throws {
        let fixture = try loadGoDNSFixture()
        let now = Date(timeIntervalSince1970: TimeInterval(fixture.soaSerial))
        for scenario in fixture.scenarios where !scenario.nodes.isEmpty {
            let netmap = try makeNetmap(scenario, now: now, legacyCapabilities: false, forZones: true)
            let zones = TunnelNetworkSettings.localZones(in: netmap, at: now)
            // Go's `LocalDomains` is in creation order (suffix, `ip6.arpa`, `64` through `127`) and is unsorted. Contract behavior S5 specifies bytewise sorting of
            // strings with trailing dots (also used for the fixture's tunnel `settings`), so the expected value is the same set in that order.
            let expected = scenario.localDomains.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            #expect(zones == expected,
                    "\(scenario.name), expected Go LocalDomains, \(expected.count) entries (contract order), got Swift, \(zones.count) entries, missing \(Set(expected).subtracting(zones).sorted()), extra \(Set(zones).subtracting(expected).sorted())")
        }
    }

    @Test("The fixture's decoded value matches the response hex parsed by an independent parser (parser calibration)")
    func calibrateParser() throws {
        for scenario in try loadGoDNSFixture().scenarios {
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) step \(index + 1) [\(step.name)]"
                let bytes = try #require([UInt8](hex: step.response), "\(context), expected valid response hex, got \(step.response)")
                let parsed = try GoDNSMessage(parsing: bytes)
                let decoded = GoDNSMessage(decoded: step.decoded)
                #expect(parsed == decoded, "\(context), expected fixture decoded \(decoded.rendered), got parsed hex \(parsed.rendered)")
                #expect(step.decoded.rcode == parsed.flags & 0xF, "\(context), expected decoded.rcode, got RCODE from flags")
            }
        }
    }

    @Test("The method for building contract expectations matches Go's bytes for the same shape (calibration)")
    func calibrateContractExpectations() throws {
        let fixture = try loadGoDNSFixture()
        let base = try #require(fixture.scenarios.first, "Expected a scenario, got none")
        let servfail = try #require(base.steps.first { $0.name == "No out-of-zone route" }, "Expected the out-of-zone step, got none")
        let nxdomain = try #require(base.steps.first { $0.name == "Unknown local name" }, "Expected the unknown local name step, got none")
        let servfailQuery = try #require([UInt8](hex: servfail.query))
        let servfailResponse = try #require([UInt8](hex: servfail.response))
        #expect(Self.servfailShape(query: servfailQuery) == servfailResponse, "Expected Go SERVFAIL bytes, got mismatched calibration bytes")
        let nxdomainQuery = try #require([UInt8](hex: nxdomain.query))
        let nxdomainResponse = try #require([UInt8](hex: nxdomain.response))
        #expect(try Self.nxdomainShape(query: nxdomainQuery, reference: nxdomain) == nxdomainResponse, "Expected Go NXDOMAIN+SOA bytes, got mismatched calibration bytes")
    }

    @Test("Unmarked difference where Go includes the previous query's question in exactly one step")
    func verifyQuestionLeakStep() throws {
        var found: [String] = []
        for scenario in try loadGoDNSFixture().scenarios {
            for step in scenario.steps where step.swiftailDiffers == nil {
                let query = try #require([UInt8](hex: step.query))
                let response = try #require([UInt8](hex: step.response))
                if try Self.hasStaleQuestion(query: query, goResponse: response) { found.append("\(scenario.name) [\(step.name)]") }
            }
        }
        #expect(found == ["Basic nodes and query formats [Header bits 8100]"], "Expected one step with a question leak, got \(found)")
    }

    @Test("Verify the fixture reference version and scenario, step, and marker counts")
    func verifyFixtureCoverage() throws {
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
                let context = "\(scenario.name) step \(index + 1) [\(step.name)]"
                #expect([UInt8](hex: step.query) != nil, "\(context), expected query hex, got \(step.query)")
                #expect([UInt8](hex: step.response) != nil, "\(context), expected response hex, got \(step.response)")
                if let reason = step.swiftailDiffers { #expect(!reason.isEmpty, "\(context), expected a reason for the difference, got an empty string") }
            }
        }
    }

    // MARK: - Scenario comparison

    private func compareScenario(_ scenario: GoDNSScenario, fixture: GoDNSFixture, legacyCapabilities: Bool) throws {
        let now = Date(timeIntervalSince1970: TimeInterval(fixture.soaSerial))
        let netmap = scenario.nodes.isEmpty
            ? nil : try makeNetmap(scenario, now: now, legacyCapabilities: legacyCapabilities, forZones: false)
        let resolver = MagicDNSResolver(netmap: netmap, localZones: scenario.localDomains)

        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) step \(index + 1) [\(step.name)]"
            let query = try #require([UInt8](hex: step.query), "\(context), expected query hex, got \(step.query)")
            let actual = resolver.response(to: query, at: now)
            let expected: [UInt8]
            if let reason = step.swiftailDiffers {
                expected = try contractResponse(reason: reason, query: query, fixture: fixture, context: context)
            } else {
                let goResponse = try #require([UInt8](hex: step.response), "\(context), expected response hex, got \(step.response)")
                expected = try Self.hasStaleQuestion(query: query, goResponse: goResponse)
                    ? Self.droppingQuestion(from: goResponse) : goResponse
            }
            for difference in Self.differences(expected: expected, actual: actual) {
                Issue.record("\(context): \(difference)")
            }
        }
    }

    // MARK: - Netmap conversion

    private func makeNetmap(_ scenario: GoDNSScenario, now: Date, legacyCapabilities: Bool, forZones: Bool) throws -> Netmap {
        func node(_ value: GoDNSNode, id: Int64, isSelf: Bool) -> GoFixtureNode {
            GoFixtureNode(
                id: id, name: value.name, addresses: value.addresses.map(Self.cidr), allowedIPs: nil,
                capabilities: isSelf && !legacyCapabilities ? scenario.capabilities : [],
                legacyCapabilities: isSelf && legacyCapabilities ? scenario.capabilities : [])
        }
        let selfIndex = try #require(scenario.nodes.firstIndex { $0.isSelf == true }, "\(scenario.name), expected a local node, got none")
        let peers = scenario.nodes.enumerated().filter { $0.offset != selfIndex }
        return try makeGoFixtureNetmap(
            selfNode: node(scenario.nodes[selfIndex], id: Int64(selfIndex + 1), isSelf: true),
            peers: peers.map { node($0.element, id: Int64($0.offset + 1), isSelf: false) },
            dnsConfigJSON: dnsConfigJSON(scenario), receivedAt: now)
    }

    /// The `DNSConfig` JSON representing the fixture's `hosts` and `localDomains`.
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

    // MARK: - Contract expectations for marked steps

    /// Swiftail response bytes under the contract behavior (D8) cited by the marker reason.
    private func contractResponse(reason: String, query: [UInt8], fixture: GoDNSFixture, context: String) throws -> [UInt8] {
        guard reason.contains("D8") else {
            Issue.record("\(context), no basis for an expected value (reason \(reason))")
            return []
        }
        if reason.contains("SERVFAIL") {
            // A name with no local answer outside `localZones` yields SERVFAIL (with the question, AA=1, and RA from the query). Behavior D5.
            return Self.servfailShape(query: query)
        }
        if reason.contains("NXDOMAIN") {
            // An unknown name inside the zone yields NXDOMAIN + the zone's SOA. Behavior D2. Take the SOA from a Go response for the same zone.
            let base = try #require(fixture.scenarios.first, "Expected a scenario, got none")
            let reference = try #require(base.steps.first { $0.name == "Unknown local name" }, "Expected the unknown local name step, got none")
            return try Self.nxdomainShape(query: query, reference: reference)
        }
        Issue.record("\(context), no basis for an expected value (reason \(reason))")
        return []
    }

    /// Builds a response by copying the query header, setting QR=1, AA=1, and RCODE=2, and including the question. The query must be a header + one question.
    private static func servfailShape(query: [UInt8]) -> [UInt8] {
        let flags = (UInt16(query[2]) << 8 | UInt16(query[3])) & ~0x000F | 0x8000 | 0x0400 | 0x0002
        return [query[0], query[1], UInt8(flags >> 8), UInt8(flags & 0xFF), 0, 1, 0, 0, 0, 0, 0, 0] + query[12...]
    }

    /// Builds a response by copying the query header, setting QR=1, AA=1, RA=1 if RD is set, and RCODE=3, and including the question and the `reference` response's authority section (SOA).
    private static func nxdomainShape(query: [UInt8], reference: GoDNSStep) throws -> [UInt8] {
        let referenceQuery = try #require([UInt8](hex: reference.query), "Expected reference query hex, got \(reference.query)")
        let referenceResponse = try #require([UInt8](hex: reference.response), "Expected reference response hex, got \(reference.response)")
        var flags = (UInt16(query[2]) << 8 | UInt16(query[3])) & ~0x000F | 0x8000 | 0x0400 | 0x0003
        if flags & 0x0100 != 0 { flags |= 0x0080 }
        // Reference response = header + question + authority section. Reference query = header + question.
        return [query[0], query[1], UInt8(flags >> 8), UInt8(flags & 0xFF), 0, 1, 0, 0, 0, 1, 0, 0]
            + query[12...] + referenceResponse[referenceQuery.count...]
    }

    // MARK: - Unmarked difference when Go includes the previous query's question

    /// Whether Go's response includes a question for queries with the response bit (QR) set or shorter than 12 bytes.
    ///
    /// When Go returns FORMERR for such a query, the response includes the **previous query's question** left in a reused parser (another app's query name
    /// may leak). Swiftail replies without a question. The contract's "Decisions made in the responder implementation" (M5-1) records this as an intentional difference
    /// from Go. The fixture omits `swiftailDiffers` for this step (a missing marker), so use the contract expectation (a reply without a question).
    private static func hasStaleQuestion(query: [UInt8], goResponse: [UInt8]) throws -> Bool {
        let short = query.count < 12
        let responseBit = query.count >= 3 && query[2] & 0x80 != 0
        guard short || responseBit else { return false }
        return try !GoDNSMessage(parsing: goResponse).questions.isEmpty
    }

    /// Removes one question (uncompressed name + TYPE + CLASS) from the response and sets QDCOUNT to 0.
    private static func droppingQuestion(from response: [UInt8]) -> [UInt8] {
        var end = 12
        while end < response.count, response[end] != 0 { end += Int(response[end]) + 1 }
        end += 1 + 4
        return Array(response[0..<4]) + [0, 0] + Array(response[6..<12]) + Array(response[end...])
    }

    // MARK: - Comparison

    /// Lists differences for one response. An empty list means the bytes match.
    private static func differences(expected: [UInt8], actual: [UInt8]) -> [String] {
        if expected == actual { return [] }
        let expectedMessage: GoDNSMessage
        let actualMessage: GoDNSMessage
        do {
            expectedMessage = try GoDNSMessage(parsing: expected)
        } catch {
            return ["Could not parse the expected response (\(error)), expected \(expected.hex)"]
        }
        do {
            actualMessage = try GoDNSMessage(parsing: actual)
        } catch {
            return ["Could not parse the actual response (\(error)), expected \(expectedMessage.rendered), got hex \(actual.hex)"]
        }
        let meaning = expectedMessage.meaningDifferences(from: actualMessage)
        if !meaning.isEmpty {
            return ["Different meaning, \(meaning.joined(separator: "; ")) | expected \(expectedMessage.rendered), got \(actualMessage.rendered)"]
        }
        // The meaning matches but the bytes differ. Identify what differs.
        var kinds = expectedMessage.byteDifferenceKinds(from: actualMessage)
        if kinds.isEmpty { kinds = ["encoding (compression or field layout)"] }
        let offset = zip(expected, actual).enumerated().first { $0.element.0 != $0.element.1 }?.offset ?? min(expected.count, actual.count)
        return ["Same meaning, different bytes [\(kinds.joined(separator: ", "))], expected length \(expected.count), got \(actual.count), first differing offset \(offset), expected \(expectedMessage.rendered), got \(actualMessage.rendered)"]
    }
}

// MARK: - DNS message parsing (test-only, independent of the codec)

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
        /// Canonical address text for A and AAAA, a name for PTR, `ns mbox serial refresh retry expire minimum` for SOA, and hex for other types.
        var value: String
    }

    var id: Int
    var flags: Int
    var questions: [Question]
    var answers: [Record]
    var authorities: [Record]
    var additionals: [Record]

    init(parsing bytes: [UInt8]) throws {
        guard bytes.count >= 12 else { throw GoDNSParseError(description: "Shorter than the 12-byte header (\(bytes.count))") }
        func u16(_ at: Int) -> Int { Int(bytes[at]) << 8 | Int(bytes[at + 1]) }
        id = u16(0)
        flags = u16(2)
        let counts = [u16(4), u16(6), u16(8), u16(10)]
        var offset = 12

        questions = []
        for _ in 0..<counts[0] {
            let (name, next) = try Self.readName(bytes, at: offset)
            guard next + 4 <= bytes.count else { throw GoDNSParseError(description: "Truncated question") }
            questions.append(Question(name: name, type: u16(next), cls: u16(next + 2)))
            offset = next + 4
        }
        var sections: [[Record]] = []
        for count in counts[1...] {
            var records: [Record] = []
            for _ in 0..<count {
                let (name, next) = try Self.readName(bytes, at: offset)
                guard next + 10 <= bytes.count else { throw GoDNSParseError(description: "Truncated record header") }
                let type = u16(next)
                let ttl = u16(next + 4) << 16 | u16(next + 6)
                let length = u16(next + 8)
                let start = next + 10
                guard start + length <= bytes.count else { throw GoDNSParseError(description: "Truncated RDATA") }
                let value = try Self.readValue(bytes, type: type, start: start, length: length)
                records.append(Record(name: name, type: type, cls: u16(next + 2), ttl: ttl, value: value))
                offset = start + length
            }
            sections.append(records)
        }
        answers = sections[0]
        authorities = sections[1]
        additionals = sections[2]
        guard offset == bytes.count else { throw GoDNSParseError(description: "\(bytes.count - offset) bytes remain after the sections") }
    }

    /// Builds a message matching the fixture's `decoded`.
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

    /// A single human-readable line.
    var rendered: String {
        func records(_ values: [Record]) -> String {
            values.map { "\($0.type) \($0.name) c\($0.cls) ttl\($0.ttl) \($0.value)" }.joined(separator: " | ")
        }
        return "{id=\(id) flags=0x\(String(flags, radix: 16)) rcode=\(rcode) Q=[\(questions.map { "\($0.name) t\($0.type) c\($0.cls)" }.joined(separator: " | "))] AN=[\(records(answers))] NS=[\(records(authorities))] AR=[\(records(additionals))]}"
    }

    // MARK: Semantic comparison

    /// Semantic differences in ID, flags, questions (case-insensitive names), and record groups (ignoring order and SOA SERIAL).
    func meaningDifferences(from other: GoDNSMessage) -> [String] {
        var result: [String] = []
        if id != other.id { result.append("ID expected \(id), got \(other.id)") }
        if flags != other.flags { result.append("Flags expected 0x\(String(flags, radix: 16)), got 0x\(String(other.flags, radix: 16))(\(flagDifference(other.flags)))") }
        if questions.map(\.normalized) != other.questions.map(\.normalized) { result.append("Questions differ") }
        for (label, mine, theirs) in [("Answer", answers, other.answers), ("Authority", authorities, other.authorities), ("Additional", additionals, other.additionals)]
        where mine.map(\.normalized).sorted() != theirs.map(\.normalized).sorted() {
            result.append("\(label) records differ")
        }
        return result
    }

    private func flagDifference(_ other: Int) -> String {
        let names: [(Int, String)] = [(0x8000, "QR"), (0x0400, "AA"), (0x0200, "TC"), (0x0100, "RD"), (0x0080, "RA"), (0x0040, "Z"), (0x0020, "AD"), (0x0010, "CD")]
        var parts = names.filter { (flags ^ other) & $0.0 != 0 }.map { "\($0.1) expected \(flags & $0.0 != 0 ? 1 : 0)" }
        if (flags ^ other) & 0x7800 != 0 { parts.append("Opcode expected \((flags >> 11) & 0xF), got \((other >> 11) & 0xF)") }
        if flags & 0xF != other & 0xF { parts.append("RCODE expected \(flags & 0xF), got \(other & 0xF)") }
        return parts.joined(separator: ", ")
    }

    // MARK: Types of byte differences

    /// How two messages with the same meaning differ in name case, record order, or SOA SERIAL.
    func byteDifferenceKinds(from other: GoDNSMessage) -> [String] {
        var kinds: [String] = []
        let names = questions.map(\.name) + (answers + authorities + additionals).map(\.name)
        let otherNames = other.questions.map(\.name) + (other.answers + other.authorities + other.additionals).map(\.name)
        if names != otherNames, names.map({ $0.lowercased() }) == otherNames.map({ $0.lowercased() }) { kinds.append("name case") }
        if answers != other.answers || authorities != other.authorities {
            let sameSet = answers.map(\.normalized).sorted() == other.answers.map(\.normalized).sorted()
            if sameSet, answers.map(\.normalized) != other.answers.map(\.normalized) { kinds.append("record order") }
        }
        let serial = { (message: GoDNSMessage) in message.authorities.filter { $0.type == 6 }.map(\.value) }
        if serial(self) != serial(other) { kinds.append("SOA value (SERIAL)") }
        return kinds
    }

    // MARK: Reading bytes

    private static func readName(_ bytes: [UInt8], at start: Int) throws -> (String, Int) {
        var labels: [String] = []
        var position = start
        var end: Int?
        var jumps = 0
        while true {
            guard position < bytes.count else { throw GoDNSParseError(description: "Truncated name") }
            let length = Int(bytes[position])
            if length == 0 {
                position += 1
                break
            }
            if length & 0xC0 == 0xC0 {
                guard position + 1 < bytes.count else { throw GoDNSParseError(description: "Truncated pointer") }
                let target = (length & 0x3F) << 8 | Int(bytes[position + 1])
                if end == nil { end = position + 2 }
                jumps += 1
                guard jumps <= 16, target < bytes.count else { throw GoDNSParseError(description: "Invalid pointer") }
                position = target
                continue
            }
            guard length < 64, position + 1 + length <= bytes.count else { throw GoDNSParseError(description: "Invalid label") }
            labels.append(String(decoding: bytes[position + 1..<position + 1 + length], as: UTF8.self))
            position += 1 + length
        }
        return (labels.isEmpty ? "." : labels.joined(separator: ".") + ".", end ?? position)
    }

    private static func readValue(_ bytes: [UInt8], type: Int, start: Int, length: Int) throws -> String {
        let data = Array(bytes[start..<start + length])
        switch type {
        case 1, 28:
            guard let address = IPAddress(bytes: data) else { throw GoDNSParseError(description: "Address length \(length)") }
            return address.description
        case 12:
            return try readName(bytes, at: start).0
        case 6:
            let (ns, afterNS) = try readName(bytes, at: start)
            let (mbox, afterMbox) = try readName(bytes, at: afterNS)
            guard afterMbox + 20 <= bytes.count else { throw GoDNSParseError(description: "Truncated SOA") }
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
    /// Name (case-insensitive), type, class, TTL, and value. Omits SERIAL (the third field) from SOA.
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

// MARK: - Fixture models

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

/// The record's `value` is a string for A, AAAA, and PTR and an object for SOA.
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

    /// The same representation as the parser's `Record.value`.
    func canonical(type: Int) -> String {
        switch self {
        case .text(let text):
            return type == 1 || type == 28 ? (IPAddress(text)?.description ?? text) : text
        case .soa(let soa):
            return "\(soa.ns) \(soa.mbox) \(soa.serial) \(soa.refresh) \(soa.retry) \(soa.expire) \(soa.minimum)"
        }
    }
}
