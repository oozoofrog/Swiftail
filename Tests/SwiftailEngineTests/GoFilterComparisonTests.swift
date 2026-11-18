import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Testing

@Suite("Independent comparison with the actual Go packet filter")
struct GoFilterComparisonTests {
    @Test("Compare verdicts for the same raw rules and packet sequence", arguments: try loadGoFilterFixtures().scenarios)
    func compareVerdicts(_ scenario: GoFilterScenario) throws {
        let decoder = JSONDecoder()
        var filter: PacketFilter
        do {
            let rules = try decoder.decode([FilterRule].self, from: Data(scenario.rules.utf8))
            filter = PacketFilter(rules: rules, localAddresses: try addresses(scenario.localAddresses))
        } catch {
            Issue.record("\(scenario.name) step 0 [initialization], expected successful decoding of rules and local addresses, got \(error)")
            return
        }

        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) step \(index + 1) [\(step.name)]"
            do {
                if step.direction == "replace" {
                    let raw = try #require(step.rules, "\(context), expected raw replacement rules, got none")
                    let local = try #require(step.localAddresses, "\(context), expected replacement local addresses, got none")
                    filter.replaceRules(try decoder.decode([FilterRule].self, from: Data(raw.utf8)),
                                        localAddresses: try addresses(local))
                    continue
                }
                let raw = try #require(step.packet, "\(context), expected IP packet hex, got none")
                let bytes = try #require([UInt8](hex: raw), "\(context), expected valid hex, got \(raw)")
                let expected = try expectation(step, context: context)

                // Check the exact ParseError for intentional parsing differences instead of treating all of them as drop verdicts.
                if let parseError = expected.parseError {
                    do {
                        _ = try IPPacket(parsing: bytes)
                        Issue.record("\(context), expected \(parseError), got successful parsing")
                    } catch {
                        #expect(error == parseError, "\(context), expected \(parseError), got \(error)")
                    }
                    continue
                }

                let packet: IPPacket
                do {
                    packet = try IPPacket(parsing: bytes)
                } catch {
                    if step.swiftailDiffers == nil && step.direction == "in" {
                        // Compare parsing failures for unmarked inputs as drop verdicts, per the contract.
                        #expect(step.verdict == "drop", "\(context), expected Go \(step.verdict ?? "none"), got drop(\(error))")
                    } else {
                        Issue.record("\(context), expected successful parsing (\(expected.rawValue)), got \(error)")
                    }
                    continue
                }

                if step.direction == "out" {
                    filter.recordOutbound(packet)
                    continue
                }
                #expect(step.direction == "in", "\(context), expected in, got \(step.direction)")
                if expected == .tsmp {
                    // TailnetEngine.receive consumes TSMP. Consumption is separate from the filter verdict.
                    #expect(packet.transportProtocol == .tsmp,
                            "\(context), expected tsmp (for the engine to consume), got \(packet.transportProtocol)")
                    continue
                }
                if expected == .trimmedAccept {
                    let length = bytes[0] >> 4 == 4
                        ? Int(bytes[2]) * 256 + Int(bytes[3])
                        : 40 + Int(bytes[4]) * 256 + Int(bytes[5])
                    #expect(length < bytes.count, "\(context), expected bytes beyond the declared length, got \(bytes.count), declared length \(length)")
                    #expect(packet.bytes == Array(bytes.prefix(length)),
                            "\(context), expected bytes trimmed to the declared length \(length), got \(packet.bytes.hex)")
                }
                let verdict = filter.checkInbound(packet)
                let actual = verdict == .accept ? "accept" : "drop"
                let wanted = expected == .trimmedAccept ? "accept" : expected.rawValue
                #expect(actual == wanted, "\(context), expected \(wanted), got \(actual)(\(verdict))")
            } catch {
                Issue.record("\(context), expected successful decoding and application of fixtures, got \(error)")
            }
        }
    }

    @Test("Verify the fixture reference version and scenario and step counts")
    func verifyFixtureCoverage() throws {
        let fixture = try loadGoFilterFixtures()
        #expect(fixture.reference == "tailscale.com v1.104.6")
        #expect(fixture.scenarios.count == 91)
        let steps = fixture.scenarios.flatMap(\.steps)
        #expect(steps.count == 2_429)
        #expect(steps.filter { $0.swiftailDiffers != nil }.count == 34)
        #expect(Set(fixture.scenarios.map(\.name)).count == fixture.scenarios.count)
        for scenario in fixture.scenarios {
            #expect(!scenario.steps.isEmpty, "\(scenario.name), expected steps, got none")
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) step \(index + 1)"
                #expect(["in", "out", "replace"].contains(step.direction), "\(context), expected a known direction, got \(step.direction)")
                #expect((step.swiftailDiffers == nil) == (step.swiftailExpected == nil),
                        "\(context), expected both a reason for the difference and an expected value, got \(step.swiftailDiffers ?? "none"), \(step.swiftailExpected ?? "none")")
                if step.direction == "in" {
                    #expect(["accept", "drop"].contains(step.verdict ?? ""), "\(context), expected a Go verdict, got \(step.verdict ?? "none")")
                }
            }
        }
    }

    private func addresses(_ values: [String]) throws -> [IPAddress] {
        try values.map { try #require(IPAddress($0), "Expected a valid local address in the fixture, got \($0)") }
    }

    private func expectation(_ step: GoFilterStep, context: String) throws -> GoFilterExpectation {
        if let reason = step.swiftailDiffers {
            #expect(!reason.isEmpty, "\(context), expected a reason for the difference, got an empty string")
            let raw = try #require(step.swiftailExpected, "\(context), expected a Swiftail contract expectation, got none")
            return try #require(GoFilterExpectation(rawValue: raw), "\(context), expected a known contract behavior, got \(raw)")
        }
        // For outbound packets, only record the flow and skip verdict comparison.
        if step.direction == "out" { return .accept }
        let raw = try #require(step.verdict, "\(context), expected a Go verdict, got none")
        return try #require(GoFilterExpectation(rawValue: raw), "\(context), expected accept/drop, got \(raw)")
    }
}

struct GoFilterFixture: Decodable, Sendable {
    let reference: String
    let scenarios: [GoFilterScenario]
}

struct GoFilterScenario: Decodable, Sendable {
    let name: String
    let rules: String
    let localAddresses: [String]
    let steps: [GoFilterStep]
}

struct GoFilterStep: Decodable, Sendable {
    let name: String
    let direction: String
    let packet: String?
    let verdict: String?
    let rules: String?
    let localAddresses: [String]?
    let swiftailDiffers: String?
    let swiftailExpected: String?
}

enum GoFilterExpectation: String {
    case accept, drop, fragment, extensionHeader, malformed, tsmp, trimmedAccept

    var parseError: IPPacket.ParseError? {
        switch self {
        case .fragment: .fragment
        case .extensionHeader: .extensionHeader
        case .malformed: .malformed
        default: nil
        }
    }
}

private func loadGoFilterFixtures() throws -> GoFilterFixture {
    let url = try #require(Bundle.module.url(forResource: "filter-verdicts", withExtension: "json", subdirectory: "Fixtures"),
                           "Expected the filter-verdicts.json resource, got none")
    return try JSONDecoder().decode(GoFilterFixture.self, from: Data(contentsOf: url))
}
