import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Testing

@Suite("Go 실제 패킷 필터와의 독립 대조")
struct GoFilterComparisonTests {
    @Test("같은 규칙 원문과 패킷 열의 판정을 비교한다", arguments: try loadGoFilterFixtures().scenarios)
    func 판정을대조한다(_ scenario: GoFilterScenario) throws {
        let decoder = JSONDecoder()
        var filter: PacketFilter
        do {
            let rules = try decoder.decode([FilterRule].self, from: Data(scenario.rules.utf8))
            filter = PacketFilter(rules: rules, localAddresses: try addresses(scenario.localAddresses))
        } catch {
            Issue.record("\(scenario.name) 단계 0 [초기화]: 기대=규칙·자기 주소 해독 성공 실제=\(error)")
            return
        }

        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)]"
            do {
                if step.direction == "replace" {
                    let raw = try #require(step.rules, "\(context): 기대=교체 규칙 원문 실제=없음")
                    let local = try #require(step.localAddresses, "\(context): 기대=교체 자기 주소 실제=없음")
                    filter.replaceRules(try decoder.decode([FilterRule].self, from: Data(raw.utf8)),
                                        localAddresses: try addresses(local))
                    continue
                }
                let raw = try #require(step.packet, "\(context): 기대=IP 패킷 hex 실제=없음")
                let bytes = try #require([UInt8](hex: raw), "\(context): 기대=올바른 hex 실제=\(raw)")
                let expected = try expectation(step, context: context)

                // 의도한 해석 차이는 drop으로 뭉개지 않고 정확한 ParseError를 확인한다.
                if let parseError = expected.parseError {
                    do {
                        _ = try IPPacket(parsing: bytes)
                        Issue.record("\(context): 기대=\(parseError) 실제=해석 성공")
                    } catch {
                        #expect(error == parseError, "\(context): 기대=\(parseError) 실제=\(error)")
                    }
                    continue
                }

                let packet: IPPacket
                do {
                    packet = try IPPacket(parsing: bytes)
                } catch {
                    if step.swiftailDiffers == nil && step.direction == "in" {
                        // 표시가 없는 입력의 해석 실패는 계약대로 drop 판정으로 비교한다.
                        #expect(step.verdict == "drop", "\(context): 기대=Go \(step.verdict ?? "없음") 실제=drop(\(error))")
                    } else {
                        Issue.record("\(context): 기대=해석 성공(\(expected.rawValue)) 실제=\(error)")
                    }
                    continue
                }

                if step.direction == "out" {
                    filter.recordOutbound(packet)
                    continue
                }
                #expect(step.direction == "in", "\(context): 기대=in 실제=\(step.direction)")
                if expected == .tsmp {
                    // TSMP 소비는 TailnetEngine.receive의 책임이다. 필터 판정과 혼동하지 않는다.
                    #expect(packet.transportProtocol == .tsmp,
                            "\(context): 기대=tsmp(엔진 소비 대상) 실제=\(packet.transportProtocol)")
                    continue
                }
                if expected == .trimmedAccept {
                    let length = bytes[0] >> 4 == 4
                        ? Int(bytes[2]) * 256 + Int(bytes[3])
                        : 40 + Int(bytes[4]) * 256 + Int(bytes[5])
                    #expect(length < bytes.count, "\(context): 기대=선언 길이 뒤 바이트 있음 실제=\(bytes.count), 선언=\(length)")
                    #expect(packet.bytes == Array(bytes.prefix(length)),
                            "\(context): 기대=선언 길이 \(length)로 자른 바이트 실제=\(packet.bytes.hex)")
                }
                let verdict = filter.checkInbound(packet)
                let actual = verdict == .accept ? "accept" : "drop"
                let wanted = expected == .trimmedAccept ? "accept" : expected.rawValue
                #expect(actual == wanted, "\(context): 기대=\(wanted) 실제=\(actual)(\(verdict))")
            } catch {
                Issue.record("\(context): 기대=자료 해독·적용 성공 실제=\(error)")
            }
        }
    }

    @Test("자료의 기준 버전과 시나리오·단계 수를 확인한다")
    func 자료범위를확인한다() throws {
        let fixture = try loadGoFilterFixtures()
        #expect(fixture.reference == "tailscale.com v1.104.6")
        #expect(fixture.scenarios.count == 91)
        let steps = fixture.scenarios.flatMap(\.steps)
        #expect(steps.count == 2_429)
        #expect(steps.filter { $0.swiftailDiffers != nil }.count == 34)
        #expect(Set(fixture.scenarios.map(\.name)).count == fixture.scenarios.count)
        for scenario in fixture.scenarios {
            #expect(!scenario.steps.isEmpty, "\(scenario.name): 기대=단계 있음 실제=없음")
            for (index, step) in scenario.steps.enumerated() {
                let context = "\(scenario.name) 단계 \(index + 1)"
                #expect(["in", "out", "replace"].contains(step.direction), "\(context): 기대=알려진 방향 실제=\(step.direction)")
                #expect((step.swiftailDiffers == nil) == (step.swiftailExpected == nil),
                        "\(context): 기대=차이 이유와 기대값을 함께 표시 실제=\(step.swiftailDiffers ?? "없음"), \(step.swiftailExpected ?? "없음")")
                if step.direction == "in" {
                    #expect(["accept", "drop"].contains(step.verdict ?? ""), "\(context): 기대=Go 판정 실제=\(step.verdict ?? "없음")")
                }
            }
        }
    }

    private func addresses(_ values: [String]) throws -> [IPAddress] {
        try values.map { try #require(IPAddress($0), "기대=자료의 올바른 자기 주소 실제=\($0)") }
    }

    private func expectation(_ step: GoFilterStep, context: String) throws -> GoFilterExpectation {
        if let reason = step.swiftailDiffers {
            #expect(!reason.isEmpty, "\(context): 기대=차이 이유 실제=빈 문자열")
            let raw = try #require(step.swiftailExpected, "\(context): 기대=Swiftail 계약 기대값 실제=없음")
            return try #require(GoFilterExpectation(rawValue: raw), "\(context): 기대=알려진 계약 동작 실제=\(raw)")
        }
        // 송신은 판정을 비교하지 않고 흐름만 기록한다.
        if step.direction == "out" { return .accept }
        let raw = try #require(step.verdict, "\(context): 기대=Go 판정 실제=없음")
        return try #require(GoFilterExpectation(rawValue: raw), "\(context): 기대=accept/drop 실제=\(raw)")
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
                           "기대=filter-verdicts.json 리소스 실제=없음")
    return try JSONDecoder().decode(GoFilterFixture.self, from: Data(contentsOf: url))
}
