// Go(gVisor) 기준 자료와 TCP 세그먼트 코덱의 독립 대조 시험.
//
// 자료(`Fixtures/tcp-segments.json`)는 `Tools/interop/cmd/tcpfixtures`가 gVisor의 `header` 패키지로 만든 IP 패킷 49개와
// 각 사례의 해석 결과다. 사례마다 `go`(gVisor가 실제로 돌려준 값)와 `swiftail`(계약이 정한 기대값)이 있고, 둘이 다르면
// `swiftailDiffers`에 까닭이 있다. 이 시험은 코덱을 쓴 세션과 다른 세션이 썼고, 코덱의 소스를 읽어 기대값을 맞추지 않았다.
//
// 대조 규칙(README "tcpfixtures"를 확인했다):
// - `error`는 빈 문자열(성공)과 `malformed`·`badChecksum`·`notTCP`이며 `TCPSegment.ParseError`와 이름이 같다.
// - 오류 사례의 `decoded`는 Go가 읽은 진단 값이라 견주지 않는다. 성공 사례만 주소·포트·번호·플래그·창·MSS·Window Scale·
//   데이터 길이를 견준다. `flags`는 Go의 8비트 원값이고 코덱은 상태 기계가 쓰는 하위 5비트만 담으므로 `& 0x1F`로 견준다.
// - `mss`는 SYN의 **유효 MSS**(옵션이 없으면 기본값 포함)이고 `windowScale`은 옵션이 없으면 -1이다. SYN이 아니면 둘 다 null.
//   코덱은 광고하지 않은 값을 `nil`로 둔다(`TCPSegment.maximumSegmentSize` 문서). 그래서 MSS 옵션이 없는 SYN은 자료의
//   기본값과 `nil`이 어긋난다. 이것은 표시 없는 차이로 따로 분리하고(`unmarkedDifferences`), 계약 T5의 읽는 규칙(옵션이
//   없으면 IPv4 536·IPv6 1220으로 본다)을 적용한 값은 자료와 같은지 따로 확인한다.
// - 표시된 차이(`swiftailDiffers`)는 `go`와 `swiftail`이 다른 필드를 계산해, 표에 적은 필드와 같은지 보고, 코덱의 결과가
//   그 필드에서 `swiftail`과 같고 `go`와는 다름을 확인한다.

import Foundation
import Testing

import SwiftailBase

@testable import SwiftailNetstack

// MARK: - 자료

/// 자료 파일의 해석 결과 하나(`go` 또는 `swiftail`).
private struct FixtureResult: Decodable, Equatable {
    struct Decoded: Decodable, Equatable {
        var ipVersion: Int
        var source: String
        var destination: String
        var ipHeaderLength: Int
        var sourcePort: UInt16
        var destinationPort: UInt16
        var sequenceNumber: UInt32
        var ackNumber: UInt32
        var flags: UInt8
        var window: UInt16
        var tcpHeaderLength: Int
        var optionsHex: String
        var mss: UInt16?
        var windowScale: Int?
        var dataLength: Int
    }

    var error: String
    var ipChecksumValid: Bool?
    var checksumValid: Bool?
    var decoded: Decoded?
}

private struct FixtureCase: Decodable, Sendable, CustomTestStringConvertible {
    var name: String
    var packet: String
    var go: FixtureResult
    var swiftail: FixtureResult
    var swiftailDiffers: String?

    var testDescription: String { name }
}

private struct FixtureDocument: Decodable {
    var reference: String
    var caseCount: Int
    var cases: [FixtureCase]
}

/// 자료 파일을 읽는다. 파일이 없거나 형식이 다르면 던진다(시험이 조용히 통과하지 않는다).
private func loadTCPSegmentFixture() throws -> FixtureDocument {
    let url = try #require(
        Bundle.module.url(forResource: "tcp-segments", withExtension: "json", subdirectory: "Fixtures"),
        "기대=tcp-segments.json 리소스 실제=없음")
    return try JSONDecoder().decode(FixtureDocument.self, from: Data(contentsOf: url))
}

private func bytes(fromHex text: String) -> [UInt8]? {
    guard text.utf8.count % 2 == 0 else { return nil }
    var result: [UInt8] = []
    result.reserveCapacity(text.utf8.count / 2)
    var high: UInt8?
    for character in text.utf8 {
        let digit: UInt8
        switch character {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): digit = character - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): digit = character - UInt8(ascii: "a") + 10
        default: return nil
        }
        if let value = high {
            result.append(value << 4 | digit)
            high = nil
        } else {
            high = digit
        }
    }
    return result
}

// MARK: - 해석 결과와 기대값의 비교

/// 코덱의 결과를 오류 이름과 세그먼트로 모은 값.
private enum ParseOutcome {
    case segment(TCPSegment)
    case failure(String)

    init(packet: [UInt8]) {
        do throws(TCPSegment.ParseError) {
            self = .segment(try TCPSegment(parsingIPPacket: packet))
        } catch {
            switch error {
            case .malformed: self = .failure("malformed")
            case .badChecksum: self = .failure("badChecksum")
            case .notTCP: self = .failure("notTCP")
            }
        }
    }

    var errorName: String {
        switch self {
        case .segment: ""
        case .failure(let name): name
        }
    }
}

/// MSS를 어떻게 견주는가.
private enum MSSReading {
    /// 코덱이 낸 값을 그대로 자료와 견준다(광고하지 않았으면 nil, 자료는 기본값).
    case literal
    /// 계약 T5의 규칙을 적용한다: SYN에 MSS 옵션이 없으면 IPv4 536·IPv6 1220으로 본다.
    case effective
}

/// 성공으로 읽은 세그먼트와 기대 `decoded`의 차이. 비어 있으면 같다. 항목은 `필드: 기대=… 실제=…`.
private func differences(of segment: TCPSegment, from expected: FixtureResult.Decoded, mss: MSSReading) -> [String] {
    var found: [String] = []
    func check<T: Equatable>(_ field: String, expected: T, actual: T) {
        if expected != actual { found.append("\(field): 기대=\(expected) 실제=\(actual)") }
    }
    let isIPv4 = segment.source.address.isIPv4
    check("ipVersion", expected: expected.ipVersion, actual: isIPv4 ? 4 : 6)
    check("source.address", expected: IPAddress(expected.source), actual: segment.source.address)
    check("destination.address", expected: IPAddress(expected.destination), actual: segment.destination.address)
    check("source.port", expected: expected.sourcePort, actual: segment.source.port)
    check("destination.port", expected: expected.destinationPort, actual: segment.destination.port)
    check("sequenceNumber", expected: expected.sequenceNumber, actual: segment.sequenceNumber.rawValue)
    check("acknowledgmentNumber", expected: expected.ackNumber, actual: segment.acknowledgmentNumber.rawValue)
    check("flags", expected: expected.flags & 0x1F, actual: segment.flags.rawValue)
    check("window", expected: expected.window, actual: segment.window)
    check("dataLength", expected: expected.dataLength, actual: segment.payload.count)
    var actualMSS = segment.maximumSegmentSize
    if mss == .effective, segment.flags.contains(.syn), actualMSS == nil { actualMSS = isIPv4 ? 536 : 1220 }
    check("mss", expected: expected.mss, actual: actualMSS)
    check("windowScale", expected: expected.windowScale.map { $0 < 0 ? nil : UInt8($0) } ?? nil,
          actual: segment.windowScale)
    return found
}

/// `go`와 `swiftail`에서 값이 다른 필드의 이름.
private func differingFields(_ go: FixtureResult, _ swiftail: FixtureResult) -> Set<String> {
    var fields: Set<String> = []
    if go.error != swiftail.error { fields.insert("error") }
    if go.ipChecksumValid != swiftail.ipChecksumValid { fields.insert("ipChecksumValid") }
    if go.checksumValid != swiftail.checksumValid { fields.insert("checksumValid") }
    switch (go.decoded, swiftail.decoded) {
    case (nil, nil):
        break
    case (let left?, let right?):
        if left.mss != right.mss { fields.insert("mss") }
        if left.windowScale != right.windowScale { fields.insert("windowScale") }
        var rest = left
        rest.mss = right.mss
        rest.windowScale = right.windowScale
        if rest != right { fields.insert("decoded(mss·windowScale 밖)") }
    default:
        fields.insert("decoded 유무")
    }
    return fields
}

// MARK: - 시험

@Suite("Go(gVisor) 기준 자료와 TCP 세그먼트 코덱의 대조")
struct GoSegmentComparisonTests {
    /// `swiftailDiffers`가 있는 11개와 차이가 나는 필드. 자료 도구(`tcpfixtures`)가 적은 이유와 README의 설명에서 옮겼다.
    private static let markedDifferences: [String: Set<String>] = [
        "ipv4-mss-zero": ["windowScale"],  // Go는 MSS 0에서 옵션 해석을 멈춰 뒤의 WS를 읽지 않는다
        "ipv6-mss-zero": ["mss", "windowScale"],  // 위와 같고, 기본 MSS도 536과 1220으로 다르다
        "ipv6-no-options": ["mss"],  // 기본 MSS(Go 536, 계약 1220)
        "small-mss": ["mss"],  // Go는 48으로 올리고 코덱은 1을 그대로 둔다
        "unknown-length-zero": ["error"],
        "unknown-length-one": ["error"],
        "unknown-length-outside": ["error"],
        "missing-option-length": ["error"],
        "mss-length-three": ["error"],
        "ws-length-two": ["error"],
        "mss-outside": ["error"],
    ]

    /// 표시 없는 차이: MSS 옵션이 없는 SYN에서 자료는 유효 MSS(기본값)를 적었고 코덱은 `nil`을 낸다.
    /// 계약 T5가 기본값으로 읽는 것은 상태 기계이고, 코덱의 필드는 "광고하지 않으면 nil"이다.
    private static let unmarkedDifferences: Set<String> = ["ipv4-no-options", "ipv6-no-options"]

    /// 자료의 기대값(`malformed`)이 계약과 어긋나 보이는 사례. 계약 "구현에서 정해진 것"(M6-1)은 길이가 규격과 다른 MSS·Window Scale을
    /// 값을 읽지 않고 길이로 건너뛴다고 정했고, 동작 W2가 `malformed`로 버리는 것은 길이가 2보다 작거나 머리 밖으로 나가는
    /// 옵션뿐이다. 이 두 사례의 옵션(`02 03 01 01`, `03 02 01 01`)은 둘 다 길이 2 이상이고 머리 안이다. 코덱은 건너뛰어 성공으로 읽고,
    /// 그 결과는 Go의 해석(MSS 기본값, Window Scale 없음)과 같다.
    private static let skippedByLengthButExpectedMalformed: Set<String> = ["mss-length-three", "ws-length-two"]

    /// 원본이 Swiftail이 만드는 모양(`ipPacket()`)과 같은 사례. 만든 바이트가 원본과 같아야 한다.
    /// IPv4는 IHL 5·DF·식별자 0·TTL 64, 옵션은 MSS + NOP + Window Scale 순서이고 SYN에만 있다.
    private static let swiftailShapedOriginals: Set<String> = [
        "ipv4-syn-mss-ws", "ipv4-synack", "ipv4-odd-payload", "ipv4-checksum-carries", "ipv4-fin-ack", "ipv4-rst",
        "ipv6-syn-mss-ws", "ipv6-synack", "ipv6-odd-payload", "ipv6-checksum-carries", "ipv6-fin-ack", "ipv6-rst",
        "shift-14",
    ]

    @Test("자료의 머리와 사례 수, 표시 수가 README와 같다")
    func 자료범위를확인한다() throws {
        let fixture = try loadTCPSegmentFixture()
        #expect(fixture.reference.hasPrefix("gvisor.dev/gvisor "), "기대=gVisor 기준 실제=\(fixture.reference)")
        #expect(fixture.caseCount == 49, "기대=caseCount 49 실제=\(fixture.caseCount)")
        #expect(fixture.cases.count == 49, "기대=사례 49개 실제=\(fixture.cases.count)")
        #expect(Set(fixture.cases.map(\.name)).count == fixture.cases.count, "기대=사례 이름이 서로 다름 실제=중복 있음")
        let marked = fixture.cases.filter { $0.swiftailDiffers != nil }
        #expect(marked.count == 11, "기대=표시된 차이 11개 실제=\(marked.count)")
        #expect(Set(marked.map(\.name)) == Set(Self.markedDifferences.keys),
                "기대=표시된 사례 \(Self.markedDifferences.keys.sorted()) 실제=\(marked.map(\.name))")
        for item in fixture.cases {
            #expect(bytes(fromHex: item.packet) != nil, "\(item.name): 기대=소문자 hex 실제=\(item.packet.prefix(40))")
            if let reason = item.swiftailDiffers { #expect(!reason.isEmpty, "\(item.name): 기대=차이 이유 실제=빈 문자열") }
        }
    }

    @Test("표시 없는 사례는 go와 swiftail이 같고, 표시된 사례는 표에 적힌 필드만 다르다(자료의 일관성)", arguments: try loadTCPSegmentFixture().cases)
    fileprivate func 자료가일관된다(_ item: FixtureCase) throws {
        if item.swiftailDiffers == nil {
            #expect(item.go == item.swiftail, "\(item.name): 기대=표시 없으면 go와 swiftail이 같음 실제=\(differingFields(item.go, item.swiftail).sorted())")
        } else {
            let expected = try #require(Self.markedDifferences[item.name], "\(item.name): 기대=차이 표에 있는 사례 실제=없음")
            #expect(differingFields(item.go, item.swiftail) == expected,
                    "\(item.name): 기대=다른 필드 \(expected.sorted()) 실제=\(differingFields(item.go, item.swiftail).sorted())")
        }
        // 오류 이름은 코덱의 세 오류와 성공뿐이다.
        #expect(["", "malformed", "badChecksum", "notTCP"].contains(item.swiftail.error), "\(item.name): 기대=알려진 오류 이름 실제=\(item.swiftail.error)")
        if item.swiftail.error.isEmpty { #expect(item.swiftail.decoded != nil, "\(item.name): 기대=성공이면 decoded 있음 실제=nil") }
    }

    @Test("코덱의 해석이 swiftail 기대값과 같고, 표시된 차이는 그 기대값 쪽에 선다", arguments: try loadTCPSegmentFixture().cases)
    fileprivate func 코덱을대조한다(_ item: FixtureCase) throws {
        let packet = try #require(bytes(fromHex: item.packet), "\(item.name): 기대=hex 실제=\(item.packet.prefix(40))")
        let outcome = ParseOutcome(packet: packet)
        let expected = item.swiftail

        if Self.skippedByLengthButExpectedMalformed.contains(item.name) {
            withKnownIssue("자료는 malformed를 기대하나 계약(M6-1)은 길이로 건너뛰어 성공으로 읽는다") {
                #expect(outcome.errorName == expected.error, "\(item.name): 기대=오류 '\(expected.error)' 실제='\(outcome.errorName)'")
            }
            // 계약대로라면 Go와 같은 성공이다: 오류 없이 읽고, 값은 Go의 해석과 같다(T5 규칙을 적용한 MSS).
            guard case .segment(let segment) = outcome, let goDecoded = item.go.decoded else {
                Issue.record("\(item.name): 기대=계약대로 성공(Go와 같음) 실제=\(outcome.errorName)")
                return
            }
            let againstGo = differences(of: segment, from: goDecoded, mss: .effective)
            #expect(againstGo.isEmpty, "\(item.name): 계약대로 읽은 값이 Go와 다름: \(againstGo.joined(separator: "; "))")
            return
        }
        #expect(outcome.errorName == expected.error, "\(item.name): 기대=오류 '\(expected.error)' 실제='\(outcome.errorName)'")
        guard case .segment(let segment) = outcome, let decoded = expected.decoded, expected.error.isEmpty else { return }

        // 표시 없는 차이는 코덱이 낸 값 그대로 견주는 쪽만 알려진 문제로 둔다. 계약 T5의 읽는 규칙을 적용한 값은 같아야 한다.
        let literal = differences(of: segment, from: decoded, mss: .literal)
        if Self.unmarkedDifferences.contains(item.name) {
            withKnownIssue("MSS 옵션이 없는 SYN: 자료는 유효 MSS(기본값), 코덱은 nil") {
                #expect(literal.isEmpty, "\(item.name): \(literal.joined(separator: "; "))")
            }
            let effective = differences(of: segment, from: decoded, mss: .effective)
            #expect(effective.isEmpty, "\(item.name): T5 규칙을 적용해도 다름: \(effective.joined(separator: "; "))")
        } else {
            #expect(literal.isEmpty, "\(item.name): \(literal.joined(separator: "; "))")
        }

        // 표시된 차이: 다른 필드에서 코덱은 go가 아니라 swiftail 쪽이다.
        if item.swiftailDiffers != nil, let goDecoded = item.go.decoded {
            if goDecoded.mss != decoded.mss, !Self.unmarkedDifferences.contains(item.name) {
                #expect(segment.maximumSegmentSize == decoded.mss && segment.maximumSegmentSize != goDecoded.mss,
                        "\(item.name): MSS 기대=\(String(describing: decoded.mss))(Go \(String(describing: goDecoded.mss))와 다름) 실제=\(String(describing: segment.maximumSegmentSize))")
            }
            if goDecoded.windowScale != decoded.windowScale {
                let actual = segment.windowScale.map(Int.init) ?? -1
                #expect(actual == decoded.windowScale && actual != goDecoded.windowScale,
                        "\(item.name): Window Scale 기대=\(String(describing: decoded.windowScale))(Go \(String(describing: goDecoded.windowScale))와 다름) 실제=\(actual)")
            }
        }
    }

    @Test("표시된 차이는 11개이고, 코덱이 go와 다른 사례는 그중 계약과 자료가 어긋나는 2개를 뺀 9개다")
    func 표시된차이의수를센다() throws {
        let fixture = try loadTCPSegmentFixture()
        var marked = 0
        var codecDiffersFromGo: [String] = []
        for item in fixture.cases {
            if item.swiftailDiffers != nil { marked += 1 }
            let packet = try #require(bytes(fromHex: item.packet), "\(item.name): 기대=hex")
            let outcome = ParseOutcome(packet: packet)
            var differs = outcome.errorName != item.go.error
            if case .segment(let segment) = outcome, let goDecoded = item.go.decoded, item.go.error.isEmpty {
                // 효과적 MSS로 견준다: 광고하지 않은 MSS를 기본값으로 읽는 것은 Go와 같은 의미이므로 차이로 세지 않는다.
                differs = differs || !differences(of: segment, from: goDecoded, mss: .effective).isEmpty
            }
            if differs { codecDiffersFromGo.append(item.name) }
        }
        #expect(marked == 11, "기대=표시된 차이 11개 실제=\(marked)")
        // 표시 없이 go와 다른 사례는 없고, 표시된 사례 중 코덱이 go와 같아 보이는 것은 자료와 계약이 어긋나는 두 개뿐이다.
        let expected = Set(Self.markedDifferences.keys).subtracting(Self.skippedByLengthButExpectedMalformed)
        #expect(Set(codecDiffersFromGo) == expected, "기대=코덱이 go와 다른 사례 \(expected.sorted()) 실제=\(codecDiffersFromGo.sorted())")
    }

    @Test("해석한 세그먼트를 ipPacket()으로 다시 만들어 해석하면 같은 세그먼트다", arguments: try loadTCPSegmentFixture().cases)
    fileprivate func 만들어서다시해석한다(_ item: FixtureCase) throws {
        guard item.swiftail.error.isEmpty else { return }
        let packet = try #require(bytes(fromHex: item.packet), "\(item.name): 기대=hex")
        guard case .segment(let segment) = ParseOutcome(packet: packet) else {
            Issue.record("\(item.name): 기대=해석 성공 실제=\(ParseOutcome(packet: packet).errorName)")
            return
        }
        let rebuilt = try #require(segment.ipPacket(), "\(item.name): 기대=패킷 실제=nil")
        guard case .segment(let again) = ParseOutcome(packet: rebuilt) else {
            Issue.record("\(item.name): 기대=만든 바이트를 해석 성공 실제=\(ParseOutcome(packet: rebuilt).errorName)")
            return
        }
        #expect(again == segment, "\(item.name): 기대=\(segment) 실제=\(again)")
        if Self.swiftailShapedOriginals.contains(item.name) {
            #expect(rebuilt == packet, "\(item.name): 기대=원본과 같은 바이트 실제=다름(원본 \(packet.count)바이트, 만든 것 \(rebuilt.count)바이트)")
        }
    }
}
