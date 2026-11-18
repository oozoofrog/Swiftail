// Independently compares the TCP segment codec with Go (gVisor) reference fixtures.
//
// The fixtures (`Fixtures/tcp-segments.json`) include 62 IP packets built by `Tools/interop/cmd/tcpfixtures` with gVisor's `header` package and
// the decoded result for each case. Each case has `go` (the actual gVisor return value) and `swiftail` (the expectation defined by the contract). When they differ,
// `swiftailDiffers` explains why. A different session from the one that wrote the codec wrote this test without reading the codec source to fit the expectations.
//
// Comparison rules (checked against README "tcpfixtures"):
// - `error` is an empty string (success) or one of `malformed`·`badChecksum`·`notTCP`, matching the names in `TCPSegment.ParseError`.
// - For error cases, `decoded` is a diagnostic value read by Go and is excluded from comparison. For successful cases only, compare addresses, ports, sequence numbers, flags, window, MSS, Window Scale, and
//   payload length. `flags` is Go's raw 8-bit value, and the codec keeps only the 5 low bits used by the state machine, so compare with `& 0x1F`.
// - `mss` is the SYN's **effective MSS** (including the default if the option is missing), and `windowScale` is -1 if the option is absent. Both are null for non-SYN segments.
//   The codec leaves unadvertised values as `nil` (see `TCPSegment.maximumSegmentSize` docs). For a SYN without the MSS option, the fixture's
//   default therefore differs from `nil`. For such cases (`withoutMSSOption`), check that the codec returns `nil` and that applying contract T5's interpretation rule
//   (use 536 for IPv4 and 1220 for IPv6 when the option is absent) matches the fixture.
// - For marked differences (`swiftailDiffers`), compute the fields where `go` and `swiftail` differ, check that they match the listed fields, and confirm that the codec result
//   matches `swiftail` and differs from `go` in those fields.
// - `sackPermitted` is a bool only on SYN and otherwise null. `sackBlocks` is a list of `[left edge, right edge]` only on non-SYN segments and is
//   null on SYN. The codec leaves `sackBlocks` empty on SYN and `sackPermitted` empty on non-SYN segments (added in M6-10a. This part
//   was also updated by the session that wrote the codec).

import Foundation
import Testing

import SwiftailBase

@testable import SwiftailNetstack

// MARK: - Fixtures

/// One decoded result from the fixture file (`go` or `swiftail`).
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
        var sackPermitted: Bool?
        var sackBlocks: [[UInt32]]?
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

/// Reads the fixture file. Throws if the file is missing or has a different format (so the test does not pass silently).
private func loadTCPSegmentFixture() throws -> FixtureDocument {
    let url = try #require(
        Bundle.module.url(forResource: "tcp-segments", withExtension: "json", subdirectory: "Fixtures"),
        "expected=tcp-segments.json resource actual=missing")
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

// MARK: - Comparing decoded and expected results

/// The codec result represented by an error name and segment.
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

/// How to compare MSS.
private enum MSSReading {
    /// Compares codec output directly with the fixture (nil if not advertised, default value in the fixture).
    case literal
    /// Applies the contract T5 rule: if SYN has no MSS option, use 536 for IPv4 and 1220 for IPv6.
    case effective
}

/// Differences between the successfully parsed segment and expected `decoded`. An empty list means they match. Entries use `field: expected=… actual=…`.
private func differences(of segment: TCPSegment, from expected: FixtureResult.Decoded, mss: MSSReading) -> [String] {
    var found: [String] = []
    func check<T: Equatable>(_ field: String, expected: T, actual: T) {
        if expected != actual { found.append("\(field): expected=\(expected) actual=\(actual)") }
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
    let isSynchronize = segment.flags.contains(.syn)
    check("sackPermitted", expected: expected.sackPermitted, actual: isSynchronize ? segment.sackPermitted : nil)
    check("sackBlocks", expected: expected.sackBlocks,
          actual: isSynchronize ? nil : segment.sackBlocks.map { [$0.leftEdge.rawValue, $0.rightEdge.rawValue] })
    if isSynchronize { check("SYN sackBlocks", expected: 0, actual: segment.sackBlocks.count) }
    return found
}

/// Names of fields with different values in `go` and `swiftail`.
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
        if rest != right { fields.insert("decoded (excluding mss and windowScale)") }
    default:
        fields.insert("decoded presence")
    }
    return fields
}

// MARK: - Tests

@Suite("Comparing the TCP segment codec with Go (gVisor) reference fixtures")
struct GoSegmentComparisonTests {
    /// The 11 cases with `swiftailDiffers` and the differing fields. Taken from the reasons recorded by the fixture tool (`tcpfixtures`) and the README explanation.
    private static let markedDifferences: [String: Set<String>] = [
        "ipv4-mss-zero": ["windowScale"],  // Go stops parsing options at MSS 0 and skips the subsequent WS
        "ipv6-mss-zero": ["mss", "windowScale"],  // Same as above, and the default MSS also differs (536 versus 1220)
        "ipv6-no-options": ["mss"],  // Default MSS (Go 536, contract 1220)
        "small-mss": ["mss"],  // Go raises it to 48 and the codec keeps 1
        "unknown-length-zero": ["error"],
        "unknown-length-one": ["error"],
        "unknown-length-outside": ["error"],
        "missing-option-length": ["error"],
        "mss-outside": ["error"],
        "sack-outside": ["error"],  // Go only stops parsing at a SACK that extends past the header
        "sack-five-blocks": ["error"],
    ]

    /// SYNs without the MSS option. The fixture's `mss` is effective MSS (including the default) and the codec field is "nil when not advertised."
    /// The state machine interprets this as the default (contract T5). These cases check that the codec yields nil and interpretation using the default matches the fixture.
    private static let withoutMSSOption: Set<String> = ["ipv4-no-options", "ipv6-no-options", "mss-length-three", "ws-length-two"]

    /// Cases where the original has the same form as Swiftail's `ipPacket()` output. The resulting bytes must match the original.
    /// IPv4 uses IHL 5, DF, identifier 0, and TTL 64. Options appear only on SYN, in the order MSS + NOP + Window Scale.
    private static let swiftailShapedOriginals: Set<String> = [
        "ipv4-syn-mss-ws", "ipv4-synack", "ipv4-odd-payload", "ipv4-checksum-carries", "ipv4-fin-ack", "ipv4-rst",
        "ipv6-syn-mss-ws", "ipv6-synack", "ipv6-odd-payload", "ipv6-checksum-carries", "ipv6-fin-ack", "ipv6-rst",
        "shift-14",
        "ipv4-syn-sack-permitted", "ipv6-syn-sack-permitted", "ipv4-ack-sack-one-block", "ipv6-ack-sack-four-blocks",
        "ipv4-ack-sack-payload",
    ]

    @Test("The fixture header, case count, and marked count match the tool's test (main_test.go)")
    func fixtureCoverage() throws {
        let fixture = try loadTCPSegmentFixture()
        #expect(fixture.reference.hasPrefix("gvisor.dev/gvisor "), "expected=gVisor reference actual=\(fixture.reference)")
        #expect(fixture.caseCount == 62, "expected=caseCount 62 actual=\(fixture.caseCount)")
        #expect(fixture.cases.count == 62, "expected=62 cases actual=\(fixture.cases.count)")
        #expect(Set(fixture.cases.map(\.name)).count == fixture.cases.count, "expected=distinct case names actual=duplicates")
        let marked = fixture.cases.filter { $0.swiftailDiffers != nil }
        #expect(marked.count == 11, "expected=11 marked differences actual=\(marked.count)")
        #expect(Set(marked.map(\.name)) == Set(Self.markedDifferences.keys),
                "expected=marked cases \(Self.markedDifferences.keys.sorted()) actual=\(marked.map(\.name))")
        for item in fixture.cases {
            #expect(bytes(fromHex: item.packet) != nil, "\(item.name): expected=lowercase hex actual=\(item.packet.prefix(40))")
            if let reason = item.swiftailDiffers { #expect(!reason.isEmpty, "\(item.name): expected=reason for difference actual=empty string") }
        }
    }

    @Test("Unmarked cases have matching go and swiftail values, and marked cases differ only in the listed fields (fixture consistency)", arguments: try loadTCPSegmentFixture().cases)
    fileprivate func fixtureIsConsistent(_ item: FixtureCase) throws {
        if item.swiftailDiffers == nil {
            #expect(item.go == item.swiftail, "\(item.name): expected=matching go and swiftail for unmarked case actual=\(differingFields(item.go, item.swiftail).sorted())")
        } else {
            let expected = try #require(Self.markedDifferences[item.name], "\(item.name): expected=case in the difference table actual=missing")
            #expect(differingFields(item.go, item.swiftail) == expected,
                    "\(item.name): expected=differing fields \(expected.sorted()) actual=\(differingFields(item.go, item.swiftail).sorted())")
        }
        // Error names are limited to the codec's three errors and success.
        #expect(["", "malformed", "badChecksum", "notTCP"].contains(item.swiftail.error), "\(item.name): expected=known error name actual=\(item.swiftail.error)")
        if item.swiftail.error.isEmpty { #expect(item.swiftail.decoded != nil, "\(item.name): expected=decoded present on success actual=nil") }
    }

    @Test("The codec parse matches swiftail expectations, including on marked differences", arguments: try loadTCPSegmentFixture().cases)
    fileprivate func codecMatchesFixture(_ item: FixtureCase) throws {
        let packet = try #require(bytes(fromHex: item.packet), "\(item.name): expected=hex actual=\(item.packet.prefix(40))")
        let outcome = ParseOutcome(packet: packet)
        let expected = item.swiftail

        #expect(outcome.errorName == expected.error, "\(item.name): expected=error '\(expected.error)' actual='\(outcome.errorName)'")
        guard case .segment(let segment) = outcome, let decoded = expected.decoded, expected.error.isEmpty else { return }

        if Self.withoutMSSOption.contains(item.name) {
            #expect(segment.maximumSegmentSize == nil, "\(item.name): expected=nil without the MSS option actual=\(String(describing: segment.maximumSegmentSize))")
            let effective = differences(of: segment, from: decoded, mss: .effective)
            #expect(effective.isEmpty, "\(item.name): still differs after applying the T5 rule: \(effective.joined(separator: "; "))")
        } else {
            let literal = differences(of: segment, from: decoded, mss: .literal)
            #expect(literal.isEmpty, "\(item.name): \(literal.joined(separator: "; "))")
        }

        // Marked difference: the codec matches swiftail and differs from go in the differing fields.
        if item.swiftailDiffers != nil, let goDecoded = item.go.decoded {
            if goDecoded.mss != decoded.mss, !Self.withoutMSSOption.contains(item.name) {
                #expect(segment.maximumSegmentSize == decoded.mss && segment.maximumSegmentSize != goDecoded.mss,
                        "\(item.name): MSS expected=\(String(describing: decoded.mss)) (differs from Go \(String(describing: goDecoded.mss))) actual=\(String(describing: segment.maximumSegmentSize))")
            }
            if goDecoded.windowScale != decoded.windowScale {
                let actual = segment.windowScale.map(Int.init) ?? -1
                #expect(actual == decoded.windowScale && actual != goDecoded.windowScale,
                        "\(item.name): Window Scale expected=\(String(describing: decoded.windowScale)) (differs from Go \(String(describing: goDecoded.windowScale))) actual=\(actual)")
            }
        }
    }

    @Test("There are 11 marked differences, and those are exactly the 11 cases where the codec differs from go")
    func markedDifferenceCount() throws {
        let fixture = try loadTCPSegmentFixture()
        var marked = 0
        var codecDiffersFromGo: [String] = []
        for item in fixture.cases {
            if item.swiftailDiffers != nil { marked += 1 }
            let packet = try #require(bytes(fromHex: item.packet), "\(item.name): expected=hex")
            let outcome = ParseOutcome(packet: packet)
            var differs = outcome.errorName != item.go.error
            if case .segment(let segment) = outcome, let goDecoded = item.go.decoded, item.go.error.isEmpty {
                // Compare effective MSS. Using the default for an unadvertised MSS means the same as in Go, so do not count that as a difference.
                differs = differs || !differences(of: segment, from: goDecoded, mss: .effective).isEmpty
            }
            if differs { codecDiffersFromGo.append(item.name) }
        }
        #expect(marked == 11, "expected=11 marked differences actual=\(marked)")
        let expected = Set(Self.markedDifferences.keys)
        #expect(Set(codecDiffersFromGo) == expected, "expected=cases where the codec differs from go \(expected.sorted()) actual=\(codecDiffersFromGo.sorted())")
    }

    @Test("Rebuilding a parsed segment with ipPacket() and parsing it again yields the same segment", arguments: try loadTCPSegmentFixture().cases)
    fileprivate func serializedSegmentParsesBack(_ item: FixtureCase) throws {
        guard item.swiftail.error.isEmpty else { return }
        let packet = try #require(bytes(fromHex: item.packet), "\(item.name): expected=hex")
        guard case .segment(let segment) = ParseOutcome(packet: packet) else {
            Issue.record("\(item.name): expected=successful parse actual=\(ParseOutcome(packet: packet).errorName)")
            return
        }
        let rebuilt = try #require(segment.ipPacket(), "\(item.name): expected=packet actual=nil")
        guard case .segment(let again) = ParseOutcome(packet: rebuilt) else {
            Issue.record("\(item.name): expected=successful parse of rebuilt bytes actual=\(ParseOutcome(packet: rebuilt).errorName)")
            return
        }
        #expect(again == segment, "\(item.name): expected=\(segment) actual=\(again)")
        if Self.swiftailShapedOriginals.contains(item.name) {
            #expect(rebuilt == packet, "\(item.name): expected=original bytes actual=different (original \(packet.count) bytes, rebuilt \(rebuilt.count) bytes)")
        }
    }
}
