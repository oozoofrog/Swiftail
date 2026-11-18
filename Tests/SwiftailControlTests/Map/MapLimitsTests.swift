// Receive-side resource limits: Frame nesting depth and value count, the buffer of a failed framer, and how much state a session retains.
// This must run in iOS network extensions with tight memory limits, so no input can kill the process or accumulate without bound.

import Foundation
import Testing

@testable import SwiftailControl

@Suite("Map limits")
struct MapLimitsTests {
    /// Payload with V in `{"Node":{"CapMap":{"cap/x":[V]}}}` filled with `[`×k + `0` + `]`×k. The total depth is 4 + k.
    private static func nestedCapMap(depth: Int) -> String {
        let inner = depth - 4
        return #"{"Node":{"CapMap":{"cap/x":["# + String(repeating: "[", count: inner) + "0"
            + String(repeating: "]", count: inner) + "]}}}"
    }

    /// Runs the framer on a helper thread with a stack of stackSize bytes.
    private static func receiveOnThread(stackSize: Int, _ bytes: [UInt8]) async -> Result<[MapResponse], MapError> {
        await withCheckedContinuation { continuation in
            let thread = Thread {
                var framer = MapResponseFramer()
                continuation.resume(returning: Result { () throws(MapError) in try framer.receive(bytes) })
            }
            thread.stackSize = stackSize
            thread.start()
        }
    }

    // MARK: Nesting depth

    @Test("Decodes up to the depth limit and returns malformed before decoding beyond it")
    func nestingDepth() throws {
        let limit = MapResponseFramer.maximumNestingDepth
        #expect(limit == 64)
        var framer = MapResponseFramer()
        let response = try #require(try framer.receive(frame(Self.nestedCapMap(depth: limit))).first)
        #expect(response.node?.capMap["cap/x"]?.count == 1)

        var deeper = MapResponseFramer()
        #expect(throws: MapError.malformed) { try deeper.receive(frame(Self.nestedCapMap(depth: limit + 1))) }
    }

    @Test("The 1,033-byte JSON at depth 504 that killed the process during review yields malformed")
    func reviewerDeepJSON() throws {
        let payload = Self.nestedCapMap(depth: 504)
        #expect(payload.utf8.count == 1_033)
        var framer = MapResponseFramer()
        #expect(throws: MapError.malformed) { try framer.receive(frame(payload)) }
    }

    @Test("A helper thread with a 512KiB stack still decodes just below the limit and returns a typed error above it")
    func nestingDepthOnSmallStack() async throws {
        let stack = 512 << 10
        let limit = MapResponseFramer.maximumNestingDepth
        let atLimit = await Self.receiveOnThread(stackSize: stack, frame(Self.nestedCapMap(depth: limit)))
        #expect(try atLimit.get().count == 1)
        for depth in [limit + 1, 504, 10_000] {
            let over = await Self.receiveOnThread(stackSize: stack, frame(Self.nestedCapMap(depth: depth)))
            #expect(throws: MapError.malformed, "Depth \(depth)") { try over.get() }
        }
    }

    @Test("JSON encoded as UTF-16 or UTF-32 yields malformed before decoding (the UTF-8 depth scan disagrees with the decoder)", arguments: [
        String.Encoding.utf16LittleEndian, .utf16BigEndian, .utf32LittleEndian, .utf32BigEndian, .utf16, .utf32,
    ])
    func rejectsNonUTF8(_ encoding: String.Encoding) throws {
        // When scanning as UTF-8, the `]` after `"\""` appear outside the string, and the deep array appears inside it.
        // Decoding as UTF-16 reverses this, letting an array beyond the depth limit pass the check and reach the decoder.
        let deep = 500
        let text = #"{"Node":{"CapMap":{"cap/x":["\""# + String(repeating: "]", count: deep)
            + #"","# + String(repeating: "[", count: deep) + "0" + String(repeating: "]", count: deep) + "]}}}"
        let payload = Array(try #require(text.data(using: encoding)))
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: payload[...]) }

        var framer = MapResponseFramer()
        let header = (0..<4).map { UInt8((payload.count >> ($0 * 8)) & 0xFF) }
        #expect(throws: MapError.malformed) { try framer.receive(header + payload) }
    }

    @Test("A payload containing a 0 byte yields malformed even inside a string")
    func rejectsNULByte() {
        let payload = Array(#"{"Node":{"Name":"a"#.utf8) + [0] + Array(#"b"}}"#.utf8)
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: payload[...]) }
    }

    @Test("Brackets, commas, and escaped quotes inside strings do not count toward depth or value count")
    func bracketsInsideStrings() throws {
        let noise = String(repeating: #"[{,\"\\"#, count: 200)
        var framer = MapResponseFramer()
        let response = try #require(try framer.receive(frame(#"{"Domain":"\#(noise)","Node":{"ID":1}}"#)).first)
        #expect(response.domain == String(repeating: #"[{,"\"#, count: 200))
        #expect(response.node?.id == 1)

        // A quote after an escaped backslash ends the string. Count the brackets that follow
        // (An incorrect count would treat them as inside the string and let them pass, and the decoder accepts depth 100 as-is).
        let closesString = #"{"Domain":"a\\","# + Self.nestedCapMap(depth: 100).dropFirst()
        var other = MapResponseFramer()
        #expect(throws: MapError.malformed) { try other.receive(frame(closesString)) }
    }

    // MARK: Value count

    @Test("Accepts up to the value limit and returns malformed for even one extra value")
    func valueCountBoundary() throws {
        let limit = MapResponseFramer.maximumValueCount
        #expect(limit == 1_000_000)
        func array(_ count: Int) -> ArraySlice<UInt8> {
            ArraySlice(Array(("[" + String(repeating: "0,", count: count - 1) + "0]").utf8))
        }
        try MapResponseFramer.checkShape(of: array(limit))
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: array(limit + 1)) }

        // Object members are values too. Empty containers do not add values.
        let members = "{" + (0..<limit).map { #""k\#($0)":{}"# }.joined(separator: ",") + "}"
        try MapResponseFramer.checkShape(of: ArraySlice(Array(members.utf8)))
        let oneMore = "{" + (0...limit).map { #""k\#($0)":[]"# }.joined(separator: ",") + "}"
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: ArraySlice(Array(oneMore.utf8))) }

        // Commas inside strings do not count.
        let commas = #"[""# + String(repeating: ",", count: limit + 1) + #""]"#
        try MapResponseFramer.checkShape(of: ArraySlice(Array(commas.utf8)))
    }

    @Test("Rejects a list of empty nodes before decoding when it has many values despite its small byte size")
    func manyEmptyNodes() throws {
        let count = MapResponseFramer.maximumValueCount
        let payload = #"{"Node":{},"Peers":["# + Array(repeating: "{}", count: count).joined(separator: ",") + "]}"
        #expect(payload.utf8.count < 4 << 20)
        var framer = MapResponseFramer()
        #expect(throws: MapError.malformed) { try framer.receive(frame(payload)) }

        // The review example (20,000 empty nodes, 60,021 bytes) is within the limit and decodes.
        let small = #"{"Node":{},"Peers":["# + Array(repeating: "{}", count: 20_000).joined(separator: ",") + "]}"
        #expect(small.utf8.count == 60_021)
        var other = MapResponseFramer()
        #expect(try other.receive(frame(small)).first?.peers?.count == 20_000)
    }

    @Test("Go fixture responses fit within the depth and value limits")
    func goFixturesWithinLimits() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Fixtures/map-sessions.json")
        let scenarios = try JSONDecoder().decode([GoFixtureScenarioResponses].self, from: Data(contentsOf: url))
        var framer = MapResponseFramer()
        let responses = scenarios.flatMap { $0.steps.map(\.response) }
        #expect(responses.count == 73)
        for response in responses {
            #expect(try framer.receive(frame(response)).count == 1)
        }
    }

    // MARK: Frame size

    /// Before the fix, the limit was 64MiB, so it also accepted a frame of 8MiB + 1 byte.
    @Test("Decodes frames up to exactly 8MiB and returns frameTooLarge at 8MiB + 1 byte without waiting for the payload")
    func frameSizeBoundary() throws {
        let limit = 8 << 20
        #expect(MapResponseFramer.maximumFrameSize == limit)
        // An 8MiB payload padded with spaces. Decodes one value.
        let json = #"{"Domain":"x"}"#
        var payload = Array(json.utf8)
        payload += [UInt8](repeating: UInt8(ascii: " "), count: limit - payload.count)
        var atLimit = MapResponseFramer()
        #expect(try atLimit.receive(frame(payload)).map(\.domain) == ["x"])

        // Reject a length over the limit from the 4-byte header alone before the payload arrives.
        var over = MapResponseFramer()
        let header = (0..<4).map { UInt8(truncatingIfNeeded: (limit + 1) >> (8 * $0)) }
        #expect(throws: MapError.frameTooLarge) { try over.receive(header) }
        #expect((Mirror(reflecting: over).descendant("buffer") as? [UInt8])?.isEmpty == true)
    }

    // MARK: Failed framer

    @Test("Rejecting a length drops the accumulated bytes and remembers only the same error")
    func failureDropsBuffer() throws {
        var framer = MapResponseFramer()
        #expect(throws: MapError.frameTooLarge) { try framer.receive([0xFF, 0xFF, 0xFF, 0xFF] + [UInt8](repeating: 0x20, count: 1_000_000)) }
        #expect((Mirror(reflecting: framer).descendant("buffer") as? [UInt8])?.isEmpty == true)
        #expect(throws: MapError.frameTooLarge) { try framer.receive(frame(#"{"KeepAlive":true}"#)) }
        #expect((Mirror(reflecting: framer).descendant("buffer") as? [UInt8])?.isEmpty == true)

        var malformed = MapResponseFramer()
        #expect(throws: MapError.malformed) { try malformed.receive(frame("{") + [UInt8](repeating: 0, count: 1_000)) }
        #expect((Mirror(reflecting: malformed).descendant("buffer") as? [UInt8])?.isEmpty == true)
        #expect(throws: MapError.malformed) { try malformed.receive(frame(#"{"KeepAlive":true}"#)) }
    }

    // MARK: Session state

    private static func ids(_ range: Range<Int>, _ body: (Int) -> String) -> String {
        range.map(body).joined(separator: ",")
    }

    /// A session that exceeds the limit clears its state and returns the same error on later calls.
    private func expectEnded(_ session: inout MapSession) throws {
        #expect(session.netmap == nil)
        #expect(throws: MapError.stateTooLarge) { try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)}"#), receivedAt: receivedAt) }
    }

    @Test("Retains peers up to the limit and ends the session if a delta exceeds it")
    func peerLimit() throws {
        let limit = MapSession.maximumPeerCount
        #expect(limit == 20_000)
        var session = MapSession()
        let full = #"{"Node":\#(selfNodeJSON),"Peers":[\#(Self.ids(2..<limit + 2) { #"{"ID":\#($0)}"# })]}"#
        #expect(try session.apply(mapResponse(full), receivedAt: receivedAt).netmap?.peers.count == limit)
        // Changing and removing peers does not increase the count.
        _ = try session.apply(mapResponse(#"{"PeersRemoved":[2],"PeersChanged":[{"ID":1000000}]}"#), receivedAt: receivedAt)
        #expect(throws: MapError.stateTooLarge) {
            try session.apply(mapResponse(#"{"PeersChanged":[{"ID":1000001}]}"#), receivedAt: receivedAt)
        }
        try expectEnded(&session)
    }

    @Test("Repeated small deltas with distinct profiles end the session at the limit")
    func userProfileLimit() throws {
        let limit = MapSession.maximumUserProfileCount
        #expect(limit == 40_000)
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)}"#), receivedAt: receivedAt)
        for start in stride(from: 0, to: limit, by: 10_000) {
            let profiles = Self.ids(start..<start + 10_000) { #"{"ID":\#($0 + 1000)}"# }
            _ = try session.apply(mapResponse(#"{"UserProfiles":[\#(profiles)]}"#), receivedAt: receivedAt)
        }
        // Updating an existing profile does not increase the count.
        _ = try session.apply(mapResponse(#"{"UserProfiles":[{"ID":1000,"DisplayName":"Updated"}]}"#), receivedAt: receivedAt)
        #expect(throws: MapError.stateTooLarge) {
            try session.apply(mapResponse(#"{"UserProfiles":[{"ID":1}]}"#), receivedAt: receivedAt)
        }
        try expectEnded(&session)
    }

    @Test("Named filters end the session if they exceed the name count limit, and removed names do not count")
    func packetFilterNameLimit() throws {
        let limit = MapSession.maximumPacketFilterNameCount
        #expect(limit == 256)
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)}"#), receivedAt: receivedAt)
        for index in 0..<limit {
            _ = try session.apply(mapResponse(#"{"PacketFilters":{"n\#(index)":[{}]}}"#), receivedAt: receivedAt)
        }
        // As in Go, null removes that name and "*": null removes all names. After removal, there is room for new entries.
        _ = try session.apply(mapResponse(#"{"PacketFilters":{"n0":null}}"#), receivedAt: receivedAt)
        _ = try session.apply(mapResponse(#"{"PacketFilters":{"other":[]}}"#), receivedAt: receivedAt)
        #expect(throws: MapError.stateTooLarge) {
            try session.apply(mapResponse(#"{"PacketFilters":{"one-more":[]}}"#), receivedAt: receivedAt)
        }
        try expectEnded(&session)

        var cleared = MapSession()
        _ = try cleared.apply(mapResponse(#"{"Node":\#(selfNodeJSON),"PacketFilters":{\#(Self.ids(0..<limit) { #""n\#($0)":[]"# })}}"#), receivedAt: receivedAt)
        let netmap = try #require(try cleared.apply(mapResponse(#"{"PacketFilters":{"*":null,"new":[{}]}}"#), receivedAt: receivedAt).netmap)
        #expect(netmap.packetFilter.count == 1)
    }

    @Test("Ends the session when the total rule count across all names exceeds the limit")
    func packetFilterRuleLimit() throws {
        let limit = MapSession.maximumPacketFilterRuleCount
        #expect(limit == 50_000)
        let rules = { (count: Int) in Array(repeating: "{}", count: count).joined(separator: ",") }
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON),"PacketFilter":[\#(rules(limit - 1))]}"#), receivedAt: receivedAt)
        #expect(try session.apply(mapResponse(#"{"PacketFilters":{"x":[{}]}}"#), receivedAt: receivedAt).netmap?.packetFilter.count == limit)
        #expect(throws: MapError.stateTooLarge) {
            try session.apply(mapResponse(#"{"PacketFilters":{"y":[{}]}}"#), receivedAt: receivedAt)
        }
        try expectEnded(&session)
    }

    @Test("A response without state fields only records the server time and does not rebuild the netmap")
    func stateFreeResponse() throws {
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON),"Peers":[\#(peerJSON(2))]}"#), receivedAt: receivedAt)
        let before = try #require(session.netmap)
        let update = try session.apply(mapResponse(#"{"ControlTime":"2026-01-02T03:04:05Z","Peers":[],"PingRequest":{"URL":"https://control.example/ping/3"}}"#), receivedAt: receivedAt)
        #expect(update.netmap == nil)
        #expect(update.pingRequest?.url == "https://control.example/ping/3")
        var expected = before
        expected.controlTime = Date(timeIntervalSince1970: 1_767_323_045)
        #expect(session.netmap == expected)

        // Before the first response, still yields missingSelfNode.
        var fresh = MapSession()
        #expect(throws: MapError.missingSelfNode) { try fresh.apply(mapResponse("{}"), receivedAt: receivedAt) }
    }
}

/// Reads only original responses from the Go fixtures.
private struct GoFixtureScenarioResponses: Decodable {
    struct Step: Decodable { var response: String }
    var steps: [Step]
}
