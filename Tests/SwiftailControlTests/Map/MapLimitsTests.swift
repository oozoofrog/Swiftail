// 받는 쪽의 자원 한도: 프레임의 중첩 깊이·값의 수, 실패한 프레이머의 버퍼, 세션이 쥐는 상태의 개수.
// 메모리 한도가 작은 iOS 네트워크 확장에서도 돌아야 하므로 어떤 입력도 프로세스를 죽이거나 무제한으로 쌓이면 안 된다.

import Foundation
import Testing

@testable import SwiftailControl

@Suite("맵 한도")
struct MapLimitsTests {
    /// `{"Node":{"CapMap":{"cap/x":[V]}}}`의 V를 `[`×k + `0` + `]`×k로 채운 페이로드. 전체 깊이는 4 + k다.
    private static func nestedCapMap(depth: Int) -> String {
        let inner = depth - 4
        return #"{"Node":{"CapMap":{"cap/x":["# + String(repeating: "[", count: inner) + "0"
            + String(repeating: "]", count: inner) + "]}}}"
    }

    /// 스택이 stackSize 바이트인 보조 스레드에서 프레이머를 돌린다.
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

    // MARK: 중첩 깊이

    @Test("깊이 한도까지는 해독하고, 넘으면 해독 전에 malformed")
    func nestingDepth() throws {
        let limit = MapResponseFramer.maximumNestingDepth
        #expect(limit == 64)
        var framer = MapResponseFramer()
        let response = try #require(try framer.receive(frame(Self.nestedCapMap(depth: limit))).first)
        #expect(response.node?.capMap["cap/x"]?.count == 1)

        var deeper = MapResponseFramer()
        #expect(throws: MapError.malformed) { try deeper.receive(frame(Self.nestedCapMap(depth: limit + 1))) }
    }

    @Test("검토에서 프로세스를 죽인 깊이 504의 1,033바이트 JSON은 malformed로 끝난다")
    func reviewerDeepJSON() throws {
        let payload = Self.nestedCapMap(depth: 504)
        #expect(payload.utf8.count == 1_033)
        var framer = MapResponseFramer()
        #expect(throws: MapError.malformed) { try framer.receive(frame(payload)) }
    }

    @Test("512KiB 스택의 보조 스레드에서도 한도 직전은 해독하고 초과는 타입 있는 오류다")
    func nestingDepthOnSmallStack() async throws {
        let stack = 512 << 10
        let limit = MapResponseFramer.maximumNestingDepth
        let atLimit = await Self.receiveOnThread(stackSize: stack, frame(Self.nestedCapMap(depth: limit)))
        #expect(try atLimit.get().count == 1)
        for depth in [limit + 1, 504, 10_000] {
            let over = await Self.receiveOnThread(stackSize: stack, frame(Self.nestedCapMap(depth: depth)))
            #expect(throws: MapError.malformed, "깊이 \(depth)") { try over.get() }
        }
    }

    @Test("UTF-16·UTF-32로 쓴 JSON은 해독 전에 malformed (UTF-8로 훑은 깊이가 해독기와 어긋난다)", arguments: [
        String.Encoding.utf16LittleEndian, .utf16BigEndian, .utf32LittleEndian, .utf32BigEndian, .utf16, .utf32,
    ])
    func rejectsNonUTF8(_ encoding: String.Encoding) throws {
        // UTF-8로 훑으면 `"\""` 뒤의 `]`들이 문자열 밖으로, 깊은 배열이 문자열 안으로 보인다.
        // UTF-16으로 해독하면 그 반대여서, 깊이 한도를 넘는 배열이 검사를 지나 해독기에 닿았다.
        let deep = 500
        let text = #"{"Node":{"CapMap":{"cap/x":["\""# + String(repeating: "]", count: deep)
            + #"","# + String(repeating: "[", count: deep) + "0" + String(repeating: "]", count: deep) + "]}}}"
        let payload = Array(try #require(text.data(using: encoding)))
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: payload[...]) }

        var framer = MapResponseFramer()
        let header = (0..<4).map { UInt8((payload.count >> ($0 * 8)) & 0xFF) }
        #expect(throws: MapError.malformed) { try framer.receive(header + payload) }
    }

    @Test("0 바이트가 든 페이로드는 문자열 안이어도 malformed")
    func rejectsNULByte() {
        let payload = Array(#"{"Node":{"Name":"a"#.utf8) + [0] + Array(#"b"}}"#.utf8)
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: payload[...]) }
    }

    @Test("문자열 안의 괄호·쉼표와 이스케이프된 따옴표는 깊이와 값으로 세지 않는다")
    func bracketsInsideStrings() throws {
        let noise = String(repeating: #"[{,\"\\"#, count: 200)
        var framer = MapResponseFramer()
        let response = try #require(try framer.receive(frame(#"{"Domain":"\#(noise)","Node":{"ID":1}}"#)).first)
        #expect(response.domain == String(repeating: #"[{,"\"#, count: 200))
        #expect(response.node?.id == 1)

        // 이스케이프된 역슬래시 뒤의 따옴표는 문자열을 끝낸다. 그 뒤의 괄호는 센다
        // (잘못 세면 문자열 안으로 보고 통과시키며, 깊이 100은 해독기가 그대로 받는다).
        let closesString = #"{"Domain":"a\\","# + Self.nestedCapMap(depth: 100).dropFirst()
        var other = MapResponseFramer()
        #expect(throws: MapError.malformed) { try other.receive(frame(closesString)) }
    }

    // MARK: 값의 수

    @Test("값의 수는 한도까지 받고 하나라도 넘으면 malformed")
    func valueCountBoundary() throws {
        let limit = MapResponseFramer.maximumValueCount
        #expect(limit == 1_000_000)
        func array(_ count: Int) -> ArraySlice<UInt8> {
            ArraySlice(Array(("[" + String(repeating: "0,", count: count - 1) + "0]").utf8))
        }
        try MapResponseFramer.checkShape(of: array(limit))
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: array(limit + 1)) }

        // 객체 멤버도 값이다. 빈 컨테이너는 값을 더하지 않는다.
        let members = "{" + (0..<limit).map { #""k\#($0)":{}"# }.joined(separator: ",") + "}"
        try MapResponseFramer.checkShape(of: ArraySlice(Array(members.utf8)))
        let oneMore = "{" + (0...limit).map { #""k\#($0)":[]"# }.joined(separator: ",") + "}"
        #expect(throws: MapError.malformed) { try MapResponseFramer.checkShape(of: ArraySlice(Array(oneMore.utf8))) }

        // 문자열 안의 쉼표는 세지 않는다.
        let commas = #"[""# + String(repeating: ",", count: limit + 1) + #""]"#
        try MapResponseFramer.checkShape(of: ArraySlice(Array(commas.utf8)))
    }

    @Test("바이트로는 작지만 값이 많은 빈 노드 목록은 해독 전에 거절한다")
    func manyEmptyNodes() throws {
        let count = MapResponseFramer.maximumValueCount
        let payload = #"{"Node":{},"Peers":["# + Array(repeating: "{}", count: count).joined(separator: ",") + "]}"
        #expect(payload.utf8.count < 4 << 20)
        var framer = MapResponseFramer()
        #expect(throws: MapError.malformed) { try framer.receive(frame(payload)) }

        // 검토의 예(빈 노드 20,000개, 60,021바이트)는 한도 안이라 해독한다.
        let small = #"{"Node":{},"Peers":["# + Array(repeating: "{}", count: 20_000).joined(separator: ",") + "]}"
        #expect(small.utf8.count == 60_021)
        var other = MapResponseFramer()
        #expect(try other.receive(frame(small)).first?.peers?.count == 20_000)
    }

    @Test("Go 자료의 응답은 깊이·값 한도 안이다")
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

    // MARK: 프레임 크기

    /// 고치기 전의 한도는 64MiB라 8MiB + 1바이트의 프레임도 받았다.
    @Test("프레임은 정확히 8MiB까지 해독하고 8MiB + 1바이트는 페이로드를 기다리지 않고 frameTooLarge")
    func frameSizeBoundary() throws {
        let limit = 8 << 20
        #expect(MapResponseFramer.maximumFrameSize == limit)
        // 공백으로 채운 8MiB 페이로드. 해독하는 값은 하나다.
        let json = #"{"Domain":"x"}"#
        var payload = Array(json.utf8)
        payload += [UInt8](repeating: UInt8(ascii: " "), count: limit - payload.count)
        var atLimit = MapResponseFramer()
        #expect(try atLimit.receive(frame(payload)).map(\.domain) == ["x"])

        // 한도를 넘는 길이는 페이로드가 오기 전에, 머리 4바이트만 보고 거절한다.
        var over = MapResponseFramer()
        let header = (0..<4).map { UInt8(truncatingIfNeeded: (limit + 1) >> (8 * $0)) }
        #expect(throws: MapError.frameTooLarge) { try over.receive(header) }
        #expect((Mirror(reflecting: over).descendant("buffer") as? [UInt8])?.isEmpty == true)
    }

    // MARK: 실패한 프레이머

    @Test("길이를 거절하면 모은 바이트를 버리고 같은 오류만 기억한다")
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

    // MARK: 세션 상태

    private static func ids(_ range: Range<Int>, _ body: (Int) -> String) -> String {
        range.map(body).joined(separator: ",")
    }

    /// 한도를 넘긴 세션은 상태를 비우고, 그 뒤의 호출도 같은 오류를 낸다.
    private func expectEnded(_ session: inout MapSession) throws {
        #expect(session.netmap == nil)
        #expect(throws: MapError.stateTooLarge) { try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)}"#), receivedAt: receivedAt) }
    }

    @Test("피어는 한도까지 쥐고, 넘기는 증분은 세션을 끝낸다")
    func peerLimit() throws {
        let limit = MapSession.maximumPeerCount
        #expect(limit == 20_000)
        var session = MapSession()
        let full = #"{"Node":\#(selfNodeJSON),"Peers":[\#(Self.ids(2..<limit + 2) { #"{"ID":\#($0)}"# })]}"#
        #expect(try session.apply(mapResponse(full), receivedAt: receivedAt).netmap?.peers.count == limit)
        // 바꾸기와 지우기는 수를 늘리지 않는다.
        _ = try session.apply(mapResponse(#"{"PeersRemoved":[2],"PeersChanged":[{"ID":1000000}]}"#), receivedAt: receivedAt)
        #expect(throws: MapError.stateTooLarge) {
            try session.apply(mapResponse(#"{"PeersChanged":[{"ID":1000001}]}"#), receivedAt: receivedAt)
        }
        try expectEnded(&session)
    }

    @Test("서로 다른 프로필을 작은 증분으로 계속 보내면 한도에서 세션을 끝낸다")
    func userProfileLimit() throws {
        let limit = MapSession.maximumUserProfileCount
        #expect(limit == 40_000)
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)}"#), receivedAt: receivedAt)
        for start in stride(from: 0, to: limit, by: 10_000) {
            let profiles = Self.ids(start..<start + 10_000) { #"{"ID":\#($0 + 1000)}"# }
            _ = try session.apply(mapResponse(#"{"UserProfiles":[\#(profiles)]}"#), receivedAt: receivedAt)
        }
        // 이미 있는 프로필의 갱신은 수를 늘리지 않는다.
        _ = try session.apply(mapResponse(#"{"UserProfiles":[{"ID":1000,"DisplayName":"갱신"}]}"#), receivedAt: receivedAt)
        #expect(throws: MapError.stateTooLarge) {
            try session.apply(mapResponse(#"{"UserProfiles":[{"ID":1}]}"#), receivedAt: receivedAt)
        }
        try expectEnded(&session)
    }

    @Test("이름 붙은 필터는 이름 수 한도를 넘으면 세션을 끝내고, 지운 이름은 세지 않는다")
    func packetFilterNameLimit() throws {
        let limit = MapSession.maximumPacketFilterNameCount
        #expect(limit == 256)
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)}"#), receivedAt: receivedAt)
        for index in 0..<limit {
            _ = try session.apply(mapResponse(#"{"PacketFilters":{"n\#(index)":[{}]}}"#), receivedAt: receivedAt)
        }
        // Go처럼 null은 그 이름을, "*": null은 모든 이름을 지운다. 지운 뒤에는 다시 들어갈 자리가 있다.
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

    @Test("모든 이름의 규칙 수 합이 한도를 넘으면 세션을 끝낸다")
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

    @Test("상태 필드가 없는 응답은 netmap을 다시 만들지 않고 서버 시각만 기록한다")
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

        // 첫 응답 전이면 여전히 missingSelfNode다.
        var fresh = MapSession()
        #expect(throws: MapError.missingSelfNode) { try fresh.apply(mapResponse("{}"), receivedAt: receivedAt) }
    }
}

/// Go 자료에서 응답 원문만 읽는다.
private struct GoFixtureScenarioResponses: Decodable {
    struct Step: Decodable { var response: String }
    var steps: [Step]
}
