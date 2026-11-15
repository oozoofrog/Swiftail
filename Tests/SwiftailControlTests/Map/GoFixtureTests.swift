import Foundation
import SwiftailBase
import SwiftailControl
import Testing

@Suite("Go 실제 맵 세션·요청과의 독립 비교")
struct GoFixtureTests {
    @Test("맵 응답 원문을 순서대로 적용한다", arguments: try loadGoFixtures("map-sessions", as: [GoMapScenario].self))
    func maps(_ scenario: GoMapScenario) throws {
        try check(scenario, framed: false)
    }

    @Test("조각난 리틀엔디언 프레임도 같은 맵을 만든다", arguments: try loadGoFixtures("map-sessions", as: [GoMapScenario].self))
    func framedMaps(_ scenario: GoMapScenario) throws {
        try check(scenario, framed: true)
    }

    private func check(_ scenario: GoMapScenario, framed: Bool) throws {
        var session = MapSession()
        var wasLockEnabled = false
        var current: Netmap?
        var framer = MapResponseFramer()
        var random = SeededRandom(seed: 0x6D61_7066_6978_0001)
        let now = try goFixtureDate("2026-01-02T03:04:05.123456789Z")
        for (index, step) in scenario.steps.enumerated() {
            let context = "\(scenario.name) 단계 \(index + 1) [\(step.name)] \(framed ? "프레임" : "원문")"
            do {
                let raw = Data(step.response.utf8)
                let response: MapResponse
                if framed {
                    let bytes = goFrame(Array(raw))
                    var responses: [MapResponse] = []
                    var offset = 0
                    while offset < bytes.count {
                        // 접두도 쪼개고, JSON 중간에서도 끊는다. 고정 시드로 재현한다.
                        let count = min(Int.random(in: 1...113, using: &random), bytes.count - offset)
                        responses += try framer.receive(Array(bytes[offset..<offset + count]))
                        offset += count
                    }
                    #expect(responses.count == 1, "\(context): 응답 수 기대=1 실제=\(responses.count)")
                    response = try #require(responses.first, "\(context): 완성된 응답 없음")
                    #expect(response == (try JSONDecoder().decode(MapResponse.self, from: raw)),
                            "\(context): 프레이머와 원문 해독 결과가 다름")
                } else {
                    // 자료의 response를 재부호화하지 않는다. 생략·null·빈 배열을 보존한다.
                    response = try JSONDecoder().decode(MapResponse.self, from: raw)
                }
                let update = try session.apply(response, receivedAt: now)
                // Go의 netmap은 `TKAEnabled`를 담는다. Swift는 그것을 netmap 밖(`serverLock`)에 두므로, Go가 보는
                // "바뀜"은 netmap이 바뀌었거나 서버가 알린 lock의 켜짐이 바뀐 것이다.
                let changed = update.netmap != nil || update.serverLock.isEnabled != wasLockEnabled
                wasLockEnabled = update.serverLock.isEnabled
                current = update.netmap ?? current
                if step.netmap == .null {
                    #expect(!changed, "\(context) $.netmap: 기대=null(변화 없음), 실제=netmap 있음")
                } else if changed, let map = current {
                    try compareGoJSON(comparableGoNetmap(step.netmap),
                                      projectGoNetmap(map, tkaEnabled: update.serverLock.isEnabled),
                                      context: context, netmap: true)
                } else {
                    Issue.record("\(context) $.netmap: 기대=정규화 객체, 실제=null")
                }
            } catch {
                Issue.record("\(context) $.response: 기대=해독·적용 성공, 실제=\(error)")
            }
        }
    }

    @Test("요청을 채워 Go JSON의 키·값·타입과 비교한다", arguments: try loadGoFixtures("requests", as: [GoRequestCase].self))
    func requests(_ fixture: GoRequestCase) throws {
        let data = try encodeGoRequest(fixture)
        let decoder = JSONDecoder()
        try compareGoJSON(decoder.decode(GoFixtureJSON.self, from: Data(fixture.json.utf8)),
                          decoder.decode(GoFixtureJSON.self, from: data), context: fixture.name)
    }

    @Test("모든 응답에서 한 바이트 삭제·값 타입 변경을 해도 죽지 않는다",
          arguments: try loadGoFixtures("map-sessions", as: [GoMapScenario].self))
    func malformedResponses(_ scenario: GoMapScenario) throws {
        var random = SeededRandom(seed: 0x6D61_7066_6978_0002)
        var completed = 0
        for step in scenario.steps {
            var cut = Array(step.response.utf8)
            let index = Int.random(in: 0..<cut.count, using: &random)
            cut.remove(at: index)
            let value = try JSONDecoder().decode(GoFixtureJSON.self, from: Data(step.response.utf8))
            let changed = changeGoValueType(value, random: &random)
            #expect(changed != value, "\(scenario.name) [\(step.name)]: 변형이 원문과 같음")
            for bytes in [cut, Array(try JSONEncoder().encode(changed))] {
                do {
                    let response = try JSONDecoder().decode(MapResponse.self, from: Data(bytes))
                    var session = MapSession()
                    _ = try session.apply(response, receivedAt: Date(timeIntervalSince1970: 0))
                } catch {
                    // 잘린 JSON·잘못된 타입·첫 self 누락 오류는 허용한다. 프로세스 생존이 검사 대상이다.
                }
                var framer = MapResponseFramer()
                do { _ = try framer.receive(goFrame(bytes)) } catch { }
                completed += 1
            }
        }
        #expect(completed == scenario.steps.count * 2)
    }

    @Test("비교기는 큰 정수·불·null·빈 배열·키 존재를 구분한다")
    func comparisonBoundaries() throws {
        func json(_ text: String) throws -> GoFixtureJSON {
            try JSONDecoder().decode(GoFixtureJSON.self, from: Data(text.utf8))
        }
        #expect(try json("9007199254740992") != json("9007199254740993"))
        #expect(try json("true") != json("1"))
        #expect(try json("false") != json("0"))
        #expect(try json("null") != json("[]"))
        #expect(try json("{}") != json(#"{"x":null}"#))
        #expect(try json(#"{"a":1,"b":[]}"#) == json(#"{"b":[],"a":1}"#))
        let date = try goFixtureDate("2026-01-02T03:04:05.123456789+09:00")
        #expect(abs(date.timeIntervalSince1970 - 1_767_290_645.123456789) < 0.000_001)
        #expect(try goFixtureDate("0001-01-01T00:00:00Z").timeIntervalSince1970 == -62_135_596_800)
        let scenarios = try loadGoFixtures("map-sessions", as: [GoMapScenario].self)
        #expect(scenarios.count == 10)
        #expect(scenarios.reduce(0) { $0 + $1.steps.count } == 73)
        #expect(try loadGoFixtures("requests", as: [GoRequestCase].self).count == 10)
    }
}

private func goFrame(_ bytes: [UInt8]) -> [UInt8] {
    (0..<4).map { UInt8(truncatingIfNeeded: bytes.count >> (8 * $0)) } + bytes
}

/// 중첩 값을 고정 시드로 골라 정확히 하나의 JSON 타입을 바꾼다. 빈 컨테이너도 변형한다.
private func changeGoValueType(_ value: GoFixtureJSON, random: inout SeededRandom) -> GoFixtureJSON {
    switch value {
    case .object(var fields) where !fields.isEmpty:
        let keys = fields.keys.sorted()
        let key = keys[Int.random(in: 0..<keys.count, using: &random)]
        if let child = fields[key] { fields[key] = changeGoValueType(child, random: &random) }
        return .object(fields)
    case .array(var values) where !values.isEmpty:
        let index = Int.random(in: 0..<values.count, using: &random)
        values[index] = changeGoValueType(values[index], random: &random)
        return .array(values)
    case .string: return .bool(false)
    default: return .string("잘못된 타입")
    }
}

/// input의 미지정 필드는 Swift 생성자의 기본값이 아닌 Go zero 값으로 명시한다.
private func encodeGoRequest(_ fixture: GoRequestCase) throws -> Data {
    let input = fixture.input
    let hostInput = try input.field("Hostinfo", default: GoFixtureJSON.null)
    let host: Hostinfo?
    if hostInput == .null { host = nil }
    else {
        let netInput = try hostInput.field("NetInfo", default: GoFixtureJSON.null)
        let net: NetInfo? = netInput == .null ? nil : try NetInfo(
            mappingVariesByDestIP: netInput.field("MappingVariesByDestIP", default: Optional<Bool>.none),
            workingIPv6: netInput.field("WorkingIPv6", default: Optional<Bool>.none),
            osHasIPv6: netInput.field("OSHasIPv6", default: Optional<Bool>.none),
            workingUDP: netInput.field("WorkingUDP", default: Optional<Bool>.none),
            workingICMPv4: netInput.field("WorkingICMPv4", default: Optional<Bool>.none),
            havePortMap: netInput.field("HavePortMap", default: false),
            upnp: netInput.field("UPnP", default: Optional<Bool>.none),
            pmp: netInput.field("PMP", default: Optional<Bool>.none),
            pcp: netInput.field("PCP", default: Optional<Bool>.none),
            preferredDERP: netInput.field("PreferredDERP", default: Int64(0)),
            linkType: netInput.field("LinkType", default: ""),
            derpLatency: netInput.field("DERPLatency", default: [String: Double]()))
        host = try Hostinfo(
            ipnVersion: hostInput.field("IPNVersion", default: ""),
            frontendLogID: hostInput.field("FrontendLogID", default: ""),
            backendLogID: hostInput.field("BackendLogID", default: ""),
            os: hostInput.field("OS", default: ""), osVersion: hostInput.field("OSVersion", default: ""),
            hostname: hostInput.field("Hostname", default: ""), app: hostInput.field("App", default: ""),
            userspace: hostInput.field("Userspace", default: Optional<Bool>.none),
            userspaceRouter: hostInput.field("UserspaceRouter", default: Optional<Bool>.none), netInfo: net)
    }
    let encoder = JSONEncoder()
    switch fixture.type {
    case "RegisterRequest":
        let authInput = try input.field("Auth", default: GoFixtureJSON.null)
        let expiry: String? = try input.field("Expiry", default: Optional<String>.none)
        let signature: String? = try input.field("NodeKeySignature", default: Optional<String>.none)
        let signatureBytes: [UInt8]
        if let signature { signatureBytes = Array(try #require(Data(base64Encoded: signature))) }
        else { signatureBytes = [] }
        let request = try RegisterRequest(
            version: input.field("Version", default: 0), nodeKey: input.field("NodeKey", default: NodePublicKey.zero),
            oldNodeKey: input.field("OldNodeKey", default: NodePublicKey.zero),
            nlKey: input.field("NLKey", default: NLPublicKey.zero),
            auth: authInput == .null ? nil : RegisterResponseAuth(authKey: authInput.field("AuthKey", default: "")),
            expiry: expiry.map(goFixtureDate), followup: input.field("Followup", default: ""), hostinfo: host,
            ephemeral: input.field("Ephemeral", default: false), nodeKeySignature: signatureBytes)
        return try encoder.encode(request)
    case "MapRequest":
        let endpoints: [String] = try input.field("Endpoints", default: [])
        let types: [Int] = try input.field("EndpointTypes", default: [])
        let request = try MapRequest(
            version: input.field("Version", default: 0), compress: input.field("Compress", default: ""),
            keepAlive: input.field("KeepAlive", default: false), nodeKey: input.field("NodeKey", default: NodePublicKey.zero),
            discoKey: input.field("DiscoKey", default: DiscoPublicKey.zero),
            stream: input.field("Stream", default: false), hostinfo: host,
            endpoints: endpoints.map { try #require(IPEndpoint($0)) },
            endpointTypes: types.map { try #require(EndpointType(rawValue: $0)) },
            omitPeers: input.field("OmitPeers", default: false))
        return try encoder.encode(request)
    default:
        throw CocoaError(.coderInvalidValue)
    }
}
