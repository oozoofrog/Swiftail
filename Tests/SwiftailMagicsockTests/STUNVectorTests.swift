import Foundation
import Testing

import SwiftailBase
@testable import SwiftailMagicsock

/// `magicsock-vectors.json`의 stun 절을 `STUNMessage`와 대조한다. 자료는 `Tools/interop/cmd/magicsockvectors`가 Go의
/// `net/stun`(`stun.Request`, `stun.Response`, `stun.ParseResponse`, `stun.Is`)으로 만든다(`Tools/interop/README.md`).
@Suite("STUN 기준값 대조")
struct STUNVectorTests {
    struct File: Decodable {
        let stun: STUN
    }

    struct STUN: Decodable {
        let requests: [Request]
        let parse: [ParseCase]
    }

    struct Request: Decodable {
        let txID: String
        let packet: String
    }

    /// Go가 해석에 성공하면 `txID`·`mapped`, 실패하면 `error`(Go의 오류 문장)가 있다.
    struct ParseCase: Decodable, CustomTestStringConvertible {
        let name: String
        let packet: String
        let looksLikeSTUN: Bool
        let txID: String?
        let mapped: String?
        let error: String?

        var testDescription: String { name }
    }

    static func load() throws -> STUN {
        let url = try #require(Bundle.module.url(forResource: "magicsock-vectors", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(File.self, from: Data(contentsOf: url)).stun
    }

    private static func bytes(_ hex: String) throws -> [UInt8] {
        try #require([UInt8](hex: hex), "16진 문자열이 아니다")
    }

    @Test("바인딩 요청이 Go stun.Request와 바이트 단위로 같다")
    func requestsMatchGo() throws {
        let requests = try Self.load().requests
        try #require(!requests.isEmpty)
        for request in requests {
            let txID = try #require(TransactionID(try Self.bytes(request.txID)))
            #expect(STUNMessage.bindingRequest(txID) == (try Self.bytes(request.packet)))
        }
    }

    @Test("응답 해석과 STUN 판정이 Go stun.ParseResponse·stun.Is와 같다", arguments: try load().parse)
    func parseMatchesGo(_ example: ParseCase) throws {
        let packet = try Self.bytes(example.packet)
        #expect(STUNMessage.looksLikeSTUN(packet) == example.looksLikeSTUN)

        let parsed = STUNMessage.parseBindingResponse(packet)
        if let mapped = example.mapped {
            let txIDHex = try #require(example.txID)
            let expectedTxID = try #require(TransactionID(try Self.bytes(txIDHex)))
            let (txID, endpoint) = try #require(parsed, "Go는 해석했다")
            #expect(txID == expectedTxID)
            let expectedEndpoint = try #require(IPEndpoint(mapped))
            #expect(endpoint == expectedEndpoint)
        } else {
            #expect(example.error != nil)
            #expect(parsed == nil, "Go는 거절했다: \(example.error ?? "")")
        }
    }

    @Test("자료에 요청 1개와 해석 사례 22건이 있다")
    func fixtureSize() throws {
        let stun = try Self.load()
        #expect(stun.requests.count == 1)
        #expect(stun.parse.count == 22)
    }
}
