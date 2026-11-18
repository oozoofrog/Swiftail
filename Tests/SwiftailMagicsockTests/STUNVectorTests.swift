import Foundation
import Testing

import SwiftailBase
@testable import SwiftailMagicsock

/// Compares the stun section of `magicsock-vectors.json` with `STUNMessage`. `Tools/interop/cmd/magicsockvectors` generates the data using Go's
/// `net/stun` (`stun.Request`, `stun.Response`, `stun.ParseResponse`, `stun.Is`). See `Tools/interop/README.md`.
@Suite("Comparison with STUN reference values")
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

    /// Contains `txID` and `mapped` if Go parsed the response, or `error` (the Go error message) if parsing failed.
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
        try #require([UInt8](hex: hex), "Expected a base-16 string")
    }

    @Test("The binding request matches Go stun.Request byte for byte")
    func requestsMatchGo() throws {
        let requests = try Self.load().requests
        try #require(!requests.isEmpty)
        for request in requests {
            let txID = try #require(TransactionID(try Self.bytes(request.txID)))
            #expect(STUNMessage.bindingRequest(txID) == (try Self.bytes(request.packet)))
        }
    }

    @Test("Response parsing and STUN detection match Go stun.ParseResponse and stun.Is", arguments: try load().parse)
    func parseMatchesGo(_ example: ParseCase) throws {
        let packet = try Self.bytes(example.packet)
        #expect(STUNMessage.looksLikeSTUN(packet) == example.looksLikeSTUN)

        let parsed = STUNMessage.parseBindingResponse(packet)
        if let mapped = example.mapped {
            let txIDHex = try #require(example.txID)
            let expectedTxID = try #require(TransactionID(try Self.bytes(txIDHex)))
            let (txID, endpoint) = try #require(parsed, "Go parsed the response")
            #expect(txID == expectedTxID)
            let expectedEndpoint = try #require(IPEndpoint(mapped))
            #expect(endpoint == expectedEndpoint)
        } else {
            #expect(example.error != nil)
            #expect(parsed == nil, "Go rejected the response: \(example.error ?? "")")
        }
    }

    @Test("The data contains 1 request and 22 parsing cases")
    func fixtureSize() throws {
        let stun = try Self.load()
        #expect(stun.requests.count == 1)
        #expect(stun.parse.count == 22)
    }
}
