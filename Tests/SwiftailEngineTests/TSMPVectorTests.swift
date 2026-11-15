// TSMP disco 키 광고의 바이트를 Go(`tailscale.com` v1.104.6 `packet.TSMPDiscoKeyAdvertisement`)의 출력과 대조한다.
// 자료는 `Tools/interop/cmd/tsmpvectors`가 만든 `Fixtures/tsmp-vectors.json`이다.

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailEngine

private struct TSMPVectors: Decodable {
    struct Advertisement: Decodable, CustomTestStringConvertible {
        let name: String
        let src: String
        let dst: String
        let key: String
        let packet: String
        var testDescription: String { name }
    }

    struct ParseCase: Decodable, CustomTestStringConvertible {
        let name: String
        let packet: String
        let key: String?
        var testDescription: String { name }
    }

    let advertisements: [Advertisement]
    let parse: [ParseCase]

    static func load() throws -> TSMPVectors {
        let url = try #require(Bundle.module.url(forResource: "tsmp-vectors", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(TSMPVectors.self, from: Data(contentsOf: url))
    }
}

@Suite("TSMP disco 키 광고: Go 대조")
struct TSMPVectorTests {
    @Test("만든 바이트가 Go Marshal과 같다", arguments: try TSMPVectors.load().advertisements)
    fileprivate func marshal(_ vector: TSMPVectors.Advertisement) throws {
        let keyBytes = try #require([UInt8](hex: vector.key))
        let key = try #require(DiscoPublicKey(rawValue: keyBytes))
        let source = try #require(IPAddress(vector.src))
        let destination = try #require(IPAddress(vector.dst))
        let prefix = try #require(IPPrefix(address: source, length: source.bytes.count * 8))
        let advertisement = try #require(TSMPDiscoKeyAdvertisement(selfAddresses: [prefix], destination: destination, key: key))
        #expect(advertisement.bytes.hex == vector.packet)
    }

    @Test("받은 패킷의 해석이 Go AsTSMPDiscoAdvertisement와 같다", arguments: try TSMPVectors.load().parse)
    fileprivate func parse(_ vector: TSMPVectors.ParseCase) throws {
        let bytes = try #require([UInt8](hex: vector.packet))
        let packet = try IPPacket(parsing: bytes)
        let parsed = TSMPDiscoKeyAdvertisement(parsing: packet)
        #expect(parsed?.key.rawValue.hex == vector.key)
    }
}
