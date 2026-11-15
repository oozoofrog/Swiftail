// TSMP disco 키 광고의 바이트와 받은 패킷의 해석을 Go(`tailscale.com` v1.104.6 `packet.TSMPDiscoKeyAdvertisement`,
// `Parsed.Decode`)와 대조한다.
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

    /// Go와 판정이 다른 사례와 그 까닭. 벡터의 `key`는 Go의 판정 그대로다.
    private static let knownDifferences: [String: String] = [
        // `IPPacket`은 IPv6 확장 머리(조각 머리 포함)를 모두 버린다(엔진 계약). Go `decode6Fragment`는 첫 조각의 TSMP를
        // 받는다. Go 피어는 73바이트 광고를 조각내지 않으므로 이 차이로 놓치는 광고는 없다.
        "ipv6-first-fragment-more": "IPv6 첫 조각을 버린다",
        "ipv6-first-fragment-last": "IPv6 조각 머리가 붙은 패킷을 버린다",
    ]

    @Test("받은 패킷의 해석이 Go AsTSMPDiscoAdvertisement와 같다(알려진 차이는 Swiftail이 버리는 쪽)", arguments: try TSMPVectors.load().parse)
    fileprivate func parse(_ vector: TSMPVectors.ParseCase) throws {
        let bytes = try #require([UInt8](hex: vector.packet))
        let parsed = (try? IPPacket(parsing: bytes)).flatMap(TSMPDiscoKeyAdvertisement.init(parsing:))
        if let difference = Self.knownDifferences[vector.name] {
            #expect(vector.key != nil, "Go는 받는다")
            #expect(parsed == nil, "\(difference)")
        } else {
            #expect(parsed?.key.rawValue.hex == vector.key)
        }
    }
}
