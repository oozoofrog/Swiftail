import Foundation
import Testing

@testable import SwiftailTKA

/// `Fixtures/tka-fixtures.json`(Go `tka`를 실행한 판정, `Tools/interop/README.md`의 `tkafixtures` 절) 가운데 자료 형식에
/// 해당하는 배열 셋(`text`의 `aumHash.*`, `encodings`, `cbor`). 정식 대조 시험(`GoComparisonTests.swift`)은 따로 쓴다.
struct ModelFixtureFile: Decodable {
    struct Text: Decodable {
        let name: String
        let kind: String
        let input: String
        let ok: Bool
        let output: String?
    }

    struct KeyValue: Decodable {
        let kind: UInt8
        let votes: UInt64
        let `public`: String?
        let meta: [String: String]?

        var trustedKey: TrustedKey {
            TrustedKey(
                kind: kind, votes: votes, publicKey: `public`.map(ModelTesting.bytes),
                meta: (meta ?? [:]).map { MetaEntry(key: Array($0.key.utf8), value: Array($0.value.utf8)) }
            )
        }
    }

    struct StateValue: Decodable {
        let lastAUMHash: String?
        let disablementValues: [String]?
        let keys: [KeyValue]?
        let stateID1: String
        let stateID2: String
    }

    struct Encoding: Decodable {
        let name: String
        let type: String
        let encoded: String
        let key: KeyValue?
        let state: StateValue?

        private enum CodingKeys: String, CodingKey { case name, type, encoded, value }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.decode(String.self, forKey: .name)
            type = try container.decode(String.self, forKey: .type)
            encoded = try container.decode(String.self, forKey: .encoded)
            key = type == "key" ? try container.decode(KeyValue.self, forKey: .value) : nil
            state = type == "state" ? try container.decode(StateValue.self, forKey: .value) : nil
        }
    }

    struct Case: Decodable {
        let name: String
        let type: String
        let input: String
        let decoded: Bool
        let staticValid: Bool?
        let accepted: Bool
        let reencoded: String?
        let hash: String?
        let sigHash: String?
    }

    let text: [Text]
    let encodings: [Encoding]
    let cbor: [Case]

    static func load() throws -> ModelFixtureFile {
        let url = try #require(Bundle.module.url(forResource: "tka-fixtures", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(ModelFixtureFile.self, from: Data(contentsOf: url))
    }
}

@Suite("Go 판정(tka-fixtures.json)과 같은 자료 형식")
struct ModelFixtureTests {
    @Test("AUMHash 텍스트: Go의 쓰기와 읽기")
    func aumHashText() throws {
        let cases = try ModelFixtureFile.load().text.filter { $0.kind.hasPrefix("aumHash.") }
        #expect(cases.count == 24)
        for item in cases {
            if item.kind == "aumHash.encode" {
                #expect(AUMHash(ModelTesting.bytes(item.input))?.text == item.output, "\(item.name)")
            } else {
                let hash = AUMHash(text: item.input)
                // 줄바꿈이 섞인 텍스트는 Go가 잘린 해시로 받고 Swiftail은 거절한다(계약 동작 D10).
                if item.input.contains(where: \.isNewline) {
                    #expect(hash == nil, "\(item.name)")
                    continue
                }
                #expect((hash != nil) == item.ok, "\(item.name)")
                if item.ok { #expect(hash.map { ModelTesting.hex($0.bytes) } == item.output, "\(item.name)") }
            }
        }
    }

    /// `State`의 배열이 Go의 nil(null)인 값은 Swiftail이 빈 배열로 쥐므로 `80`으로 쓴다(동작 E6).
    @Test("Key·State의 정준 바이트")
    func encodings() throws {
        let encodings = try ModelFixtureFile.load().encodings
        #expect(encodings.count == 13)
        for encoding in encodings {
            var writer = CBORWriter()
            var expected = encoding.encoded
            if let key = encoding.key {
                key.trustedKey.write(to: &writer)
            } else {
                let value = try #require(encoding.state, "\(encoding.name)")
                let state = AuthorityState(
                    lastAUMHash: value.lastAUMHash.flatMap { AUMHash(ModelTesting.bytes($0)) },
                    disablementValues: (value.disablementValues ?? []).map(ModelTesting.bytes),
                    keys: (value.keys ?? []).map(\.trustedKey),
                    stateID1: try #require(UInt64(value.stateID1)),
                    stateID2: try #require(UInt64(value.stateID2))
                )
                state.write(to: &writer)
                if value.disablementValues == nil { expected = expected.replacingOccurrences(of: "02f6", with: "0280") }
                if value.keys == nil { expected = expected.replacingOccurrences(of: "03f6", with: "0380") }
            }
            #expect(ModelTesting.hex(writer.bytes) == expected, "\(encoding.name)")
        }
    }

    @Test("CBOR 입력마다 Go와 같은 판정, 받아들인 것은 같은 바이트와 해시")
    func cborCases() throws {
        let cases = try ModelFixtureFile.load().cbor
        #expect(cases.count == 279)
        var decodeDifferences: [String] = []
        var bytesDifferences: [String] = []
        for item in cases {
            let input = ModelTesting.bytes(item.input)
            if item.type == "aum" {
                let aum = try? AUM(decoding: input)
                if (aum != nil) != item.decoded { decodeDifferences.append(item.name) }
                let accepted = aum.map { aum in (try? aum.validate()) != nil } ?? false
                #expect(accepted == item.accepted, "\(item.name)")
                guard let aum, item.decoded else { continue }
                if item.accepted {
                    // 받아들인 AUM은 바이트·해시·SigHash가 Go와 같아야 한다(동작 E5).
                    #expect(ModelTesting.hex(aum.serialized()) == item.reencoded, "\(item.name)")
                    #expect(ModelTesting.hex(aum.hash.bytes) == item.hash, "\(item.name)")
                    #expect(ModelTesting.hex(aum.signatureHash) == item.sigHash, "\(item.name)")
                } else if ModelTesting.hex(aum.serialized()) != item.reencoded {
                    bytesDifferences.append(item.name)
                }
            } else {
                let signature = try? NodeKeySignature(decoding: input)
                #expect((signature != nil) == item.decoded, "\(item.name)")
                guard let signature, item.decoded else { continue }
                #expect(ModelTesting.hex(signature.serialized()) == item.reencoded, "\(item.name)")
                #expect(ModelTesting.hex(signature.signatureHash) == item.sigHash, "\(item.name)")
            }
        }
        // 디코딩 판정이 다른 것은 동작 D8(체크포인트 상태의 null이 아닌 `LastAUMHash`)뿐이다. 둘 다 결국 거절이다.
        #expect(decodeDifferences == ["accept/checkpoint-last-aum-hash-2-bytes", "value/checkpoint-last-aum-hash"])
        // 정적 검사를 통과하지 못한 AUM의 다시 쓴 바이트는 Go의 nil(null)과 빈 값의 차이만큼 다르다(동작 E6):
        // 서명의 KeyID·Signature, `State`의 두 배열.
        #expect(
            bytesDifferences == [
                "probe/signatures-null-element", "probe/signature-fields-null", "probe/checkpoint-state-arrays-null",
                "value/checkpoint-disablement-null", "value/checkpoint-keys-null",
            ]
        )
    }
}
