// 기준 바이트와 해시의 일부는 Go 시험에서 옮겼다:
//   tailscale.com v1.104.7 `tka/aum_test.go`의 `TestSerialization`, `tka/state_test.go`의 `TestApplyUpdatesChain`.
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// AUM의 정준 쓰기와 해시(계약 동작 E2~E6, 7절 시험 3, 노트 3.1·3.7·7.1·8.1).
@Suite("AUM 쓰기와 해시")
struct AUMEncodingTests {
    @Test("동작 E4의 기준 바이트(노트 8.1)")
    func baselineBytes() {
        let updateKey = AUM(messageKind: 4, prevAUMHash: nil, keyID: [1], votes: 0, meta: [])
        #expect(ModelTesting.hex(updateKey.serialized()) == "a4010402f60441010600")
        #expect(ModelTesting.hex(AUM(messageKind: 3, prevAUMHash: []).serialized()) == "a201030240")

        var writer = CBORWriter()
        AuthorityState(stateID1: 1 << 40).write(to: &writer)
        #expect(ModelTesting.hex(writer.bytes) == "a401f6028003800" + "41b0000010000000000")
    }

    @Test("Meta는 인코딩한 키 바이트의 사전순으로 쓴다: a, c, bb")
    func metaOrder() {
        let meta = ["bb", "a", "c"].map { MetaEntry(key: Array($0.utf8), value: []) }
        let aum = AUM(messageKind: 4, prevAUMHash: nil, keyID: [1], meta: meta)
        #expect(ModelTesting.hex(aum.serialized()) == "a4010402f604410107a3" + "616160" + "616360" + "62626260")
    }

    /// Go `TestSerialization`(`tka/aum_test.go:17-159`).
    @Test("Go TestSerialization의 AddKey·RemoveKey·UpdateKey와 같은 바이트")
    func goSerialization() throws {
        let cases: [(AUM, String)] = [
            (AUM(messageKind: 1, prevAUMHash: nil, key: TrustedKey(kind: 0, votes: 0, publicKey: nil)), "a3010102f603a301000200 03f6"),
            (AUM(messageKind: 2, prevAUMHash: nil, keyID: [1, 2]), "a3010202f6044201 02"),
            (
                AUM(messageKind: 4, prevAUMHash: nil, keyID: [1, 2], votes: 2, meta: [MetaEntry(key: [0x61], value: [0x62])]),
                "a5010402f60442010206020 7a16161 6162"
            ),
        ]
        for (aum, hex) in cases {
            let expected = ModelTesting.bytes(hex.replacingOccurrences(of: " ", with: ""))
            #expect(aum.serialized() == expected)
            #expect(try AUM(decoding: expected) == aum)
        }
    }

    /// Go `TestSerialization`의 Checkpoint·Signature는 Go의 nil을 null로 쓴다(`DisablementValues`, `Signature`).
    /// Swiftail은 그 둘의 nil과 빈 값을 가리지 않으므로(동작 E6) 다시 쓴 바이트가 다르다. 둘 다 정적 검사에서 떨어진다.
    @Test("Go TestSerialization의 Checkpoint·Signature: 읽히고, 정적 검사에서 떨어진다")
    func goSerializationNilFields() throws {
        let checkpoint = "a3010502420102" + "05a3015820" + String(repeating: "00", count: 32) + "02f6038" + "1a3010102000342 0506"
        let signature = "a3010102f61781a20141010 2f6"
        for hex in [checkpoint, signature] {
            let input = ModelTesting.bytes(hex.replacingOccurrences(of: " ", with: ""))
            // 체크포인트는 `LastAUMHash`가 있어 동작 D8로 디코딩에서 거절한다.
            let result = Result { () throws(TKAError) in try AUM(decoding: input) }
            switch result {
            case .success(let aum):
                #expect(throws: TKAError.invalidAUM) { try aum.validate() }
                #expect(aum.serialized() != input)
            case .failure(let error):
                #expect(error == .invalidStructure && hex == checkpoint)
            }
        }
    }

    /// Go `TestApplyUpdatesChain`(`tka/state_test.go:96-164`)이 적은 AUM 해시. 체크포인트(`57343671…`)는 Go의 nil
    /// `DisablementValues`(null)가 들어 있어 옮기지 않았다(동작 E6).
    @Test("Go TestApplyUpdatesChain의 AUM 해시")
    func goChainHashes() {
        let addKey1234 = AUM(messageKind: 1, prevAUMHash: nil, key: TrustedKey(kind: 1, votes: 0, publicKey: [1, 2, 3, 4]))
        let parent = ModelTesting.bytes("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03")
        let addKey5678 = AUM(messageKind: 1, prevAUMHash: nil, key: TrustedKey(kind: 1, votes: 0, publicKey: [5, 6, 7, 8]))
        let chainedParent = ModelTesting.bytes("f09bda3bb7cf6756ea9adc25770aede4b3ca8142949d6ef5ca0add29af912fd4")
        let cases: [(AUM, String)] = [
            (addKey1234, "53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
            (
                AUM(messageKind: 2, prevAUMHash: parent, keyID: [1, 2, 3, 4]),
                "15d65756abfafbb592279503f40759898590c9c59056be1e2e9f02684c15ba4b"
            ),
            (
                AUM(messageKind: 4, prevAUMHash: parent, keyID: [1, 2, 3, 4], votes: 1, meta: [MetaEntry(key: [0x61], value: [0x62])]),
                "d55458a9c3ed6997439ba5a18b9b62d2c6e5e0c1bb4c61409e92a1281a3b458d"
            ),
            (addKey5678, "f09bda3bb7cf6756ea9adc25770aede4b3ca8142949d6ef5ca0add29af912fd4"),
            (
                AUM(messageKind: 2, prevAUMHash: chainedParent, keyID: [1, 2, 3, 4]),
                "218165fe5f757304b9deaff4ac742890364f5f509e533c74e80e0ce35e44ee1d"
            ),
        ]
        for (aum, hash) in cases {
            #expect(ModelTesting.hex(aum.hash.bytes) == hash)
        }
    }

    @Test("genesis 체크포인트(노트 7.1·8.1): 다시 쓰면 같은 558바이트, 해시와 SigHash가 Go와 같고 서명이 검증된다")
    func genesis() throws {
        let input = try #require(CBORVectorFile.load().vectors.first { $0.name == "genesis 체크포인트" }).input()
        #expect(input.count == 558)
        let aum = try AUM(decoding: input)
        #expect(aum.serialized() == input)
        #expect(aum.hash.text == AUMHashTests.genesisText)
        #expect(aum.hash.bytes == BLAKE2s.hash(input))
        #expect(ModelTesting.hex(aum.signatureHash) == "f34f12d83807a70bd9d7c5bef557ebfa453846cdfff1ce5c60d18d7a9facf325")
        try aum.validate()

        let state = try #require(aum.state)
        #expect(aum.messageKind == 5 && aum.prevAUMHash == nil)
        #expect(state.disablementValues.count == 10 && state.keys.count == 2)
        #expect(state.keys.allSatisfy { $0.kind == 1 && $0.votes == 1 && $0.publicKey?.count == 32 && $0.meta.isEmpty })
        #expect(state.stateID1 == 1_253_033_988_139_371_657 && state.stateID2 == 18_333_649_726_973_670_556)
        let signature = try #require(aum.signatures.first)
        #expect(aum.signatures.count == 1 && signature.keyID == state.keys[0].publicKey)
        #expect(
            Ed25519Verification.isValidZIP215(signature: signature.signature, message: aum.signatureHash, publicKey: signature.keyID)
        )
    }

    @Test("정준이 아닌 입력: 받아들이되 해시는 다시 쓴 바이트의 것이다")
    func nonCanonicalHash() throws {
        let file = try CBORVectorFile.load()
        var nonCanonicalCount = 0
        for vector in file.vectors where vector.aum == "accept" {
            let input = try vector.input()
            guard let aum = try? AUM(decoding: input) else { continue }
            let canonical = aum.serialized()
            #expect(aum.hash.bytes == BLAKE2s.hash(canonical), "\(vector.name)")
            #expect(try AUM(decoding: canonical).serialized() == canonical, "\(vector.name)")
            if canonical != input {
                nonCanonicalCount += 1
                #expect(aum.hash.bytes != BLAKE2s.hash(input), "\(vector.name)")
            }
        }
        #expect(nonCanonicalCount >= 20)
    }

    @Test("SigHash는 서명만 빼고, 해시는 서명을 넣는다")
    func signatureHashExcludesSignatures() {
        var aum = AUM(messageKind: 3, prevAUMHash: nil)
        let unsignedHash = aum.hash.bytes
        aum.signatures = [AUMSignature(keyID: [UInt8](repeating: 7, count: 32), signature: [UInt8](repeating: 8, count: 64))]
        #expect(aum.signatureHash == unsignedHash)
        #expect(aum.hash.bytes != unsignedHash)
        aum.signatures[0].signature[0] = 9
        #expect(aum.signatureHash == unsignedHash)
    }

    @Test("임의의 값: 쓰고 읽으면 같고, 다시 쓰면 같은 바이트, 비정준 인코딩도 같은 정준 바이트가 된다")
    func roundTripProperty() throws {
        var generator = ModelTesting.Generator(random: CBORTesting.Random(state: 0x2a2a))
        for index in 0..<400 {
            let aum = generator.aum()
            let canonical = aum.serialized()
            let decoded = try AUM(decoding: canonical)
            #expect(decoded == aum, "값 \(index)")
            #expect(decoded.serialized() == canonical, "값 \(index)")

            let loose = generator.looseEncoding(of: try CBOR.decode(canonical))
            let looselyDecoded = try AUM(decoding: loose)
            #expect(looselyDecoded == aum, "값 \(index)")
            #expect(looselyDecoded.serialized() == canonical, "값 \(index)")
            #expect(looselyDecoded.hash == aum.hash, "값 \(index)")
        }
    }
}
