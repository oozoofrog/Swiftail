import CryptoKit
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// 재서명(계약 동작 R7, 결정 L9, 단위 시험 13). 기준은 Go `ResignNKS`를 실행한 `resign` 10개다.
@Suite("재서명")
struct ResigningTests {
    @Test("resign 10개: 같은 결과의 모양과 판정. 줄이지 않은 것은 SigHash까지 같다")
    func goResign() throws {
        let fixtures = try SignatureFixtureFile.load()
        #expect(fixtures.resign.count == 10)
        for item in fixtures.resign {
            let lockKey = try fixtures.signingKey(seed: item.nlKey)
            let nodeKey = try SignatureTesting.nodeKey(item.nodeKey)
            let old = ModelTesting.bytes(item.oldNKS)
            let made = Result { () throws(TKAError) in try NodeKeySignature.resigned(old, for: nodeKey, with: lockKey) }
            guard item.ok else {
                #expect(throws: TKAError.self, "\(item.name)") { try made.get() }
                continue
            }
            let bytes = try made.get()
            #expect((bytes == old) == item.sameAsOld, "\(item.name)")
            let result = try NodeKeySignature(decoding: bytes)
            let goResult = try NodeKeySignature(decoding: ModelTesting.bytes(try #require(item.result)))
            #expect(SignatureTesting.depth(result) == item.depth, "\(item.name)")
            #expect(SignatureTesting.publicKeys(result) == SignatureTesting.publicKeys(goResult), "\(item.name)")
            // 줄인 사슬은 안쪽 서명을 CryptoKit이 새로 만들어 SigHash가 달라진다.
            if goResult.nested == (try? NodeKeySignature(decoding: old)) || item.sameAsOld {
                #expect(ModelTesting.hex(result.signatureHash) == item.sigHash, "\(item.name)")
            }
            // Swift가 만든 것과 Go가 만든 것이 Swift의 검증에서 Go의 판정과 같다(검증되지 않는 것은 그대로 검증되지 않는다).
            let state = try fixtures.state(named: item.authority)
            let verdict = try #require(item.verdict, "\(item.name)")
            #expect(SignatureTesting.verdict(state, nodeKey, bytes) == verdict, "\(item.name)")
            #expect(SignatureTesting.verdict(state, nodeKey, goResult.serialized()) == verdict, "\(item.name)")
        }
    }

    /// 시험 13의 재서명 항목: 같은 키면 그대로, 회전 키가 NL 키인 direct는 통과, credential 사슬과 `WrappingPubkey` 없는 direct는
    /// 만들어지되 검증되지 않음, 16번째 키에서 줄어듦.
    @Test("시험 13의 재서명 항목이 기준 자료에 있다")
    func contractItemsPresent() throws {
        let items = Dictionary(uniqueKeysWithValues: try SignatureFixtureFile.load().resign.map { ($0.name, $0) })
        let expected: [(String, Bool)] = [
            ("same-node-key", true), ("direct-wrapping-is-nl-key", true), ("credential-chain", false),
            ("direct-no-wrapping", false), ("rotation-15-keys", true), ("rotation-16-keys", true),
        ]
        for (name, authorized) in expected {
            let item = try #require(items[name], "\(name)")
            #expect(item.ok && item.verdict?.authorized == authorized, "\(name)")
        }
    }

    @Test("16개째에서 줄인 사슬: 맨 안쪽 direct 위에 가장 최근 14개, 그 위에 새 키. 다시 줄여도 16단을 넘지 않는다")
    func trimming() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let nlKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        var nodeKeys = [SignatureTesting.randomNodeKey()]
        var signature = try SignatureTesting.direct(nodeKeys[0], by: lockKey, wrapping: nlKey.publicKey).serialized()
        for _ in 1...20 {
            let next = SignatureTesting.randomNodeKey()
            signature = try NodeKeySignature.resigned(signature, for: next, with: nlKey)
            nodeKeys.append(next)
            let decoded = try NodeKeySignature(decoding: signature)
            #expect(SignatureTesting.depth(decoded) <= 16)
            let details = try #require(try state.authorize(next, keySignature: signature))
            let previous = Array(nodeKeys.dropLast().reversed())
            // 키가 15개(바깥 포함 16개)를 넘으면 맨 안쪽 direct의 키와 최근 14개만 남는다.
            let expected = previous.count <= 15 ? previous : Array(previous.prefix(14)) + [nodeKeys[0]]
            #expect(details.previousNodeKeys == expected, "\(nodeKeys.count)")
        }
    }

    @Test("Pubkey가 같으면 옛 바이트를 그대로, 읽히지 않는 옛 서명은 오류")
    func verbatimAndUndecodable() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let nodeKey = SignatureTesting.randomNodeKey()
        // 모르는 필드가 든 옛 서명: 다시 쓰면 바이트가 달라지므로 그대로 돌려줬는지가 드러난다.
        let direct = try SignatureTesting.direct(nodeKey, by: lockKey, wrapping: nil).serialized()
        let withUnknownField = [direct[0] + 1] + direct.dropFirst() + [0x07, 0x00]
        #expect(try NodeKeySignature.resigned(withUnknownField, for: nodeKey, with: lockKey) == withUnknownField)
        #expect(throws: TKAError.self) { try NodeKeySignature.resigned([0xa0, 0x00], for: nodeKey, with: lockKey) }
        #expect(throws: TKAError.self) { try NodeKeySignature.resigned([], for: nodeKey, with: lockKey) }
    }
}
