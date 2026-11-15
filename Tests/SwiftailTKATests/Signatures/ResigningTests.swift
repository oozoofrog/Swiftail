import CryptoKit
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// 재서명(계약 동작 R7, 단위 시험 13, 5절 TL-11b 항목 1). 기준은 Go `ResignNKS`를 실행한 `resign` 10개다.
///
/// TL-11b 항목 1로 Swiftail은 이미 자기 NL 키로 서명한 사슬만 다시 서명한다. Go가 만들던 "검증되지 않는 서명" 셋은 Swiftail이
/// 만들지 않는다(`refusedRows`).
@Suite("재서명")
struct ResigningTests {
    /// Go는 만들고(받는 쪽에서 검증되지 않는다) Swiftail은 거절하는 줄과 그 까닭.
    static let refusedRows: [String: TKAError] = [
        "direct-wrapping-is-other-key": .untrustedSigner, "direct-no-wrapping": .untrustedSigner,
        "credential-chain": .invalidSignature,
    ]

    @Test("resign 10개: 같은 결과의 모양과 판정. 줄이지 않은 것은 SigHash까지 같다. 검증되지 않을 셋은 만들지 않는다")
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
            if let refusal = Self.refusedRows[item.name] {
                #expect(item.verdict?.authorized == false, "\(item.name): Go가 만든 것도 인가되지 않는다")
                #expect(throws: refusal, "\(item.name)") { try made.get() }
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

    /// 시험 13의 재서명 항목: 같은 키면 그대로, 회전 키가 NL 키인 direct는 통과, 16번째 키에서 줄어듦. credential 사슬과
    /// `WrappingPubkey` 없는 direct는 Go가 만들되 검증되지 않고, Swiftail은 만들지 않는다(TL-11b 항목 1).
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
            #expect((Self.refusedRows[name] == nil) == authorized, "\(name)")
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

    // MARK: 재서명 전의 검사(TL-11b 항목 1)

    /// 신뢰 키(`trusted`)가 `nlKey`를 회전 키로 적어 서명한 direct와, 그 위에 rotation `count`겹. 겹마다 `signer(겹 번호)`가
    /// 서명한다(0이 맨 안쪽 겹). 맨 바깥 겹의 node 키는 `outermost`다.
    private static func chain(
        direct nodeKey: NodePublicKey, by trusted: Curve25519.Signing.PrivateKey, wrapping: Curve25519.Signing.PublicKey?,
        layers count: Int, outermost: NodePublicKey? = nil,
        signer: (Int) -> Curve25519.Signing.PrivateKey?
    ) throws -> NodeKeySignature {
        var signature = try SignatureTesting.direct(nodeKey, by: trusted, wrapping: wrapping)
        for layer in 0..<count {
            let key = layer == count - 1 ? outermost ?? SignatureTesting.randomNodeKey() : SignatureTesting.randomNodeKey()
            if let rotationKey = signer(layer) {
                signature = try SignatureTesting.rotation(key, nesting: signature, by: rotationKey)
            } else {
                // 서버가 서명 없이(0으로 채워) 얹은 겹.
                signature = NodeKeySignature(
                    kind: NodeKeySignature.Kind.rotation, publicKey: key.binaryForm,
                    signature: [UInt8](repeating: 0, count: 64), nested: signature
                )
            }
        }
        return signature
    }

    @Test("서버가 고른 node 키 15겹을 얹은 사슬은 다시 서명하지 않는다(서명 오라클이 아니다)")
    func forgedRotationLayers() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [trusted])
        let attackerKey = SignatureTesting.randomNodeKey()
        // 15겹이 디코딩의 한도(direct 위에 rotation 15겹)이고, 15겹이면 재서명이 줄이기를 한다.
        for count in [1, 14, 15] {
            // 맨 안쪽은 이 노드의 진짜 direct(회전 키가 이 노드의 NL 키)다.
            let forged = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: count,
                outermost: attackerKey, signer: { _ in nil }
            )
            #expect(throws: TKAError.invalidSignature, "\(count)겹") {
                try NodeKeySignature.resigned(forged.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
            // 다른 키(공격자의 키)가 서명한 겹도 같다.
            let otherKey = Curve25519.Signing.PrivateKey()
            let signedByOther = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: count,
                outermost: attackerKey, signer: { _ in otherKey }
            )
            #expect(throws: TKAError.invalidSignature, "\(count)겹") {
                try NodeKeySignature.resigned(signedByOther.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
            #expect(throws: TKAError.unauthorized) { try state.authorize(attackerKey, keySignature: forged.serialized()) }
        }
    }

    @Test("한 겹만 NL 키로 검증되지 않아도 다시 서명하지 않는다(맨 안쪽·가운데·맨 바깥)", arguments: [0, 7, 14])
    func oneBadLayer(_ bad: Int) throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        // 15겹이라 재서명하면 줄이기가 일어나는 사슬이다.
        let chain = try Self.chain(
            direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: 15,
            signer: { $0 == bad ? other : nlKey }
        )
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(chain.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
    }

    @Test("맨 안쪽 서명의 WrappingPubkey가 이 노드의 NL 키가 아니거나 없으면 다시 서명하지 않는다")
    func innermostWrappingKey() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        for wrapping in [other.publicKey, nil] {
            // rotation 겹이 없는 direct: 안쪽 `WrappingPubkey`만 본다.
            let direct = try SignatureTesting.direct(SignatureTesting.randomNodeKey(), by: trusted, wrapping: wrapping)
            #expect(throws: TKAError.untrustedSigner) {
                try NodeKeySignature.resigned(direct.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
            // 모든 겹을 NL 키로 서명했어도 맨 안쪽이 이 노드의 NL 키를 적지 않았으면 거절한다.
            let rotated = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: wrapping, layers: 3, signer: { _ in nlKey }
            )
            #expect(throws: TKAError.untrustedSigner) {
                try NodeKeySignature.resigned(rotated.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
        }
    }

    @Test("credential에서 시작하는 사슬(서명된 인증 키로 등록한 노드)은 다시 서명하지 않는다")
    func credentialRoot() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let wrapped = Curve25519.Signing.PrivateKey()
        var credential = NodeKeySignature(
            kind: NodeKeySignature.Kind.credential, keyID: Array(trusted.publicKey.rawRepresentation),
            wrappingPublicKey: Array(wrapped.publicKey.rawRepresentation)
        )
        try credential.sign(with: trusted)
        // 등록할 때 만든 것: 감싼 키가 서명한 rotation(Go `SignByCredential`).
        let registered = try SignatureTesting.rotation(SignatureTesting.randomNodeKey(), nesting: credential, by: wrapped)
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(registered.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
        // 겹을 NL 키가 서명했더라도 맨 안쪽 credential의 회전 키는 감싼 키다.
        let relayed = try SignatureTesting.rotation(SignatureTesting.randomNodeKey(), nesting: credential, by: nlKey)
        #expect(throws: TKAError.untrustedSigner) {
            try NodeKeySignature.resigned(relayed.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
        // credential 하나만.
        #expect(throws: TKAError.untrustedSigner) {
            try NodeKeySignature.resigned(credential.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
    }

    @Test("rotation 아닌 서명으로 끝나지 않는 사슬, 서명이 빈 겹은 다시 서명하지 않는다")
    func malformedChains() throws {
        let nlKey = Curve25519.Signing.PrivateKey()
        // `Nested`가 없는 rotation(NL 키가 서명했다).
        let dangling = try SignatureTesting.rotation(
            SignatureTesting.randomNodeKey(),
            nesting: NodeKeySignature(kind: NodeKeySignature.Kind.rotation, publicKey: SignatureTesting.randomNodeKey().binaryForm),
            by: nlKey
        )
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(dangling.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
        var bare = NodeKeySignature(kind: NodeKeySignature.Kind.rotation, publicKey: SignatureTesting.randomNodeKey().binaryForm)
        try bare.sign(with: nlKey)
        #expect(throws: TKAError.untrustedSigner) {
            try NodeKeySignature.resigned(bare.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
        // 서명 필드가 빈 겹.
        let trusted = Curve25519.Signing.PrivateKey()
        let direct = try SignatureTesting.direct(SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey)
        let unsigned = NodeKeySignature(
            kind: NodeKeySignature.Kind.rotation, publicKey: SignatureTesting.randomNodeKey().binaryForm, nested: direct
        )
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(unsigned.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
    }

    @Test("정상 사슬: 1겹·여러 겹·줄이기가 일어나는 15겹 모두 다시 서명되고 그 결과가 인가된다")
    func genuineChains() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [trusted])
        for count in [0, 1, 5, 14, 15] {
            let chain = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: count,
                signer: { _ in nlKey }
            )
            let next = SignatureTesting.randomNodeKey()
            let resigned = try NodeKeySignature.resigned(chain.serialized(), for: next, with: nlKey)
            let details = try state.authorize(next, keySignature: resigned)
            // 15겹 위에 다시 서명하면 키가 16개라 줄인다: 최근 14개와 맨 안쪽 direct의 키.
            #expect(details?.previousNodeKeys.count == min(count + 1, 15), "\(count)겹")
            #expect(SignatureTesting.depth(try NodeKeySignature(decoding: resigned)) <= 16, "\(count)겹")
        }
    }
}
