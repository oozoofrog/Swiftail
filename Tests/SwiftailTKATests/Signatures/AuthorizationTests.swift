import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailTKA

/// NKS 검증(계약 동작 S, 단위 시험 10, 노트 4.4). 기준은 Go `NodeKeyAuthorizedWithDetails`를 실행한 `signatures` 51개다.
@Suite("NKS 검증")
struct AuthorizationTests {
    @Test("signatures 51개: 판정과 내력(PrevNodeKeys 순서, 처음 서명의 종류·WrappingPubkey)이 Go와 같다")
    func goVerdicts() throws {
        let fixtures = try SignatureFixtureFile.load()
        #expect(fixtures.signatures.count == 51)
        for item in fixtures.signatures {
            let state = try fixtures.state(named: item.authority)
            let verdict = SignatureTesting.verdict(state, try SignatureTesting.nodeKey(item.nodeKey), ModelTesting.bytes(item.nks))
            #expect(verdict == item.verdict, "\(item.name)")
        }
    }

    /// 계약 7절 시험 10의 항목이 자료에 있고 Go의 판정이 계약과 같다(위 시험이 Swift의 판정을 견준다).
    @Test("시험 10의 항목이 기준 자료에 있다")
    func contractItemsPresent() throws {
        let verdicts = Dictionary(uniqueKeysWithValues: try SignatureFixtureFile.load().signatures.map { ($0.name, $0.authorized) })
        let expected: [String: Bool] = [
            "direct": true, "rotation-depth-1": true, "rotation-depth-15": true, "rotation-depth-16": false,
            "credential-alone": false, "credential-rotation": true, "rotation-middle-wrapping-used": true,
            "rotation-no-rotation-key": false, "direct-other-node-key": false, "direct-untrusted-key": false,
            "direct-key-after-removal": false, "direct-with-nested": false, "direct-31-byte-trusted-key": false,
            "rotation-inner-pubkey-not-np": false, "credential-with-garbage-pubkey": false,
            // R에 위수 2인 점을 더한 서명: ZIP-215로 보는 direct는 통과, 표준 규칙으로 보는 rotation 바깥은 거절(노트 8.1).
            "direct-zip215-only-signature": true, "rotation-outer-zip215-only-signature": false,
        ]
        for (name, authorized) in expected {
            #expect(verdicts[name] == authorized, "\(name)")
        }
    }

    @Test("direct 위에 rotation 15겹은 통과하고 내력은 새것부터, 16겹은 CBOR 중첩 한도로 거절")
    func depthLimit() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        let nodeKeys = (0...16).map { _ in SignatureTesting.randomNodeKey() }
        // 중간의 rotation은 `WrappingPubkey`를 생략한다: 회전 키는 맨 안쪽 direct의 것이다.
        var signature = try SignatureTesting.direct(nodeKeys[0], by: lockKey, wrapping: rotationKey.publicKey)
        for level in 1...15 {
            signature = try SignatureTesting.rotation(nodeKeys[level], nesting: signature, by: rotationKey)
        }
        let details = try #require(try state.authorize(nodeKeys[15], keySignature: signature.serialized()))
        #expect(details.previousNodeKeys == nodeKeys[0...14].reversed())
        #expect(details.initialSignature.kind == NodeKeySignature.Kind.direct)

        let deeper = try SignatureTesting.rotation(nodeKeys[16], nesting: signature, by: rotationKey)
        #expect(throws: TKAError.unauthorized) { try state.authorize(nodeKeys[16], keySignature: deeper.serialized()) }
    }

    @Test("rotation의 바깥 서명은 회전 키가 해야 한다: 신뢰 키나 다른 키의 서명은 거절")
    func rotationSigner() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        let (old, new) = (SignatureTesting.randomNodeKey(), SignatureTesting.randomNodeKey())
        let direct = try SignatureTesting.direct(old, by: lockKey, wrapping: rotationKey.publicKey)
        for (signer, authorized) in [(rotationKey, true), (lockKey, false), (Curve25519.Signing.PrivateKey(), false)] {
            let rotation = try SignatureTesting.rotation(new, nesting: direct, by: signer)
            #expect(((try? state.authorize(new, keySignature: rotation.serialized())) != nil) == authorized)
        }
    }

    /// Go는 안쪽(credential 아님)의 `Pubkey`를 `NodePublic.UnmarshalBinary`로 읽어 빈 값도 거절한다(`tka/sig.go:283-290`).
    /// 내력은 빈 `Pubkey`를 건너뛰므로 이 검사만이 잡는다. 자료에 없는 판정이다.
    @Test("rotation 안쪽 direct의 Pubkey가 비었으면 거절")
    func emptyInnerPublicKey() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        let (old, new) = (SignatureTesting.randomNodeKey(), SignatureTesting.randomNodeKey())
        var direct = try SignatureTesting.direct(old, by: lockKey, wrapping: rotationKey.publicKey)
        let signed = try SignatureTesting.rotation(new, nesting: direct, by: rotationKey)
        #expect(try state.authorize(new, keySignature: signed.serialized()) != nil)
        direct.publicKey = []
        try direct.sign(with: lockKey)
        let empty = try SignatureTesting.rotation(new, nesting: direct, by: rotationKey)
        #expect(throws: TKAError.unauthorized) { try state.authorize(new, keySignature: empty.serialized()) }
    }

    /// Go `State.GetKey`는 `Key.ID()`가 실패하는 키(`Key25519`가 아님)를 만나면 그 뒤를 보지 않는다(`tka/state.go:56-69`).
    /// 정적 검사를 거친 상태에는 그런 키가 없어 자료에 없는 판정이다.
    @Test("신뢰 키 찾기는 Key25519가 아닌 키에서 멈춘다")
    func keyLookupStopsAtUnknownKind() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let nodeKey = SignatureTesting.randomNodeKey()
        let signature = try SignatureTesting.direct(nodeKey, by: lockKey, wrapping: nil).serialized()
        let unknown = TrustedKey(kind: 2, votes: 1, publicKey: Array(repeating: 7, count: 32))
        let trusted = SignatureTesting.state(trusting: [lockKey]).keys[0]
        var state = AuthorityState(keys: [trusted, unknown])
        #expect(try state.authorize(nodeKey, keySignature: signature) == nil)
        state.keys = [unknown, trusted]
        #expect(throws: TKAError.unauthorized) { try state.authorize(nodeKey, keySignature: signature) }
    }

    @Test("NKS 하나는 8KiB까지(동작 M): 모르는 필드로 채운 8,192바이트는 통과, 8,193바이트는 거절")
    func byteLimit() throws {
        let fixtures = try SignatureFixtureFile.load()
        let direct = try #require(fixtures.signatures.first { $0.name == "direct" })
        let state = try fixtures.state(named: direct.authority)
        let nodeKey = try SignatureTesting.nodeKey(direct.nodeKey)
        let original = ModelTesting.bytes(direct.nks)
        #expect(original.first == 0xa5)
        // a5 → a6, 끝에 {7: bstr}를 더한다. 모르는 필드는 다시 쓴 바이트(SigHash)에 들지 않는다.
        func padded(to total: Int) -> [UInt8] {
            let count = total - original.count - 4
            return [0xa6] + original.dropFirst() + [0x07, 0x59, UInt8(count >> 8), UInt8(count & 0xff)]
                + [UInt8](repeating: 0, count: count)
        }
        #expect(padded(to: 8_192).count == 8_192)
        #expect(try state.authorize(nodeKey, keySignature: padded(to: 8_192)) == nil)
        #expect(throws: TKAError.unauthorized) { try state.authorize(nodeKey, keySignature: padded(to: 8_193)) }
    }

    @Test("어떤 바이트로도 트랩하지 않는다: 자료의 모든 접두와 임의 바이트")
    func untrustedInput() throws {
        let fixtures = try SignatureFixtureFile.load()
        let state = try fixtures.state(named: "nks-base")
        let nodeKey = SignatureTesting.randomNodeKey()
        for item in fixtures.signatures {
            let bytes = ModelTesting.bytes(item.nks)
            for end in 0..<bytes.count {
                #expect(throws: TKAError.unauthorized) { try state.authorize(nodeKey, keySignature: Array(bytes[..<end])) }
            }
        }
        var random = CBORTesting.Random(state: 0x7f4a)
        for _ in 0..<2_000 {
            let bytes = (0..<Int.random(in: 0...300, using: &random)).map { _ in UInt8.random(in: 0...255, using: &random) }
            _ = try? state.authorize(nodeKey, keySignature: bytes)
        }
    }

    @Test("text의 node 키 표기: nodekey: 텍스트와 NKS 안의 np 이진 형식")
    func nodeKeyText() throws {
        let cases = try SignatureFixtureFile.load().text.filter { $0.kind.hasPrefix("nodePublic.") }
        #expect(cases.count == 2)
        for item in cases {
            let key = try SignatureTesting.nodeKey(item.input)
            let output = item.kind == "nodePublic.binary" ? ModelTesting.hex(key.binaryForm) : key.description
            #expect(output == item.output, "\(item.name)")
            #expect(NodePublicKey(binaryForm: key.binaryForm) == key)
        }
        let binary = SignatureTesting.randomNodeKey().binaryForm
        #expect(NodePublicKey(binaryForm: Array(binary.dropLast())) == nil)
        #expect(NodePublicKey(binaryForm: binary + [0]) == nil)
        #expect(NodePublicKey(binaryForm: [0x6e, 0x71] + binary.dropFirst(2)) == nil)
    }
}
