import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailTKA

/// NKS verification (contract behavior S, unit test 10, note §4.4). Uses 51 `signatures` cases from running Go `NodeKeyAuthorizedWithDetails` as the reference.
@Suite("NKS verification")
struct AuthorizationTests {
    @Test("All 51 signatures match Go's outcomes and history (PrevNodeKeys order and first signature's kind and WrappingPubkey)")
    func goVerdicts() throws {
        let fixtures = try SignatureFixtureFile.load()
        #expect(fixtures.signatures.count == 53)
        for item in fixtures.signatures {
            let state = try fixtures.state(named: item.authority)
            let verdict = SignatureTesting.verdict(state, try SignatureTesting.nodeKey(item.nodeKey), ModelTesting.bytes(item.nks))
            #expect(verdict == item.verdict, "\(item.name)")
        }
    }

    /// The fixtures cover contract §7 test 10 and Go's outcomes match the contract. The test above compares Swift's outcomes.
    @Test("The reference fixtures cover test 10")
    func contractItemsPresent() throws {
        let verdicts = Dictionary(uniqueKeysWithValues: try SignatureFixtureFile.load().signatures.map { ($0.name, $0.authorized) })
        let expected: [String: Bool] = [
            "direct": true, "rotation-depth-1": true, "rotation-depth-15": true, "rotation-depth-16": false,
            "credential-alone": false, "credential-rotation": true, "rotation-middle-wrapping-used": true,
            "rotation-no-rotation-key": false, "direct-other-node-key": false, "direct-untrusted-key": false,
            "direct-key-after-removal": false, "direct-with-nested": false, "direct-31-byte-trusted-key": false,
            "rotation-inner-pubkey-not-np": false, "credential-with-garbage-pubkey": false,
            // A signature with an order-2 point added to R: direct passes ZIP-215, and the outer rotation fails standard verification (note §8.1).
            "direct-zip215-only-signature": true, "rotation-outer-zip215-only-signature": false,
        ]
        for (name, authorized) in expected {
            #expect(verdicts[name] == authorized, "\(name)")
        }
    }

    @Test("15 rotations over direct pass, with newest-first history. 16 layers of rotation fail the CBOR nesting limit")
    func depthLimit() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        let nodeKeys = (0...16).map { _ in SignatureTesting.randomNodeKey() }
        // Intermediate rotations omit `WrappingPubkey`. The rotation key comes from the innermost direct signature.
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

    @Test("The rotation key must sign the outer rotation. A trusted key or another key is rejected")
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

    /// Go decodes an inner non-credential `Pubkey` with `NodePublic.UnmarshalBinary` and rejects an empty value as well (`tka/sig.go:283-290`).
    /// History skips empty `Pubkey`, so only this check catches it. The fixture omits this outcome.
    @Test("Rejects an empty Pubkey in direct inside rotation")
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

    /// Go `State.GetKey` stops at a key whose `Key.ID()` fails (a key other than `Key25519`, `tka/state.go:56-69`).
    /// Static validation leaves no such key in state, so this outcome is absent from the fixture.
    @Test("Trusted key lookup stops at a key other than Key25519")
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

    @Test("An NKS can be up to 8KiB (behavior M): 8,192 bytes padded with an unknown field pass, and 8,193 bytes fail")
    func byteLimit() throws {
        let fixtures = try SignatureFixtureFile.load()
        let direct = try #require(fixtures.signatures.first { $0.name == "direct" })
        let state = try fixtures.state(named: direct.authority)
        let nodeKey = try SignatureTesting.nodeKey(direct.nodeKey)
        let original = ModelTesting.bytes(direct.nks)
        #expect(original.first == 0xa5)
        // a5 → a6, then add {7: bstr} at the end. Rewritten bytes (SigHash) omit unknown fields.
        func padded(to total: Int) -> [UInt8] {
            let count = total - original.count - 4
            return [0xa6] + original.dropFirst() + [0x07, 0x59, UInt8(count >> 8), UInt8(count & 0xff)]
                + [UInt8](repeating: 0, count: count)
        }
        #expect(padded(to: 8_192).count == 8_192)
        #expect(try state.authorize(nodeKey, keySignature: padded(to: 8_192)) == nil)
        #expect(throws: TKAError.unauthorized) { try state.authorize(nodeKey, keySignature: padded(to: 8_193)) }
    }

    @Test("No bytes cause a trap, including every fixture prefix and arbitrary bytes")
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

    @Test("Node key representations in text: nodekey: text and np binary inside NKS")
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
