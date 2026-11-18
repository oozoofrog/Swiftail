import CryptoKit
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// Resigning (contract behavior R7, unit test 13, §5 TL-11b item 1). Uses 10 `resign` cases from running Go `ResignNKS` as the reference.
///
/// Under TL-11b item 1, Swiftail resigns only chains already signed with its own NL key. Swiftail omits the three unverifiable signatures that Go
/// produced (`refusedRows`).
@Suite("Resigning")
struct ResigningTests {
    /// Rows Go produces and the recipient cannot verify, with the reasons Swiftail rejects them.
    static let refusedRows: [String: TKAError] = [
        "direct-wrapping-is-other-key": .untrustedSigner, "direct-no-wrapping": .untrustedSigner,
        "credential-chain": .invalidSignature,
    ]

    @Test("All 10 resign cases match result shape and outcome. Unshortened chains also match SigHash. The three unverifiable signatures are not produced")
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
                #expect(item.verdict?.authorized == false, "\(item.name): The Go result is also unauthorized")
                #expect(throws: refusal, "\(item.name)") { try made.get() }
                continue
            }
            let bytes = try made.get()
            #expect((bytes == old) == item.sameAsOld, "\(item.name)")
            let result = try NodeKeySignature(decoding: bytes)
            let goResult = try NodeKeySignature(decoding: ModelTesting.bytes(try #require(item.result)))
            #expect(SignatureTesting.depth(result) == item.depth, "\(item.name)")
            #expect(SignatureTesting.publicKeys(result) == SignatureTesting.publicKeys(goResult), "\(item.name)")
            // In a shortened chain, CryptoKit regenerates inner signatures, changing SigHash.
            if goResult.nested == (try? NodeKeySignature(decoding: old)) || item.sameAsOld {
                #expect(ModelTesting.hex(result.signatureHash) == item.sigHash, "\(item.name)")
            }
            // Swift verification of Swift and Go results matches Go's outcomes. Unverifiable signatures still fail verification.
            let state = try fixtures.state(named: item.authority)
            let verdict = try #require(item.verdict, "\(item.name)")
            #expect(SignatureTesting.verdict(state, nodeKey, bytes) == verdict, "\(item.name)")
            #expect(SignatureTesting.verdict(state, nodeKey, goResult.serialized()) == verdict, "\(item.name)")
        }
    }

    /// Test 13 resigning cases: the same key stays unchanged, direct with an NL rotation key passes, and the 16th key triggers shortening. Go produces
    /// a credential chain and a direct signature without `WrappingPubkey`, both unverifiable. Swiftail does not produce them (TL-11b item 1).
    @Test("The reference fixtures cover test 13 resigning")
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

    @Test("Chain shortened on the 16th key: the latest 14 above the innermost direct, then the new key. Repeated shortening stays within 16 levels")
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
            // Beyond 15 keys (16 including the outermost), retains the innermost direct's key and the latest 14.
            let expected = previous.count <= 15 ? previous : Array(previous.prefix(14)) + [nodeKeys[0]]
            #expect(details.previousNodeKeys == expected, "\(nodeKeys.count)")
        }
    }

    @Test("Same Pubkey returns the old bytes unchanged. An undecodable old signature returns an error")
    func verbatimAndUndecodable() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let nodeKey = SignatureTesting.randomNodeKey()
        // The old signature has an unknown field. Rewriting changes the bytes, so the test can tell whether they were returned unchanged.
        let direct = try SignatureTesting.direct(nodeKey, by: lockKey, wrapping: nil).serialized()
        let withUnknownField = [direct[0] + 1] + direct.dropFirst() + [0x07, 0x00]
        #expect(try NodeKeySignature.resigned(withUnknownField, for: nodeKey, with: lockKey) == withUnknownField)
        #expect(throws: TKAError.self) { try NodeKeySignature.resigned([0xa0, 0x00], for: nodeKey, with: lockKey) }
        #expect(throws: TKAError.self) { try NodeKeySignature.resigned([], for: nodeKey, with: lockKey) }
    }

    // MARK: Checks before resigning (TL-11b item 1)

    /// Direct signed by a trusted key (`trusted`) that specifies `nlKey` as the rotation key, with `count` rotation layers on top. `signer(layer number)` signs
    /// each layer (0 is innermost). The outermost layer's node key is `outermost`.
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
                // A layer added by the server without a signature (filled with zeros).
                signature = NodeKeySignature(
                    kind: NodeKeySignature.Kind.rotation, publicKey: key.binaryForm,
                    signature: [UInt8](repeating: 0, count: 64), nested: signature
                )
            }
        }
        return signature
    }

    @Test("Refuses to resign a chain topped by 15 layers of server-selected node keys. It does not act as a signing oracle")
    func forgedRotationLayers() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [trusted])
        let attackerKey = SignatureTesting.randomNodeKey()
        // The decoding limit is 15 layers (15 rotations over direct), and resigning at 15 layers triggers shortening.
        for count in [1, 14, 15] {
            // The innermost is this node's genuine direct signature whose rotation key is this node's NL key.
            let forged = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: count,
                outermost: attackerKey, signer: { _ in nil }
            )
            #expect(throws: TKAError.invalidSignature, "\(count) layers") {
                try NodeKeySignature.resigned(forged.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
            // The same applies to layers signed by another key (the attacker's key).
            let otherKey = Curve25519.Signing.PrivateKey()
            let signedByOther = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: count,
                outermost: attackerKey, signer: { _ in otherKey }
            )
            #expect(throws: TKAError.invalidSignature, "\(count) layers") {
                try NodeKeySignature.resigned(signedByOther.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
            #expect(throws: TKAError.unauthorized) { try state.authorize(attackerKey, keySignature: forged.serialized()) }
        }
    }

    @Test("Refuses to resign if even one layer fails verification with the NL key (innermost, middle, or outermost)", arguments: [0, 7, 14])
    func oneBadLayer(_ bad: Int) throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        // The chain has 15 layers, so resigning would shorten it.
        let chain = try Self.chain(
            direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey, layers: 15,
            signer: { $0 == bad ? other : nlKey }
        )
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(chain.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
    }

    @Test("Refuses to resign when the innermost signature's WrappingPubkey differs from this node's NL key or is missing")
    func innermostWrappingKey() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        for wrapping in [other.publicKey, nil] {
            // For direct with no rotation layers, only check the inner `WrappingPubkey`.
            let direct = try SignatureTesting.direct(SignatureTesting.randomNodeKey(), by: trusted, wrapping: wrapping)
            #expect(throws: TKAError.untrustedSigner) {
                try NodeKeySignature.resigned(direct.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
            // Even if all layers are signed with the NL key, reject when the innermost does not specify this node's NL key.
            let rotated = try Self.chain(
                direct: SignatureTesting.randomNodeKey(), by: trusted, wrapping: wrapping, layers: 3, signer: { _ in nlKey }
            )
            #expect(throws: TKAError.untrustedSigner) {
                try NodeKeySignature.resigned(rotated.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
            }
        }
    }

    @Test("Refuses to resign a chain starting with a credential (a node registered with a signed auth key)")
    func credentialRoot() throws {
        let trusted = Curve25519.Signing.PrivateKey(), nlKey = Curve25519.Signing.PrivateKey()
        let wrapped = Curve25519.Signing.PrivateKey()
        var credential = NodeKeySignature(
            kind: NodeKeySignature.Kind.credential, keyID: Array(trusted.publicKey.rawRepresentation),
            wrappingPublicKey: Array(wrapped.publicKey.rawRepresentation)
        )
        try credential.sign(with: trusted)
        // Created during registration: rotation signed by the wrapped key (Go `SignByCredential`).
        let registered = try SignatureTesting.rotation(SignatureTesting.randomNodeKey(), nesting: credential, by: wrapped)
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(registered.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
        // Even if the NL key signs the layer, the innermost credential's rotation key is the wrapped key.
        let relayed = try SignatureTesting.rotation(SignatureTesting.randomNodeKey(), nesting: credential, by: nlKey)
        #expect(throws: TKAError.untrustedSigner) {
            try NodeKeySignature.resigned(relayed.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
        // A single credential.
        #expect(throws: TKAError.untrustedSigner) {
            try NodeKeySignature.resigned(credential.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
    }

    @Test("Refuses to resign chains that never reach a non-rotation signature or contain a layer with an empty signature")
    func malformedChains() throws {
        let nlKey = Curve25519.Signing.PrivateKey()
        // Rotation with no `Nested`, signed by the NL key.
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
        // A layer with an empty signature field.
        let trusted = Curve25519.Signing.PrivateKey()
        let direct = try SignatureTesting.direct(SignatureTesting.randomNodeKey(), by: trusted, wrapping: nlKey.publicKey)
        let unsigned = NodeKeySignature(
            kind: NodeKeySignature.Kind.rotation, publicKey: SignatureTesting.randomNodeKey().binaryForm, nested: direct
        )
        #expect(throws: TKAError.invalidSignature) {
            try NodeKeySignature.resigned(unsigned.serialized(), for: SignatureTesting.randomNodeKey(), with: nlKey)
        }
    }

    @Test("Resigns valid chains with 1 layer, multiple layers, or 15 layers that trigger shortening, and authorizes every result")
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
            // Resigning over 15 layers gives 16 keys and triggers shortening to the latest 14 and the innermost direct's key.
            #expect(details?.previousNodeKeys.count == min(count + 1, 15), "\(count) layers")
            #expect(SignatureTesting.depth(try NodeKeySignature(decoding: resigned)) <= 16, "\(count) layers")
        }
    }
}
