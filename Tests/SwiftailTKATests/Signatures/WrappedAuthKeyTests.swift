import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// Decoding signed auth keys and the signatures they produce (contract behaviors R3, R5②, K, and M, decisions L12 and L13, unit tests 13 and 14).
/// Uses 16 `authKeys` cases from running Go `DecodeWrappedAuthkey` and `SignByCredential` as the reference.
@Suite("Signed auth keys")
struct WrappedAuthKeyTests {
    /// Swiftail rejects at decode time all cases where Go returns the full original string as an auth key (decision L12), panics during signing (L13), refuses to sign because A is not a credential (R3),
    /// or uses a mismatched key to produce an unverifiable signature (L13 and R3).
    static let intendedRejections: [String: String] = [
        "missing-dash": "L12", "padded-base64": "L12", "url-alphabet-key": "L12", "extra-dash": "L12",
        "credential-not-cbor": "L12", "empty-parts": "L12",
        "credential-trailing-bits": "L12", "key-trailing-bits": "L12", "credential-lf": "L12", "key-crlf": "L12",
        "key-trailing-lf": "L12",
        "key-63-bytes": "L13", "key-65-bytes": "L13", "key-32-bytes": "L13", "key-public-half-mismatch": "L13",
        "credential-direct-kind": "R3", "credential-wrapping-other-key": "R3",
    ]

    @Test("All 16 authKeys cases match parts and outcomes for Go's accepted cases and reject the rest as intended differences")
    func goAuthKeys() throws {
        let fixtures = try SignatureFixtureFile.load()
        #expect(fixtures.authKeys.count == 21)
        var compared = 0
        for item in fixtures.authKeys {
            let parsed = Result { () throws(TKAError) in try WrappedAuthKey(parsing: item.input) }
            if !item.input.contains("--TL") {
                #expect(!item.isWrapped && item.authKey == item.input, "\(item.name)")
                #expect(try parsed.get() == nil, "\(item.name)")
                compared += 1
                continue
            }
            if Self.intendedRejections[item.name] != nil {
                #expect(throws: TKAError.invalidAuthKey, "\(item.name)") { try parsed.get() }
                // When Go produces a signature, Swift verification of that signature matches Go's outcome.
                if let nks = item.nks, let verdict = item.verdict, let authority = item.authority, let nodeKey = item.nodeKey {
                    let state = try fixtures.state(named: authority)
                    let swiftVerdict = SignatureTesting.verdict(state, try SignatureTesting.nodeKey(nodeKey), ModelTesting.bytes(nks))
                    #expect(swiftVerdict == verdict, "\(item.name)")
                }
                continue
            }
            // Go decoded these as wrapped keys and signed with them.
            #expect(item.isWrapped && item.sign == "ok" && item.privateKeyLength == 64, "\(item.name)")
            let key = try #require(try parsed.get(), "\(item.name)")
            #expect(key.controlValue == item.authKey, "\(item.name)")
            #expect(ModelTesting.hex(key.credential.serialized()) == item.credential, "\(item.name)")
            let nodeKey = try SignatureTesting.nodeKey(try #require(item.nodeKey))
            let made = try key.keySignature(for: nodeKey)
            let decoded = try NodeKeySignature(decoding: made)
            let goSignature = try NodeKeySignature(decoding: ModelTesting.bytes(try #require(item.nks)))
            // CryptoKit signatures vary, so compare the structure and SigHash without the signature and verify the signature itself.
            #expect(decoded.signatureHash == goSignature.signatureHash, "\(item.name)")
            #expect(decoded.kind == NodeKeySignature.Kind.rotation && decoded.nested == key.credential, "\(item.name)")
            #expect(
                Ed25519Verification.isValidStandard(
                    signature: decoded.signature, message: decoded.signatureHash, publicKey: key.credential.wrappingPublicKey
                ),
                "\(item.name)"
            )
            if let authority = item.authority, let verdict = item.verdict {
                let state = try fixtures.state(named: authority)
                #expect(SignatureTesting.verdict(state, nodeKey, made) == verdict, "\(item.name)")
                #expect(SignatureTesting.verdict(state, nodeKey, ModelTesting.bytes(try #require(item.nks))) == verdict)
            }
            compared += 1
        }
        #expect(compared == 4)
    }

    @Test("The generated signature passes authorize and its history starts at the credential")
    func madeSignatureAuthorizes() throws {
        let material = try Material()
        let key = try #require(try WrappedAuthKey(parsing: material.authKey()))
        #expect(key.controlValue == Material.control)
        let nodeKey = SignatureTesting.randomNodeKey()
        let details = try #require(try material.state.authorize(nodeKey, keySignature: key.keySignature(for: nodeKey)))
        #expect(details.previousNodeKeys.isEmpty)
        #expect(details.initialSignature == material.credential)
        #expect(throws: TKAError.unauthorized) {
            try material.state.authorize(SignatureTesting.randomNodeKey(), keySignature: key.keySignature(for: nodeKey))
        }
    }

    @Test("Truncated and invalid --TL suffixes")
    func malformedSuffix() throws {
        let material = try Material()
        let credential = SignatureTesting.rawBase64(material.credential.serialized())
        let privateKey = SignatureTesting.rawBase64(material.privateKey)
        #expect(try WrappedAuthKey(parsing: Material.control) == nil)
        #expect(try WrappedAuthKey(parsing: Material.control + "--T" + credential) == nil)
        // Base64 with nonzero trailing bits: the last character for 64 bytes is A, Q, g, or w because the 4 trailing bits are zero. Replacing it with the next character
        // gives a noncanonical form that decodes to the same bytes. Go (`RawStdEncoding`) ignores the trailing bits (behavior R3).
        let lastCharacter = try #require(privateKey.last)
        let nextCharacter = try #require(["A": "B", "Q": "R", "g": "h", "w": "x"][lastCharacter])
        let nonCanonical = String(privateKey.dropLast()) + nextCharacter
        let brokenLine = String(privateKey.prefix(40)) + "\n" + String(privateKey.dropFirst(40))
        let suffixes: [String] = [
            "", "-", credential, credential + "-", "-" + privateKey, String(credential.dropLast()) + "-" + privateKey,
            credential + "-" + String(privateKey.dropLast()), credential + "-" + nonCanonical,
            credential + "-" + privateKey + "=", credential + "-" + brokenLine,
            credential + "-" + privateKey + "-", credential + "-" + SignatureTesting.rawBase64(material.privateKey + [0]),
        ]
        for suffix in suffixes {
            #expect(throws: TKAError.invalidAuthKey, "\(suffix.count)") {
                try WrappedAuthKey(parsing: Material.control + "--TL" + suffix)
            }
        }
        // Splitting at the first `--TL` makes the later `--TL` part of A, which is then invalid base64.
        #expect(throws: TKAError.invalidAuthKey) { try WrappedAuthKey(parsing: Material.control + "--TL--TL" + credential + "-" + privateKey) }
        #expect(try WrappedAuthKey(parsing: material.authKey()) != nil)
    }

    @Test("An auth key string can be up to 16KiB, and its credential up to 8KiB (behavior M)")
    func limits() throws {
        let material = try Material()
        let suffix = String(material.authKey().dropFirst(Material.control.count))
        func authKey(totalByteCount: Int) -> String {
            "tskey-" + String(repeating: "a", count: totalByteCount - 6 - suffix.utf8.count) + suffix
        }
        #expect(authKey(totalByteCount: 16_384).utf8.count == 16_384)
        #expect(try WrappedAuthKey(parsing: authKey(totalByteCount: 16_384)) != nil)
        #expect(throws: TKAError.invalidAuthKey) { try WrappedAuthKey(parsing: authKey(totalByteCount: 16_385)) }

        // Add unknown field {7: bstr} to the credential to reach the byte count. The rewritten credential used in the signature omits it.
        let original = material.credential.serialized()
        func credential(byteCount: Int) -> [UInt8] {
            let count = byteCount - original.count - 4
            return [original[0] + 1] + original.dropFirst() + [0x07, 0x59, UInt8(count >> 8), UInt8(count & 0xff)]
                + [UInt8](repeating: 0, count: count)
        }
        let accepted = try #require(try WrappedAuthKey(parsing: material.authKey(credential: credential(byteCount: 8_192))))
        #expect(accepted.credential == material.credential)
        #expect(throws: TKAError.invalidAuthKey) {
            try WrappedAuthKey(parsing: material.authKey(credential: credential(byteCount: 8_193)))
        }
    }

    @Test("Wrapped private key checks: 64 bytes, seed's public key = last 32 bytes = WrappingPubkey (decision L13)")
    func wrappedKeyChecks() throws {
        let material = try Material()
        let other = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        var direct = material.credential
        direct.kind = NodeKeySignature.Kind.direct
        var shortWrapping = material.credential
        shortWrapping.wrappingPublicKey.removeLast()
        for (credential, privateKey) in [
            (material.credential.serialized(), Array(material.privateKey.prefix(32)) + other),
            (material.credential.serialized(), Array(material.privateKey.prefix(63))),
            (material.credential.serialized(), material.privateKey + [0]),
            (direct.serialized(), material.privateKey),
            (shortWrapping.serialized(), material.privateKey),
        ] {
            #expect(throws: TKAError.invalidAuthKey) {
                try WrappedAuthKey(parsing: material.authKey(credential: credential, privateKey: privateKey))
            }
        }
        // The credential's `WrappingPubkey` differs, and the wrapped key is internally consistent.
        let mismatched = try Material(wrappingPublicKey: other)
        #expect(throws: TKAError.invalidAuthKey) { try WrappedAuthKey(parsing: mismatched.authKey()) }
    }

    @Test("description, dump, and String(reflecting:) omit the auth key and wrapped key in every representation (behavior K2)")
    func secretsHidden() throws {
        let material = try Material()
        let key = try #require(try WrappedAuthKey(parsing: material.authKey()))
        var dumped = ""
        dump(key, to: &dumped)
        let seed = Array(material.privateKey.prefix(32))
        let secrets = [
            ModelTesting.hex(material.privateKey), ModelTesting.hex(seed), ModelTesting.hex(seed).uppercased(),
            SignatureTesting.rawBase64(material.privateKey), SignatureTesting.rawBase64(seed),
            Data(seed).base64EncodedString(), Data(material.privateKey).base64EncodedString(),
            Material.control, "--TL",
        ]
        for text in [key.description, String(describing: key), String(reflecting: key), "\(key)", dumped] {
            for secret in secrets {
                #expect(!text.contains(secret), "\(text)")
            }
        }
    }

    @Test("No string causes a trap")
    func untrustedInput() throws {
        let material = try Material()
        let valid = material.authKey()
        var random = CBORTesting.Random(state: 0x2d54)
        let alphabet = Array("ABCZaz09+/-=_\n€--TL")
        for end in 0...valid.count {
            _ = try? WrappedAuthKey(parsing: String(valid.prefix(end)))
        }
        for _ in 0..<2_000 {
            let suffix = String((0..<Int.random(in: 0...200, using: &random)).map { _ in alphabet.randomElement(using: &random) ?? "A" })
            _ = try? WrappedAuthKey(parsing: Material.control + "--TL" + suffix)
        }
    }
}

/// Trusted key, credential, and wrapped key generated in the test.
private struct Material {
    static let control = "tskey-auth-ktest0001CNTRL-test0000"

    let state: AuthorityState
    let credential: NodeKeySignature
    /// 32-byte seed ‖ 32-byte public key.
    let privateKey: [UInt8]

    init(wrappingPublicKey: [UInt8]? = nil) throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let wrappingKey = Curve25519.Signing.PrivateKey()
        let publicKey = Array(wrappingKey.publicKey.rawRepresentation)
        var credential = NodeKeySignature(
            kind: NodeKeySignature.Kind.credential, keyID: Array(lockKey.publicKey.rawRepresentation),
            wrappingPublicKey: wrappingPublicKey ?? publicKey
        )
        try credential.sign(with: lockKey)
        self.state = SignatureTesting.state(trusting: [lockKey])
        self.credential = credential
        self.privateKey = Array(wrappingKey.rawRepresentation) + publicKey
    }

    func authKey(credential: [UInt8]? = nil, privateKey: [UInt8]? = nil) -> String {
        Self.control + "--TL" + SignatureTesting.rawBase64(credential ?? self.credential.serialized()) + "-"
            + SignatureTesting.rawBase64(privateKey ?? self.privateKey)
    }
}
