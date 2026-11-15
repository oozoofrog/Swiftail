import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// 서명된 인증 키의 해석과 그것으로 만든 서명(계약 동작 R3·R5②·K·M, 결정 L12·L13, 단위 시험 13·14). 기준은 Go
/// `DecodeWrappedAuthkey`·`SignByCredential`을 실행한 `authKeys` 16개다.
@Suite("서명된 인증 키")
struct WrappedAuthKeyTests {
    /// Go가 원문 전체를 인증 키로 돌려주는 것(결정 L12), 서명에서 panic하는 것(L13), 서명을 거절하는 credential 아닌 A(R3),
    /// 검증되지 않는 서명을 만드는 어긋난 키(L13·R3)를 Swiftail은 모두 해석에서 거절한다.
    static let intendedRejections: [String: String] = [
        "missing-dash": "L12", "padded-base64": "L12", "url-alphabet-key": "L12", "extra-dash": "L12",
        "credential-not-cbor": "L12", "empty-parts": "L12",
        "credential-trailing-bits": "L12", "key-trailing-bits": "L12", "credential-lf": "L12", "key-crlf": "L12",
        "key-trailing-lf": "L12",
        "key-63-bytes": "L13", "key-65-bytes": "L13", "key-32-bytes": "L13", "key-public-half-mismatch": "L13",
        "credential-direct-kind": "R3", "credential-wrapping-other-key": "R3",
    ]

    @Test("authKeys 16개: Go가 받는 것은 같은 부분과 같은 판정, 나머지는 의도된 차이로 거절")
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
                // Go가 서명을 만든 경우, 그 서명은 Swift의 검증으로도 Go와 같은 판정이다.
                if let nks = item.nks, let verdict = item.verdict, let authority = item.authority, let nodeKey = item.nodeKey {
                    let state = try fixtures.state(named: authority)
                    let swiftVerdict = SignatureTesting.verdict(state, try SignatureTesting.nodeKey(nodeKey), ModelTesting.bytes(nks))
                    #expect(swiftVerdict == verdict, "\(item.name)")
                }
                continue
            }
            // Go가 감싼 키로 읽고 서명한 것.
            #expect(item.isWrapped && item.sign == "ok" && item.privateKeyLength == 64, "\(item.name)")
            let key = try #require(try parsed.get(), "\(item.name)")
            #expect(key.controlValue == item.authKey, "\(item.name)")
            #expect(ModelTesting.hex(key.credential.serialized()) == item.credential, "\(item.name)")
            let nodeKey = try SignatureTesting.nodeKey(try #require(item.nodeKey))
            let made = try key.keySignature(for: nodeKey)
            let decoded = try NodeKeySignature(decoding: made)
            let goSignature = try NodeKeySignature(decoding: ModelTesting.bytes(try #require(item.nks)))
            // CryptoKit 서명은 매번 다르므로 서명을 뺀 SigHash와 구조를 견주고, 서명은 검증한다.
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

    @Test("만든 서명은 authorize를 통과하고 내력은 credential에서 시작한다")
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

    @Test("잘린·틀린 --TL 접미사")
    func malformedSuffix() throws {
        let material = try Material()
        let credential = SignatureTesting.rawBase64(material.credential.serialized())
        let privateKey = SignatureTesting.rawBase64(material.privateKey)
        #expect(try WrappedAuthKey(parsing: Material.control) == nil)
        #expect(try WrappedAuthKey(parsing: Material.control + "--T" + credential) == nil)
        // 남는 비트가 0이 아닌 base64: 64바이트의 마지막 글자는 남는 4비트가 0이라 A·Q·g·w 가운데 하나다. 그 다음 글자로 바꾸면
        // 같은 바이트로 읽히는 비정규형이다. Go(`RawStdEncoding`)는 남는 비트를 보지 않는다(동작 R3).
        let lastCharacter = try #require(privateKey.last)
        let nextCharacter = try #require(["A": "B", "Q": "R", "g": "h", "w": "x"][lastCharacter])
        let nonCanonical = String(privateKey.dropLast()) + nextCharacter
        for suffix in [
            "", "-", credential, credential + "-", "-" + privateKey, String(credential.dropLast()) + "-" + privateKey,
            credential + "-" + String(privateKey.dropLast()), credential + "-" + nonCanonical,
            credential + "-" + privateKey + "=", credential + "-" + privateKey.prefix(40) + "\n" + privateKey.dropFirst(40),
            credential + "-" + privateKey + "-", credential + "-" + SignatureTesting.rawBase64(material.privateKey + [0]),
        ] {
            #expect(throws: TKAError.invalidAuthKey, "\(suffix.count)") {
                try WrappedAuthKey(parsing: Material.control + "--TL" + suffix)
            }
        }
        // 첫 `--TL`에서 자르므로 뒤의 `--TL`은 A의 일부가 되어 base64가 아니다.
        #expect(throws: TKAError.invalidAuthKey) { try WrappedAuthKey(parsing: Material.control + "--TL--TL" + credential + "-" + privateKey) }
        #expect(try WrappedAuthKey(parsing: material.authKey()) != nil)
    }

    @Test("인증 키 문자열은 16KiB까지, 그 안의 credential은 8KiB까지(동작 M)")
    func limits() throws {
        let material = try Material()
        let suffix = String(material.authKey().dropFirst(Material.control.count))
        func authKey(totalByteCount: Int) -> String {
            "tskey-" + String(repeating: "a", count: totalByteCount - 6 - suffix.utf8.count) + suffix
        }
        #expect(authKey(totalByteCount: 16_384).utf8.count == 16_384)
        #expect(try WrappedAuthKey(parsing: authKey(totalByteCount: 16_384)) != nil)
        #expect(throws: TKAError.invalidAuthKey) { try WrappedAuthKey(parsing: authKey(totalByteCount: 16_385)) }

        // credential에 모르는 필드 {7: bstr}를 더해 바이트를 맞춘다. 다시 쓴 credential(서명에 들어가는 것)에서는 빠진다.
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

    @Test("감싼 개인 키의 검사: 64바이트, 시드의 공개 키 = 뒤 32바이트 = WrappingPubkey(결정 L13)")
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
        // credential의 `WrappingPubkey`가 다른 키(감싼 키는 자기 자신과 맞음).
        let mismatched = try Material(wrappingPublicKey: other)
        #expect(throws: TKAError.invalidAuthKey) { try WrappedAuthKey(parsing: mismatched.authKey()) }
    }

    @Test("description·dump·String(reflecting:)에 인증 키와 감싼 키가 어떤 표기로도 없다(동작 K2)")
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

    @Test("어떤 문자열로도 트랩하지 않는다")
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

/// 시험 자리에서 만든 신뢰 키·credential·감싼 키.
private struct Material {
    static let control = "tskey-auth-ktest0001CNTRL-test0000"

    let state: AuthorityState
    let credential: NodeKeySignature
    /// 시드 32 ‖ 공개 32.
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
