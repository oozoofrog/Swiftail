import CryptoKit
import Foundation
import SwiftailBase
import Testing

@testable import SwiftailTKA

/// `Fixtures/tka-fixtures.json`(Go `tka`를 실행한 판정, `Tools/interop/README.md`의 `tkafixtures` 절) 가운데 서명 단위(TL-4)가
/// 견주는 배열. 자료의 키는 공개된 시험 전용 값이다.
struct SignatureFixtureFile: Decodable {
    struct Key: Decodable {
        let seed: String
        let `private`: String
        let `public`: String
    }

    struct Authority: Decodable {
        struct State: Decodable {
            let keys: [ModelFixtureFile.KeyValue]
            let disablementValues: [String]?
            let stateID1: String
            let stateID2: String
        }

        let name: String
        let state: State
    }

    /// `NodeKeyAuthorizedWithDetails`의 판정과 내력.
    struct Verdict: Decodable, Equatable {
        struct Rotation: Decodable, Equatable {
            let prevNodeKeys: [String]
            let initialKind: UInt8
            let initialWrappingPubkey: String
        }

        let authorized: Bool
        let rotation: Rotation?
    }

    struct Signature: Decodable {
        let name: String
        let authority: String
        let nodeKey: String
        let nks: String
        let authorized: Bool
        let rotation: Verdict.Rotation?

        var verdict: Verdict { Verdict(authorized: authorized, rotation: rotation) }
    }

    struct PeerSet: Decodable {
        struct Peer: Decodable {
            let nodeKey: String
            let signature: String?
            let unsignedPeerAPIOnly: Bool
        }

        let name: String
        let authority: String
        let peers: [Peer]
        let kept: [String]
    }

    struct AuthKey: Decodable {
        let name: String
        let input: String
        let authKey: String
        let isWrapped: Bool
        let returnedInput: Bool
        let credential: String?
        let privateKeyLength: Int
        let nodeKey: String?
        let sign: String?
        let nks: String?
        let authority: String?
        let verdict: Verdict?
    }

    struct Resign: Decodable {
        let name: String
        let authority: String
        let nlKey: String
        let oldNKS: String
        let nodeKey: String
        let ok: Bool
        let result: String?
        let sigHash: String?
        let sameAsOld: Bool
        let depth: Int
        let verdict: Verdict?
    }

    struct Text: Decodable {
        let name: String
        let kind: String
        let input: String
        let ok: Bool
        let output: String?
    }

    let keys: [Key]
    let authorities: [Authority]
    let text: [Text]
    let signatures: [Signature]
    let peerSets: [PeerSet]
    let authKeys: [AuthKey]
    let resign: [Resign]

    static func load() throws -> SignatureFixtureFile {
        let url = try #require(Bundle.module.url(forResource: "tka-fixtures", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(SignatureFixtureFile.self, from: Data(contentsOf: url))
    }

    /// 이름의 신뢰 상태. 판정에 쓰는 것은 키 목록이다(`authorize`는 상태만 받는다).
    func state(named name: String) throws -> AuthorityState {
        let state = try #require(authorities.first { $0.name == name }, "\(name)").state
        return AuthorityState(
            lastAUMHash: nil,
            disablementValues: (state.disablementValues ?? []).map(ModelTesting.bytes),
            keys: state.keys.map(\.trustedKey),
            stateID1: try #require(UInt64(state.stateID1)),
            stateID2: try #require(UInt64(state.stateID2))
        )
    }

    /// `swiftail-fixtures/tka/<역할>/<번호>`의 Ed25519 개인 키.
    func signingKey(seed: String) throws -> Curve25519.Signing.PrivateKey {
        let key = try #require(keys.first { $0.seed == seed }, "\(seed)")
        return try Curve25519.Signing.PrivateKey(rawRepresentation: ModelTesting.bytes(key.private))
    }
}

enum SignatureTesting {
    static func nodeKey(_ hex: String) throws -> NodePublicKey {
        try #require(NodePublicKey(rawValue: ModelTesting.bytes(hex)), "\(hex)")
    }

    static func randomNodeKey() -> NodePublicKey {
        NodePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
    }

    /// `authorize`의 판정을 자료의 모양으로 바꾼다.
    static func verdict(_ state: AuthorityState, _ nodeKey: NodePublicKey, _ signature: [UInt8]) -> SignatureFixtureFile.Verdict {
        switch Result(catching: { () throws(TKAError) in try state.authorize(nodeKey, keySignature: signature) }) {
        case .failure:
            return SignatureFixtureFile.Verdict(authorized: false, rotation: nil)
        case .success(nil):
            return SignatureFixtureFile.Verdict(authorized: true, rotation: nil)
        case .success(let details?):
            return SignatureFixtureFile.Verdict(
                authorized: true,
                rotation: SignatureFixtureFile.Verdict.Rotation(
                    prevNodeKeys: details.previousNodeKeys.map { ModelTesting.hex($0.rawValue) },
                    initialKind: details.initialSignature.kind,
                    initialWrappingPubkey: ModelTesting.hex(details.initialSignature.wrappingPublicKey)
                )
            )
        }
    }

    /// 중첩의 단수(서명 하나는 1).
    static func depth(_ signature: NodeKeySignature) -> Int { 1 + (signature.nested.map(depth) ?? 0) }

    /// 바깥부터 모든 단의 `Pubkey`.
    static func publicKeys(_ signature: NodeKeySignature) -> [[UInt8]] {
        [signature.publicKey] + (signature.nested.map(publicKeys) ?? [])
    }

    // MARK: 서명 만들기(시험 자리에서 만든 키)

    static func direct(
        _ nodeKey: NodePublicKey, by lockKey: Curve25519.Signing.PrivateKey, wrapping: Curve25519.Signing.PublicKey?
    ) throws -> NodeKeySignature {
        var signature = NodeKeySignature(
            kind: NodeKeySignature.Kind.direct, publicKey: nodeKey.binaryForm,
            keyID: Array(lockKey.publicKey.rawRepresentation),
            wrappingPublicKey: wrapping.map { Array($0.rawRepresentation) } ?? []
        )
        try signature.sign(with: lockKey)
        return signature
    }

    static func rotation(
        _ nodeKey: NodePublicKey, nesting nested: NodeKeySignature, by rotationKey: Curve25519.Signing.PrivateKey
    ) throws -> NodeKeySignature {
        var signature = NodeKeySignature(kind: NodeKeySignature.Kind.rotation, publicKey: nodeKey.binaryForm, nested: nested)
        try signature.sign(with: rotationKey)
        return signature
    }

    /// `lockKeys`를 이 순서로 믿는 상태.
    static func state(trusting lockKeys: [Curve25519.Signing.PrivateKey]) -> AuthorityState {
        AuthorityState(
            keys: lockKeys.map { TrustedKey(kind: 1, votes: 1, publicKey: Array($0.publicKey.rawRepresentation)) },
            stateID1: 1, stateID2: 2
        )
    }

    /// 패딩 없는 표준 base64.
    static func rawBase64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
