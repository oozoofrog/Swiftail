import CryptoKit
import Foundation
import SwiftailBase
import Testing

@testable import SwiftailTKA

/// The arrays compared by the signature unit (TL-4) from `Fixtures/tka-fixtures.json` (outcomes from running Go `tka`, `tkafixtures` section of
/// `Tools/interop/README.md`). Fixture keys are public test-only values.
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

    /// `NodeKeyAuthorizedWithDetails` outcome and history.
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

    /// Trust state for the name. The outcome uses the key list (`authorize` takes only state).
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

    /// The Ed25519 private key for `swiftail-fixtures/tka/<role>/<number>`.
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

    /// Converts the `authorize` outcome to the fixture format.
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

    /// Nesting level count (one signature is 1).
    static func depth(_ signature: NodeKeySignature) -> Int { 1 + (signature.nested.map(depth) ?? 0) }

    /// `Pubkey` at every level, starting at the outside.
    static func publicKeys(_ signature: NodeKeySignature) -> [[UInt8]] {
        [signature.publicKey] + (signature.nested.map(publicKeys) ?? [])
    }

    // MARK: Creating signatures with keys generated on demand

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

    /// A state that trusts `lockKeys` in this order.
    static func state(trusting lockKeys: [Curve25519.Signing.PrivateKey]) -> AuthorityState {
        AuthorityState(
            keys: lockKeys.map { TrustedKey(kind: 1, votes: 1, publicKey: Array($0.publicKey.rawRepresentation)) },
            stateID1: 1, stateID2: 2
        )
    }

    /// Standard base64 without padding.
    static func rawBase64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
