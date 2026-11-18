// Shared tailnet lock test helpers for creating signed AUMs and node key signatures, building map response JSON, and reading Go reference fixtures.
// Each test generates its keys on the spot (fixed seed keys from the Go reference fixtures appear only in `Fixtures/tka-peer-sets.json`).

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

enum LockTesting {
    /// The disablement secret and its KDF value. These are Go reference values for behavior X3 of the `docs/contracts/SwiftailTailnetLock.md` contract
    /// (`0xa5` × 32 → Argon2i). This avoids running the 16MiB KDF each time a test creates a checkpoint.
    static let disablementSecret = [UInt8](repeating: 0xa5, count: 32)
    static let disablementValue = [UInt8](hex: "c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f") ?? []

    /// One signing device. Signs AUMs and node keys with a trusted key.
    struct Signer: Sendable {
        let key = Curve25519.Signing.PrivateKey()

        var keyID: [UInt8] { Array(key.publicKey.rawRepresentation) }
        var trusted: TrustedKey { TrustedKey(kind: 1, votes: 1, publicKey: keyID) }

        /// The `aum` with this key's signature attached.
        func signed(_ aum: AUM) throws -> AUM {
            var signed = aum
            signed.signatures.append(AUMSignature(keyID: keyID, signature: Array(try key.signature(for: aum.signatureHash))))
            return signed
        }

        /// Bytes of a direct signature (NKS) for `nodeKey`. `rotationKey` is that node's NL public key.
        func signature(for nodeKey: NodePublicKey, rotationKey: Curve25519.Signing.PublicKey? = nil) throws -> [UInt8] {
            var signature = NodeKeySignature(
                kind: NodeKeySignature.Kind.direct, publicKey: nodeKey.binaryForm, keyID: keyID,
                wrappingPublicKey: rotationKey.map { Array($0.rawRepresentation) } ?? []
            )
            try signature.sign(with: key)
            return signature.serialized()
        }
    }

    /// A checkpoint that trusts `signers`. Its only disablement value is `disablementValue`.
    static func checkpoint(trusting signers: [Signer], signedBy signer: Signer) throws -> AUM {
        let state = AuthorityState(disablementValues: [disablementValue], keys: signers.map(\.trusted), stateID1: 1, stateID2: 2)
        return try signer.signed(AUM(messageKind: AUM.Kind.checkpoint, prevAUMHash: nil, state: state))
    }

    static func addKey(_ added: Signer, after parent: AUMHash, signedBy signer: Signer) throws -> AUM {
        try signer.signed(AUM(messageKind: AUM.Kind.addKey, prevAUMHash: parent.bytes, key: added.trusted))
    }

    static func removeKey(_ removed: Signer, after parent: AUMHash, signedBy signer: Signer) throws -> AUM {
        try signer.signed(AUM(messageKind: AUM.Kind.removeKey, prevAUMHash: parent.bytes, keyID: removed.keyID))
    }

    /// A rotation signature for `nodeKey` wrapping `previous` (the old node key's signature). `rotationKey` is the private key for the old signature's `WrappingPubkey`.
    static func rotation(
        to nodeKey: NodePublicKey, nesting previous: [UInt8], by rotationKey: Curve25519.Signing.PrivateKey
    ) throws -> [UInt8] {
        var signature = NodeKeySignature(
            kind: NodeKeySignature.Kind.rotation, publicKey: nodeKey.binaryForm,
            nested: try NodeKeySignature(decoding: previous)
        )
        try signature.sign(with: rotationKey)
        return signature.serialized()
    }

    static func newNodeKey() -> NodePublicKey { NodePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey) }

    // MARK: Map response JSON

    static let capability = #""CapMap":{"https://tailscale.com/cap/tailnet-lock":null}"#

    /// Peer JSON. With `apiOnly`, creates an `UnsignedPeerAPIOnly` peer that is exempt from signature checks.
    static func peerJSON(_ id: Int64, key: NodePublicKey, signature: [UInt8] = [], apiOnly: Bool = false) -> String {
        let extra = apiOnly ? #","UnsignedPeerAPIOnly":true"# : ""
        return SwiftailControlTests.peerJSON(id, #","Key":"\#(key)"\#(signatureField(signature))\#(extra)"#)
    }

    /// Self-node JSON. Includes `tailnet-lock` in `CapMap` when `hasCapability` is set.
    static func selfJSON(key: NodePublicKey, signature: [UInt8] = [], hasCapability: Bool = true, _ extra: String = "") -> String {
        let fields = #"{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":100,"Addresses":["100.64.0.1/32"],"MachineAuthorized":true"#
        return fields + #","Key":"\#(key)"\#(signatureField(signature))\#(hasCapability ? "," + capability : "")\#(extra)}"#
    }

    /// Map response JSON. `lock` is a `"TKAInfo":…` fragment (`tkaInfo(head:)`, `tkaDisabled`). Omits it when nil.
    static func mapJSON(selfNode: String? = nil, peers: [String]? = nil, lock: String? = nil, _ extra: String = "") -> String {
        var fields: [String] = []
        if let selfNode { fields.append(#""Node":\#(selfNode)"#) }
        if let peers { fields.append(#""Peers":[\#(peers.joined(separator: ","))]"#) }
        if let lock { fields.append(lock) }
        if !extra.isEmpty { fields.append(extra) }
        return "{" + fields.joined(separator: ",") + "}"
    }

    static func tkaInfo(head: AUMHash) -> String { #""TKAInfo":{"Head":"\#(head.text)"}"# }
    static let tkaDisabled = #""TKAInfo":{"Disabled":true}"#

    private static func signatureField(_ signature: [UInt8]) -> String {
        signature.isEmpty ? "" : #","KeySignature":"\#(Data(signature).base64EncodedString())""#
    }
}

/// `Fixtures/tka-peer-sets.json` contains peer set decisions from Go `tka` and `ipnlocal`'s `rotationTracker`
/// (copied from `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`. See `Fixtures/README.md`).
struct GoPeerSetFile: Decodable {
    struct Authority: Decodable {
        let name: String
        /// The bootstrap checkpoint and subsequent AUMs (base-16).
        let aums: [String]
    }

    struct PeerSet: Decodable, CustomTestStringConvertible {
        struct Peer: Decodable {
            let nodeKey: String
            let signature: String?
            let unsignedPeerAPIOnly: Bool
        }

        let name: String
        let authority: String
        let peers: [Peer]
        /// Node keys of the peers Go retained (base-16).
        let kept: [String]

        var testDescription: String { name }
    }

    let authorities: [Authority]
    let peerSets: [PeerSet]

    static func load() throws -> GoPeerSetFile {
        let url = try #require(Bundle.module.url(forResource: "tka-peer-sets", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(GoPeerSetFile.self, from: Data(contentsOf: url))
    }

    /// Builds the named authority state from Go-generated AUMs.
    func authority(named name: String) throws -> SwiftailTKA.Authority {
        let aums = try #require(authorities.first { $0.name == name }, "\(name)").aums.map {
            try AUM(decoding: try #require([UInt8](hex: $0)))
        }
        var authority = try SwiftailTKA.Authority(bootstrappingWith: try #require(aums.first))
        if aums.count > 1 { try authority.inform(Array(aums.dropFirst())) }
        return authority
    }
}
