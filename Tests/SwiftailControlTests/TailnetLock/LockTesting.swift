// tailnet lock 시험이 함께 쓰는 도구: 서명한 AUM과 노드 키 서명 만들기, 맵 응답 JSON, Go 기준 자료 읽기.
// 키는 시험마다 그 자리에서 만든다(Go 기준 자료의 고정 씨앗 키는 `Fixtures/tka-peer-sets.json`에만 있다).

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

enum LockTesting {
    /// 끄기 비밀과 그 KDF 값. 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 X3의 Go 기준값이다
    /// (`0xa5` × 32 → Argon2i). 시험이 체크포인트를 만들 때마다 16MiB KDF를 돌리지 않게 한다.
    static let disablementSecret = [UInt8](repeating: 0xa5, count: 32)
    static let disablementValue = [UInt8](hex: "c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f") ?? []

    /// 서명 기기 하나: 신뢰 키로 AUM과 node 키에 서명한다.
    struct Signer: Sendable {
        let key = Curve25519.Signing.PrivateKey()

        var keyID: [UInt8] { Array(key.publicKey.rawRepresentation) }
        var trusted: TrustedKey { TrustedKey(kind: 1, votes: 1, publicKey: keyID) }

        /// 이 키의 서명을 붙인 `aum`.
        func signed(_ aum: AUM) throws -> AUM {
            var signed = aum
            signed.signatures.append(AUMSignature(keyID: keyID, signature: Array(try key.signature(for: aum.signatureHash))))
            return signed
        }

        /// `nodeKey`에 대한 direct 서명(NKS)의 바이트. `rotationKey`는 그 노드의 NL 공개 키다.
        func signature(for nodeKey: NodePublicKey, rotationKey: Curve25519.Signing.PublicKey? = nil) throws -> [UInt8] {
            var signature = NodeKeySignature(
                kind: NodeKeySignature.Kind.direct, publicKey: nodeKey.binaryForm, keyID: keyID,
                wrappingPublicKey: rotationKey.map { Array($0.rawRepresentation) } ?? []
            )
            try signature.sign(with: key)
            return signature.serialized()
        }
    }

    /// `signers`를 믿는 체크포인트. 끄기 값은 `disablementValue` 하나다.
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

    /// `previous`(옛 node 키의 서명)를 감싸 `nodeKey`로 회전한 서명. `rotationKey`는 옛 서명의 `WrappingPubkey`의 개인 키다.
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

    // MARK: 맵 응답 JSON

    static let capability = #""CapMap":{"https://tailscale.com/cap/tailnet-lock":null}"#

    /// 피어 JSON. `apiOnly`면 서명 검사를 받지 않는 `UnsignedPeerAPIOnly` 피어다.
    static func peerJSON(_ id: Int64, key: NodePublicKey, signature: [UInt8] = [], apiOnly: Bool = false) -> String {
        let extra = apiOnly ? #","UnsignedPeerAPIOnly":true"# : ""
        return SwiftailControlTests.peerJSON(id, #","Key":"\#(key)"\#(signatureField(signature))\#(extra)"#)
    }

    /// self 노드 JSON. `hasCapability`면 `CapMap`에 `tailnet-lock`을 싣는다.
    static func selfJSON(key: NodePublicKey, signature: [UInt8] = [], hasCapability: Bool = true, _ extra: String = "") -> String {
        let fields = #"{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":100,"Addresses":["100.64.0.1/32"],"MachineAuthorized":true"#
        return fields + #","Key":"\#(key)"\#(signatureField(signature))\#(hasCapability ? "," + capability : "")\#(extra)}"#
    }

    /// 맵 응답 JSON. `lock`은 `"TKAInfo":…` 조각이다(`tkaInfo(head:)`, `tkaDisabled`). nil이면 싣지 않는다.
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

/// `Fixtures/tka-peer-sets.json`: Go `tka`와 `ipnlocal`의 `rotationTracker`가 낸 피어 집합의 판정
/// (`Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`에서 옮긴 것. `Fixtures/README.md`).
struct GoPeerSetFile: Decodable {
    struct Authority: Decodable {
        let name: String
        /// 부트스트랩 체크포인트와 그 뒤의 AUM들(16진).
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
        /// Go가 남긴 피어의 node 키(16진).
        let kept: [String]

        var testDescription: String { name }
    }

    let authorities: [Authority]
    let peerSets: [PeerSet]

    static func load() throws -> GoPeerSetFile {
        let url = try #require(Bundle.module.url(forResource: "tka-peer-sets", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(GoPeerSetFile.self, from: Data(contentsOf: url))
    }

    /// 이름의 서명 권한 상태를 Go가 만든 AUM들로 세운다.
    func authority(named name: String) throws -> SwiftailTKA.Authority {
        let aums = try #require(authorities.first { $0.name == name }, "\(name)").aums.map {
            try AUM(decoding: try #require([UInt8](hex: $0)))
        }
        var authority = try SwiftailTKA.Authority(bootstrappingWith: try #require(aums.first))
        if aums.count > 1 { try authority.inform(Array(aums.dropFirst())) }
        return authority
    }
}
