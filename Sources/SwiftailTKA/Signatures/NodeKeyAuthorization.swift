// node 키가 지금의 신뢰 상태로 인가되는지의 판정. 노트 4.4, 계약 동작 S.
// Go `tailscale.com` v1.104.7의 판정을 옮겼다: `tka/tka.go:685-711`(`NodeKeyAuthorizedWithDetails`),
// `tka/sig.go:140-348`(`wrappingPublic`·`authorizingKeyID`·`verifySignature`·`rotationDetails`), `tka/state.go:56-69`(`GetKey`),
// `types/key/node.go:349-369`(`NodePublic`의 이진 형식).
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailBase
import SwiftailCrypto

/// 통과한 rotation 서명의 내력(Go `tka.RotationDetails`). 회전으로 낡은 키를 가리는 데 쓴다(동작 P4).
package struct RotationDetails: Sendable, Equatable {
    /// 안쪽 서명들 가운데 `Pubkey`가 비지 않은 것의 node 키. 새것부터이고 맨 안쪽 rotation 아닌 서명의 키를 포함한다.
    package var previousNodeKeys: [NodePublicKey]
    /// 맨 안쪽의 rotation이 아닌 서명(direct나 credential).
    package var initialSignature: NodeKeySignature
}

extension AuthorityState {
    /// 이 node 키가 이 신뢰 상태로 인가되는가(Go `NodeKeyAuthorizedWithDetails`, 동작 S).
    ///
    /// `Authority`의 머리 상태를 받는 순수 함수다. 판정 순서는 Go와 같다: 디코딩(동작 D, 8KiB 한도), 맨 바깥 credential 거절,
    /// 허가 KeyID 찾기, 그 KeyID가 신뢰 키인지, 서명 검증(재귀), 내력. 깊이는 CBOR 중첩 16단이 묶는다(direct 위에 rotation 15겹).
    ///
    /// - Returns: 바깥 서명이 rotation이면 내력, direct면 nil.
    /// - Throws: `unauthorized` — 어느 단계에서든 인가되지 않는다. 까닭은 담지 않는다(동작 K5).
    package func authorize(_ nodeKey: NodePublicKey, keySignature: [UInt8]) throws(TKAError) -> RotationDetails? {
        guard let signature = try? NodeKeySignature(decoding: keySignature),
            signature.kind != NodeKeySignature.Kind.credential,
            let keyID = signature.authorizingKeyID,
            let key = trustedKey(withID: keyID),
            signature.verifies(nodeKey: nodeKey.binaryForm, by: key)
        else { throw .unauthorized }
        guard signature.kind == NodeKeySignature.Kind.rotation else { return nil }
        // credential의 `Pubkey`는 검증되지 않으므로, 값이 있는데 np 형식이 아니면 여기서 실패한다(4.4 6).
        guard let details = signature.rotationDetails else { throw .unauthorized }
        return details
    }

    /// Go `State.GetKey`: 앞에서부터 찾는다. KeyID가 없는 키(`Key25519`가 아님)를 먼저 만나면 거기서 실패한다.
    private func trustedKey(withID keyID: [UInt8]) -> TrustedKey? {
        for key in keys {
            guard let candidate = key.keyID else { return nil }
            if candidate == keyID { return key }
        }
        return nil
    }
}

extension NodeKeySignature {
    /// 이 서명을 감싸는 rotation에 서명할 키(Go `wrappingPublic`). 자기 `WrappingPubkey`가 비었고 rotation이면 안쪽 것을 쓴다.
    var rotationKey: [UInt8]? {
        if !wrappingPublicKey.isEmpty { return wrappingPublicKey }
        guard kind == Kind.rotation else { return nil }
        return nested?.rotationKey
    }

    /// 이 서명을 허가하는 신뢰 키의 KeyID(Go `authorizingKeyID`): direct·credential은 자기 것, rotation은 `Nested`를 따라간다.
    fileprivate var authorizingKeyID: [UInt8]? {
        switch kind {
        case Kind.direct, Kind.credential: keyID.isEmpty ? nil : keyID
        case Kind.rotation: nested?.authorizingKeyID
        default: nil
        }
    }

    /// 서명이 `key`로 인증되고 `nodeKey`(np 형식)를 허가하는가(Go `verifySignature`).
    ///
    /// 검증 규칙이 갈린다(노트 3.7): rotation의 바깥 서명은 Go 표준 `ed25519.Verify`, direct·credential은 ZIP-215다.
    /// credential은 node 키 대신 `WrappingPubkey`를 허가하므로 `Pubkey`를 보지 않는다.
    fileprivate func verifies(nodeKey: [UInt8], by key: TrustedKey) -> Bool {
        if kind != Kind.credential, publicKey != nodeKey { return false }
        switch kind {
        case Kind.rotation:
            guard let nested, let rotationKey = nested.rotationKey, rotationKey.count == 32,
                Ed25519Verification.isValidStandard(signature: signature, message: signatureHash, publicKey: rotationKey)
            else { return false }
            // 안쪽이 credential이 아니면 안쪽 `Pubkey`가 np 형식이어야 한다. 그 값을 다른 무엇과 견주지는 않는다.
            if nested.kind != Kind.credential, NodePublicKey(binaryForm: nested.publicKey) == nil { return false }
            return nested.verifies(nodeKey: nested.publicKey, by: key)
        case Kind.direct, Kind.credential:
            guard nested == nil, key.kind == TrustedKey.ed25519Kind, let publicKey = key.publicKey, publicKey.count == 32
            else { return false }
            return Ed25519Verification.isValidZIP215(signature: signature, message: signatureHash, publicKey: publicKey)
        default:
            return false
        }
    }

    /// rotation의 내력(Go `rotationDetails`). 안쪽 `Pubkey`가 np 형식으로 읽히지 않으면 nil이다.
    ///
    /// 검증을 통과한 rotation 사슬은 rotation 아닌 서명으로 끝나므로 끝까지 rotation인 사슬(Go의 nil `InitialSig`)도 nil이다.
    fileprivate var rotationDetails: RotationDetails? {
        var previousNodeKeys: [NodePublicKey] = []
        var current = nested
        while let signature = current {
            if !signature.publicKey.isEmpty {
                guard let key = NodePublicKey(binaryForm: signature.publicKey) else { return nil }
                previousNodeKeys.append(key)
            }
            if signature.kind != Kind.rotation {
                return RotationDetails(previousNodeKeys: previousNodeKeys, initialSignature: signature)
            }
            current = signature.nested
        }
        return nil
    }
}

extension PrefixedKey where Kind == NodeKeyKind {
    /// NKS의 `Pubkey`에 쓰는 이진 형식(Go `NodePublic.MarshalBinary`): `"np"` ‖ 32바이트.
    var binaryForm: [UInt8] { Self.binaryPrefix + rawValue }

    /// 이진 형식을 읽는다(Go `NodePublic.UnmarshalBinary`). `np`로 시작하는 34바이트가 아니면 nil.
    init?(binaryForm bytes: [UInt8]) {
        guard bytes.count == Self.binaryPrefix.count + Self.byteCount, bytes.starts(with: Self.binaryPrefix) else { return nil }
        self.init(rawValue: bytes.dropFirst(Self.binaryPrefix.count))
    }

    private static var binaryPrefix: [UInt8] { Array("np".utf8) }
}
