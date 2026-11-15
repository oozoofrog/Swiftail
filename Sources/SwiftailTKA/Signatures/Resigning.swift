// node 키를 바꿀 때의 재서명. 노트 4.4 끝·4.6 4, 계약 동작 R7과 5절 "독립 검토에서 고치는 것: 제어의 절차 (TL-11b)" 항목 1.
// Go `tailscale.com` v1.104.7 `tka/sig.go:350-437`(`ResignNKS`·`maybeTrimRotationSignatureChain`)을 옮겼다.
// 재서명 전에 옛 서명을 검사하는 것(`requireSigned(byLockKey:)`)은 Go에 없다(TL-11b 항목 1).
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import CryptoKit
import SwiftailBase
import SwiftailCrypto

extension NodeKeySignature {
    /// rotation 사슬이 담는 node 키의 상한. 15개짜리 사슬을 한 번 더 감싸면 CBOR 중첩 16단에 닿는다(Go `maxPrevKeys`).
    static let maximumPreviousKeyCount = 15

    /// 옛 서명을 새 node 키로 이어 서명한다(Go `ResignNKS`, 동작 R7).
    ///
    /// 옛 서명의 `Pubkey`가 새 키와 같으면 옛 바이트를 그대로 돌려준다(서명을 만들지 않는다). 아니면 옛 서명이 **이 노드가 이미
    /// `lockKey`로 서명한 사슬**인지 먼저 본다(`requireSigned(byLockKey:)`). 옛 서명은 제어 서버의 응답이라, 검사 없이 줄이기가
    /// 서버가 고른 node 키에 NL 키로 서명해 주는 오라클이 되기 때문이다(TL-11b 항목 1. Go는 검사하지 않는다). 통과하면 옛 서명
    /// (키가 15개를 넘는 rotation이면 줄인 것)을 `Nested`로 하는 rotation을 `lockKey`로 서명한다.
    ///
    /// - Parameter previous: 서버가 방금 준 옛 서명의 바이트(동작 R6).
    /// - Throws: 옛 서명이 동작 D로 읽히지 않으면 그 디코딩 오류. rotation 겹의 서명이 `lockKey`로 검증되지 않으면
    ///   `invalidSignature`, 맨 안쪽의 rotation 아닌 서명이 없거나 그 `WrappingPubkey`가 `lockKey`가 아니면 `untrustedSigner`.
    ///   CryptoKit이 서명하지 못하면 `signingFailed`.
    package static func resigned(
        _ previous: [UInt8], for nodeKey: NodePublicKey, with lockKey: Curve25519.Signing.PrivateKey
    ) throws(TKAError) -> [UInt8] {
        let old = try NodeKeySignature(decoding: previous)
        let publicKey = nodeKey.binaryForm
        if old.publicKey == publicKey { return previous }
        try old.requireSigned(byLockKey: Array(lockKey.publicKey.rawRepresentation))
        var signature = NodeKeySignature(
            kind: Kind.rotation, publicKey: publicKey, nested: try old.trimmingRotationChain(signingWith: lockKey)
        )
        try signature.sign(with: lockKey)
        return signature.serialized()
    }

    /// 이 사슬을 이 노드가 이미 `lockKey`로 서명했는가(TL-11b 항목 1). 그렇다면 재서명과 줄이기가 새로 서명하는 node 키는
    /// 모두 `lockKey`가 이미 서명한 것이다.
    ///
    /// rotation 겹마다 서명이 `lockKey`로 검증되어야 한다(rotation의 바깥 서명 규칙인 표준 검증, 입력은 `signatureHash`.
    /// `authorize`와 같다). 맨 안쪽의 rotation 아닌 서명은 `WrappingPubkey`가 `lockKey`여야 한다: 서명 기기가 이 노드의 NL 키를
    /// 회전 키로 적어 준 direct가 그렇고, 서명된 인증 키의 credential(회전 키가 감싼 키다)이나 `WrappingPubkey` 없는 direct는
    /// 아니다. 맨 안쪽 서명 자체는 신뢰 키의 서명이라 여기서 검증하지 않는다(재서명은 그것을 바꾸지 않고 그대로 싣는다).
    /// 겹의 수는 디코딩의 한도(CBOR 중첩 16단, 8KiB)가 묶는다.
    private func requireSigned(byLockKey lockKey: [UInt8]) throws(TKAError) {
        var current = self
        while current.kind == Kind.rotation {
            guard Ed25519Verification.isValidStandard(
                signature: current.signature, message: current.signatureHash, publicKey: lockKey
            ) else { throw .invalidSignature }
            guard let nested = current.nested else { throw .untrustedSigner }
            current = nested
        }
        guard current.wrappingPublicKey == lockKey else { throw .untrustedSigner }
    }

    /// rotation 사슬이 node 키를 15개 넘게 담으면, 맨 안쪽 rotation 아닌 서명 위에 가장 최근 키 14개만 `lockKey`로 다시 서명해
    /// 감싼 사슬을 돌려준다(Go `maybeTrimRotationSignatureChain`). 그 사이의 키는 빠진다.
    ///
    /// 셈은 바깥 `Pubkey`(비어도 센다)와, 안쪽 서명들 가운데 `Pubkey`가 비지 않은 것이다.
    private func trimmingRotationChain(signingWith lockKey: Curve25519.Signing.PrivateKey) throws(TKAError) -> NodeKeySignature {
        guard kind == Kind.rotation else { return self }
        var previousKeys = [publicKey]
        var initial = nested
        while let signature = initial {
            if !signature.publicKey.isEmpty { previousKeys.append(signature.publicKey) }
            if signature.kind != Kind.rotation { break }
            initial = signature.nested
        }
        guard previousKeys.count > Self.maximumPreviousKeyCount else { return self }
        let kept = previousKeys.prefix(Self.maximumPreviousKeyCount - 1)
        var chain = initial
        for publicKey in kept.reversed() {
            var link = NodeKeySignature(kind: Kind.rotation, publicKey: publicKey, nested: chain)
            try link.sign(with: lockKey)
            chain = link
        }
        return chain ?? self
    }
}
