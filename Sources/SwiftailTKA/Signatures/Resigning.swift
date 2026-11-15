// node 키를 바꿀 때의 재서명. 노트 4.4 끝·4.6 4, 계약 동작 R7, 결정 L9.
// Go `tailscale.com` v1.104.7 `tka/sig.go:350-437`(`ResignNKS`·`maybeTrimRotationSignatureChain`)을 옮겼다.
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import CryptoKit
import SwiftailBase

extension NodeKeySignature {
    /// rotation 사슬이 담는 node 키의 상한. 15개짜리 사슬을 한 번 더 감싸면 CBOR 중첩 16단에 닿는다(Go `maxPrevKeys`).
    static let maximumPreviousKeyCount = 15

    /// 옛 서명을 새 node 키로 이어 서명한다(Go `ResignNKS`, 동작 R7).
    ///
    /// 옛 서명의 `Pubkey`가 새 키와 같으면 옛 바이트를 그대로 돌려준다. 아니면 옛 서명(키가 15개를 넘는 rotation이면 줄인 것)을
    /// `Nested`로 하는 rotation을 `lockKey`(NL 키)로 서명한다. Go와 같이 만든 서명을 스스로 검증하지 않는다(결정 L9): 옛 사슬의
    /// 회전 키가 `lockKey`의 공개 키가 아니면(credential 사슬, `WrappingPubkey` 없는 direct) 받는 쪽에서 검증되지 않는다.
    ///
    /// - Parameter previous: 서버가 방금 준 옛 서명의 바이트(동작 R6).
    /// - Throws: 옛 서명이 동작 D로 읽히지 않으면 그 디코딩 오류, CryptoKit이 서명하지 못하면 `signingFailed`.
    package static func resigned(
        _ previous: [UInt8], for nodeKey: NodePublicKey, with lockKey: Curve25519.Signing.PrivateKey
    ) throws(TKAError) -> [UInt8] {
        let old = try NodeKeySignature(decoding: previous)
        let publicKey = nodeKey.binaryForm
        if old.publicKey == publicKey { return previous }
        var signature = NodeKeySignature(
            kind: Kind.rotation, publicKey: publicKey, nested: try old.trimmingRotationChain(signingWith: lockKey)
        )
        try signature.sign(with: lockKey)
        return signature.serialized()
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
