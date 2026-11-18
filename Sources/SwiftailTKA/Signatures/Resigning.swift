// Re-signing when changing the node key. End of notes §4.4 and §4.6 item 4, contract behavior R7 and §5 "Changes from the independent review: Control flow (TL-11b)" item 1.
// Ported from Go `tailscale.com` v1.104.7 `tka/sig.go:350-437` (`ResignNKS` and `maybeTrimRotationSignatureChain`).
// Go omits the old signature check before re-signing (`requireSigned(byLockKey:)`, TL-11b item 1).
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import CryptoKit
import SwiftailBase
import SwiftailCrypto

extension NodeKeySignature {
    /// The maximum node key count in the rotation chain. Wrapping a 15-key chain once more reaches the CBOR nesting limit of 16 (Go `maxPrevKeys`).
    static let maximumPreviousKeyCount = 15

    /// Re-signs the old signature for the new node key (Go `ResignNKS`, behavior R7).
    ///
    /// If the old signature's `Pubkey` matches the new key, returns the old bytes unchanged without signing. Otherwise first checks that the old signature
    /// **is a chain this node already signed with `lockKey`** (`requireSigned(byLockKey:)`). The old signature is a control server response, so unchecked trimming
    /// would create an oracle that signs server-chosen node keys with the NL key (TL-11b item 1, which Go does not check). If verified, signs a rotation with lockKey
    /// whose `Nested` is the old signature (trimmed if it is a rotation with more than 15 keys).
    ///
    /// - Parameter previous: The old signature bytes the server just supplied (behavior R6).
    /// - Throws: The decoding error if behavior D cannot read the old signature. Throws invalidSignature if a rotation layer does not verify with `lockKey`,
    ///   `untrustedSigner` if there is no innermost non-rotation signature or its `WrappingPubkey` is not `lockKey`, and
    ///   `signingFailed` if CryptoKit cannot sign.
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

    /// Checks whether this node already signed this chain with `lockKey` (TL-11b item 1). If so, re-signing and trimming sign only node keys
    /// that `lockKey` already signed.
    ///
    /// Each rotation layer's signature must verify with `lockKey` (standard verification for outer rotation signatures, with `signatureHash` as input,
    /// same as `authorize`). The innermost non-rotation signature must have `lockKey` as `WrappingPubkey`. A direct signature where the signing device set this node's NL key
    /// as the rotation key meets this condition. A signed auth key's credential (whose rotation key is the wrapped key) or a direct signature without `WrappingPubkey`
    /// does not. The innermost signature itself is from a trusted key and is not verified here (re-signing includes it unchanged).
    /// The decoder limits the number of layers (16 CBOR nesting levels, 8KiB).
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

    /// If a rotation chain includes more than 15 node keys, returns a chain wrapping the innermost non-rotation signature with only the 14 most recent keys
    /// re-signed by lockKey (Go `maybeTrimRotationSignatureChain`). Omits the intervening keys.
    ///
    /// Counts the outer `Pubkey` even if empty and the nested signatures whose Pubkey is nonempty.
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
