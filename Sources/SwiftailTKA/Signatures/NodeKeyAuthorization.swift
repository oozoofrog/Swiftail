// Determines whether the current trust state authorizes a node key. Notes §4.4, contract behavior S.
// Ports the decision logic from Go `tailscale.com` v1.104.7: `tka/tka.go:685-711` (`NodeKeyAuthorizedWithDetails`),
// `tka/sig.go:140-348`(`wrappingPublic`·`authorizingKeyID`·`verifySignature`·`rotationDetails`), `tka/state.go:56-69`(`GetKey`),
// `types/key/node.go:349-369` (the binary format of `NodePublic`).
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailBase
import SwiftailCrypto

/// The history of a verified rotation signature (Go `tka.RotationDetails`). Used to identify keys superseded by rotation (behavior P4).
package struct RotationDetails: Sendable, Equatable {
    /// The node keys of nested signatures with a nonempty `Pubkey`. Newest first, including the key of the innermost non-rotation signature.
    package var previousNodeKeys: [NodePublicKey]
    /// The innermost non-rotation signature (direct or credential).
    package var initialSignature: NodeKeySignature
}

extension AuthorityState {
    /// Checks whether this trust state authorizes the node key (Go `NodeKeyAuthorizedWithDetails`, behavior S).
    ///
    /// A pure function that takes `Authority`'s head state. The decision order matches Go: decoding (behavior D, 8KiB limit), rejection of an outermost credential,
    /// lookup of the authorizing KeyID, checking that it is trusted, recursive signature verification, and history. CBOR's 16-level nesting limit bounds depth (15 rotations over direct).
    ///
    /// - Returns: The history for an outer rotation signature, or nil for direct.
    /// - Throws: `unauthorized` if authorization fails at any stage. Omits the reason (behavior K5).
    package func authorize(_ nodeKey: NodePublicKey, keySignature: [UInt8]) throws(TKAError) -> RotationDetails? {
        guard let signature = try? NodeKeySignature(decoding: keySignature),
            signature.kind != NodeKeySignature.Kind.credential,
            let keyID = signature.authorizingKeyID,
            let key = trustedKey(withID: keyID),
            signature.verifies(nodeKey: nodeKey.binaryForm, by: key)
        else { throw .unauthorized }
        guard signature.kind == NodeKeySignature.Kind.rotation else { return nil }
        // A credential's `Pubkey` is unverified, so fail here if present and not in np format (§4.4 item 6).
        guard let details = signature.rotationDetails else { throw .unauthorized }
        return details
    }

    /// Go `State.GetKey` searches from the beginning and fails immediately if it first encounters a key without a KeyID (a kind other than `Key25519`).
    private func trustedKey(withID keyID: [UInt8]) -> TrustedKey? {
        for key in keys {
            guard let candidate = key.keyID else { return nil }
            if candidate == keyID { return key }
        }
        return nil
    }
}

extension NodeKeySignature {
    /// The signing key for a rotation that wraps this signature (Go `wrappingPublic`). A rotation with an empty `WrappingPubkey` uses the nested one.
    var rotationKey: [UInt8]? {
        if !wrappingPublicKey.isEmpty { return wrappingPublicKey }
        guard kind == Kind.rotation else { return nil }
        return nested?.rotationKey
    }

    /// The trusted KeyID authorizing this signature (Go `authorizingKeyID`). direct and credential use their own, and rotation follows `Nested`.
    fileprivate var authorizingKeyID: [UInt8]? {
        switch kind {
        case Kind.direct, Kind.credential: keyID.isEmpty ? nil : keyID
        case Kind.rotation: nested?.authorizingKeyID
        default: nil
        }
    }

    /// Checks whether `key` authenticates the signature and whether the signature authorizes `nodeKey` (np format, Go `verifySignature`).
    ///
    /// Verification rules differ (notes §3.7). The outer signature of rotation uses Go's standard `ed25519.Verify`, and direct and credential use ZIP-215.
    /// credential authorizes `WrappingPubkey` in place of the node key, so it does not check `Pubkey`.
    fileprivate func verifies(nodeKey: [UInt8], by key: TrustedKey) -> Bool {
        if kind != Kind.credential, publicKey != nodeKey { return false }
        switch kind {
        case Kind.rotation:
            guard let nested, let rotationKey = nested.rotationKey, rotationKey.count == 32,
                Ed25519Verification.isValidStandard(signature: signature, message: signatureHash, publicKey: rotationKey)
            else { return false }
            // If the nested signature is not a credential, its `Pubkey` must be in np format. It is not compared with any other value.
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

    /// The rotation history (Go `rotationDetails`). Returns nil if a nested `Pubkey` cannot be read in np format.
    ///
    /// A verified rotation chain ends in a non-rotation signature, so a chain of rotations all the way down (Go's nil `InitialSig`) also returns nil.
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
    /// The binary format used in the NKS `Pubkey` (Go `NodePublic.MarshalBinary`): `"np"` ‖ 32 bytes.
    var binaryForm: [UInt8] { Self.binaryPrefix + rawValue }

    /// Reads the binary format (Go `NodePublic.UnmarshalBinary`). Returns nil unless it is 34 bytes starting with `np`.
    init?(binaryForm bytes: [UInt8]) {
        guard bytes.count == Self.binaryPrefix.count + Self.byteCount, bytes.starts(with: Self.binaryPrefix) else { return nil }
        self.init(rawValue: bytes.dropFirst(Self.binaryPrefix.count))
    }

    private static var binaryPrefix: [UInt8] { Array("np".utf8) }
}
