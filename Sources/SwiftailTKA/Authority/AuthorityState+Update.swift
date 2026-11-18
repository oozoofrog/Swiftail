// Verification and state application for one AUM. Notes §4.1 and §4.2, contract behaviors A2–A7 and F1.
//
// The check order, per-kind application rules, and signature weighting were ported from Go.
// Origin: tailscale.com v1.104.7 `tka/tka.go` (`aumVerify`, `checkParent`), `tka/verify.go` (`signatureVerify`),
// `tka/state.go`(`GetKey`, `parentMatches`, `applyVerifiedAUM`), `tka/aum.go`(`Weight`).
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

import SwiftailCrypto

extension AuthorityState {
    /// The new state after applying a verified AUM (Go `applyVerifiedAUM`, behavior A6). The resulting `lastAUMHash` is that AUM's hash.
    ///
    /// Does not check signatures or static rules. `Authority` decides admission.
    package func applying(_ update: AUM) throws(TKAError) -> AuthorityState {
        try applying(update, hash: update.hash)
    }

    /// Like `applying(_:)`, but takes the precomputed hash and avoids reencoding.
    func applying(_ update: AUM, hash: AUMHash) throws(TKAError) -> AuthorityState {
        // If the state has a `lastAUMHash`, `PrevAUMHash` must match byte for byte (Go `parentMatches`).
        if let lastAUMHash, lastAUMHash.bytes != update.prevAUMHash ?? [] { throw .rejectedUpdate }
        var next = self
        next.lastAUMHash = hash

        switch update.messageKind {
        case AUM.Kind.checkpoint:
            guard var checkpoint = update.state, checkpoint.stateID1 == stateID1, checkpoint.stateID2 == stateID2
            else { throw .rejectedUpdate }
            checkpoint.lastAUMHash = hash
            return checkpoint
        case AUM.Kind.addKey:
            // The 512-entry limit does not apply here (notes §4.2).
            guard let key = update.key, let keyID = key.keyID, self.key(withID: keyID) == nil else { throw .rejectedUpdate }
            next.keys.append(key)
        case AUM.Kind.updateKey:
            let keyID = update.keyID ?? []
            guard var key = self.key(withID: keyID) else { throw .rejectedUpdate }
            if let votes = update.votes { key.votes = votes }
            if let meta = update.meta { key.meta = meta }
            do { try key.validate() } catch { throw .rejectedUpdate }
            for index in next.keys.indices where next.keys[index].keyID == keyID {
                next.keys[index] = key
            }
        case AUM.Kind.removeKey:
            guard let index = keys.firstIndex(where: { $0.keyID == update.keyID ?? [] }) else { throw .rejectedUpdate }
            next.keys.remove(at: index)
        default:
            // NoOp, kind 0 (`AUMInvalid`), or an unknown kind leaves state unchanged (Go's contract lets older clients ignore these, decision L10).
            break
        }
        return next
    }

    /// Checks whether an AUM can be admitted using this state as its parent state (Go `aumVerify`, behaviors A1–A5).
    ///
    /// Bootstrap (`isBootstrap`) skips the parent check and verifies the checkpoint's signatures against its own state (behavior F5).
    /// There is no vote threshold. One trusted key signature is sufficient (behavior A4).
    func verify(_ update: AUM, isBootstrap: Bool) throws(TKAError) {
        try update.validate()
        try verifyParentAndSignatures(of: update, isBootstrap: isBootstrap)
    }

    /// The checks from `verify(_:isBootstrap:)` other than static checks (behavior A1): parent, signatures, and removal of the last key (behaviors A2–A5).
    ///
    /// Reopening the store runs only these checks (TL-11a item 2). Even an AUM that fails static checks cannot trap here. Verification rejects bad signature lengths,
    /// application (`applying`) rejects missing fields, and weights wrap on overflow as in Go.
    ///
    /// - Returns: The number of signature verifications. Count repeated (KeyID, signature) pairs only once. Tests use this number to measure verification cost.
    @discardableResult
    func verifyParentAndSignatures(of update: AUM, isBootstrap: Bool) throws(TKAError) -> Int {
        if !isBootstrap {
            guard let parent = update.prevAUMHash, !parent.isEmpty else { throw .missingParent }
            guard let lastAUMHash, lastAUMHash.bytes == parent else { throw .rejectedUpdate }
        }

        guard !update.signatures.isEmpty else { throw .unsigned }
        let signatureHash = update.signatureHash
        // Remember already verified (KeyID, signature) pairs. Identical pairs give the same result, so verify them once. Go verifies every occurrence,
        // allowing one AUM repeating a trusted signature thousands of times to tie up a receiver for tens of seconds.
        var verified: Set<AUMSignature> = []
        for signature in update.signatures where verified.insert(signature).inserted {
            // Use the public key from the state because the sender chooses KeyID (see the comment in Go `signatureVerify`).
            guard let key = key(withID: signature.keyID) else { throw .untrustedSigner }
            guard key.kind == TrustedKey.ed25519Kind, let publicKey = key.publicKey, publicKey.count == 32,
                Ed25519Verification.isValidZIP215(
                    signature: signature.signature, message: signatureHash, publicKey: publicKey
                )
            else { throw .invalidSignature }
        }

        if update.messageKind == AUM.Kind.removeKey, keys.count == 1, keys[0].keyID == update.keyID ?? [] {
            throw .rejectedUpdate
        }
        return verified.count
    }

    /// Signature weight for fork resolution (Go `AUM.Weight`). Sums `Votes` for trusted signing keys, counting each key once and unknown keys as 0.
    func weight(of update: AUM) -> UInt64 {
        var counted: Set<[UInt8]> = []
        var weight: UInt64 = 0
        for signature in update.signatures {
            guard let key = key(withID: signature.keyID), counted.insert(signature.keyID).inserted else { continue }
            // Keys in admitted state have `Votes` of at most 4,096 (static checks), so the weight sum does not overflow. State reopened from the store has not undergone static checks,
            // so add with wrapping like Go `uint` (no trap).
            weight &+= key.votes
        }
        return weight
    }

    /// The trusted key with the same KeyID (Go `GetKey`). Null and empty public keys have the same KeyID (behavior E6).
    ///
    /// Search from the beginning as Go does, and fail immediately if a key without a KeyID (a kind other than `Key25519`) is encountered before a match. Such keys are absent from admitted state
    /// because of static checks. This case is reachable only on reopening, which skips static checks (TL-11a item 2).
    func key(withID keyID: [UInt8]) -> TrustedKey? {
        keys.first { $0.keyID == nil || $0.keyID == keyID }.flatMap { $0.keyID == nil ? nil : $0 }
    }
}
