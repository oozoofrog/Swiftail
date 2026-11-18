// Ed25519 signature verification with the same acceptance criteria as two Go implementations.
//
// Origin: the verification procedure follows `Verify` in `github.com/hdevalence/ed25519consensus` v0.2.0 `ed25519.go` and
// `verifyWithDom` in Go 1.27.3 `crypto/internal/fips140/ed25519/ed25519.go`.
// Copyright 2016 The Go Authors, Copyright 2016 Henry de Valence (`ed25519consensus`). Copyright 2024 The Go Authors (Go standard library). BSD-3-Clause (full text at
// the top of `Edwards25519/FieldElement.swift`. The ed25519consensus LICENSE differs only in the name in clause 3 (Google Inc.) and the copyright lines).

import CryptoKit

/// Verifies Ed25519 signatures. It does not sign or handle secret values.
///
/// Tailnet Lock uses different verification rules depending on the signature. AUM signatures and direct and credential `NodeKeySignature` values use
/// ZIP-215. The outer signature of a rotation `NodeKeySignature` follows the standard Go rules
/// (`docs/protocol-notes/tailnet-lock.md` §3.7 and §6.1). Both rules use pure Ed25519 (no context).
///
/// Both rules apply the following checks and computation.
/// - Requires a 64-byte signature (R ‖ S) and 32-byte public key A. Otherwise returns false.
/// - Requires the high three bits of `sig[63]` to be 0.
/// - Both rules decode A with support for noncanonical encodings (y ≥ p or a sign bit set for x = 0) and reject points off the curve. ZIP-215 uses the same decoder for R.
/// - Requires canonical S (S < L).
/// - k = SHA-512(R ‖ A ‖ M) mod L. Hashes the exact bytes of R and A as received.
///
/// Both rules accept honestly generated signatures. Their decisions only differ for deliberately constructed signatures
/// containing small-order components or noncanonical encodings.
public enum Ed25519Verification {
    /// Verifies a signature under ZIP-215 with the same acceptance criteria as `Verify` in the Go package `github.com/hdevalence/ed25519consensus`.
    ///
    /// Checks the cofactor-multiplied equation [8]([S]B − [k]A − R) = 0. Multiplication by the cofactor eliminates small-order components in the point arithmetic.
    /// The original bytes of A and R still enter the computation of k.
    public static func isValidZIP215(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard let input = Input(signature: signature, message: message, publicKey: publicKey),
              let r = EdwardsPoint(encoding: Array(signature[0..<32]))
        else { return false }
        return (input.computedR - r).multipliedByCofactor().isIdentity
    }

    /// Verifies with the same acceptance criteria as `Verify` in the Go standard library's `crypto/ed25519`.
    ///
    /// The canonical encoding of [S]B − [k]A, computed without the cofactor, must equal the signature's R bytes. This rejects a noncanonical R encoding
    /// or a point that differs from the computed point by even a small-order component. Go panics for a public key of the wrong length.
    /// This implementation returns false for that case.
    public static func isValidStandard(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard let input = Input(signature: signature, message: message, publicKey: publicKey) else { return false }
        return input.computedR.encoding == Array(signature[0..<32])
    }

    /// The checks and computation shared by both rules. Instances are created only for input that passes the checks.
    private struct Input {
        /// [S]B − [k]A. For a valid signature this equals R under the standard rule. Under ZIP-215, their difference is killed by the cofactor.
        let computedR: EdwardsPoint

        init?(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) {
            guard signature.count == 64, publicKey.count == 32, signature[63] & 0b1110_0000 == 0,
                  let a = EdwardsPoint(encoding: publicKey),
                  let s = Scalar(canonicalBytes: Array(signature[32..<64]))
            else { return nil }
            var hash = SHA512()
            hash.update(data: signature[0..<32])
            hash.update(data: publicKey)
            hash.update(data: message)
            let k = Scalar(reducing: Array(hash.finalize()))
            computedR = EdwardsPoint.varTimeDoubleScalarBaseMultiply(k, -a, s)
        }
    }
}
