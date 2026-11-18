// Parses a signed auth key (`<auth key>--TL<A>-<B>`) and signs a new node key with it. Notes §3.8 and §4.6 item 2, contract behaviors R3, R5②, and K, decisions L12 and L13.
// Split positions and the signature form follow Go `tailscale.com` v1.104.7 `tka/sig.go:439-498` (`SignByCredential` and `DecodeWrappedAuthkey`).
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import CryptoKit
import SwiftailBase

/// A parsed auth key containing `--TL`. This is a secret that contains the wrapped private key.
///
/// The auth key and wrapped private key stay out of `description`, `dump`, and `String(reflecting:)` (behavior K2). Only `controlValue` goes to the server.
package struct WrappedAuthKey: Sendable {
    /// The portion to send to the server, before the first `--TL`. It is still an auth key and therefore secret.
    package let controlValue: String
    /// The credential NKS (A) that delegated signing authority. The recipient's `authorize` checks whether the key is trusted.
    let credential: NodeKeySignature
    /// The delegated Ed25519 key, the first 32 bytes of B as a seed.
    private let wrappingKey: Curve25519.Signing.PrivateKey

    /// The limit on the full auth key string and the wrapped private key length (behaviors M and R3).
    static let maximumByteCount = 16 * 1_024
    static let wrappedPrivateKeyByteCount = 64

    /// Parses an auth key (behavior R3). Splits at the first `--TL`, then splits the suffix at the first `-` to get A (credential) and B (64-byte private key).
    ///
    /// If decoding fails, Go returns the full original string (including the private key) as the auth key. It panics at signing if B is not 64 bytes and does not check
    /// B's last 32 bytes (notes §3.8). Swiftail rejects all these cases before sending anything to the server (decisions L12 and L13).
    ///
    /// - Returns: nil without `--TL` (an ordinary auth key).
    /// `-` Throws: `invalidAuthKey` if the string exceeds 16KiB, - is missing, A or B is not canonical unpadded standard base64, A exceeds 8KiB,
    ///   A does not decode as an NKS, A is not a credential, `WrappingPubkey` is not 32 bytes, B is not 64 bytes, or the public key derived
    ///   from B's seed differs from B's last 32 bytes or A's `WrappingPubkey`. Errors omit key contents.
    package init?(parsing authKey: String) throws(TKAError) {
        let text = Array(authKey.utf8)
        guard let marker = text.firstRange(of: Array("--TL".utf8)) else { return nil }
        let suffix = text[marker.upperBound...]
        guard text.count <= Self.maximumByteCount,
            let dash = suffix.firstIndex(of: UInt8(ascii: "-")),
            let credentialBytes = Self.decodeRawBase64(suffix[..<dash]),
            let privateKey = Self.decodeRawBase64(suffix[(dash + 1)...]),
            let credential = try? NodeKeySignature(decoding: credentialBytes),
            credential.kind == NodeKeySignature.Kind.credential,
            credential.wrappingPublicKey.count == 32,
            privateKey.count == Self.wrappedPrivateKeyByteCount,
            let wrappingKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKey[..<32])
        else { throw .invalidAuthKey }
        let publicKey = Array(wrappingKey.publicKey.rawRepresentation)
        guard publicKey == Array(privateKey[32...]), publicKey == credential.wrappingPublicKey else { throw .invalidAuthKey }
        controlValue = String(decoding: text[..<marker.lowerBound], as: UTF8.self)
        self.credential = credential
        self.wrappingKey = wrappingKey
    }

    /// A signature for a new node key (Go `SignByCredential`). Returns the canonical bytes of rotation NKS{`Pubkey`: np ‖ node key, `Nested`: credential}, whose `SigHash`
    /// is signed with the wrapped key. Put these bytes in the registration request's `NodeKeySignature` (behavior R5②).
    ///
    /// CryptoKit's Ed25519 signatures are nondeterministic, so the bytes differ on each call. The recipient verifies with Go's standard rules (notes §3.7).
    /// - Throws: `signingFailed` if CryptoKit could not sign.
    package func keySignature(for nodeKey: NodePublicKey) throws(TKAError) -> [UInt8] {
        var signature = NodeKeySignature(kind: NodeKeySignature.Kind.rotation, publicKey: nodeKey.binaryForm, nested: credential)
        try signature.sign(with: wrappingKey)
        return signature.serialized()
    }

    /// Reads only canonical unpadded standard base64 (RFC 4648 §4, `+/`). Returns nil for other characters, `=`, line breaks, 6 unused bits, or nonzero unused bits.
    /// Go `base64.RawStdEncoding` skips line breaks and ignores unused bits (behavior R3 accepts only the canonical form).
    private static func decodeRawBase64(_ text: ArraySlice<UInt8>) -> [UInt8]? {
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0
        var bitCount: UInt32 = 0
        for character in text {
            let value: UInt8
            switch character {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): value = character - UInt8(ascii: "A")
            case UInt8(ascii: "a")...UInt8(ascii: "z"): value = character - UInt8(ascii: "a") + 26
            case UInt8(ascii: "0")...UInt8(ascii: "9"): value = character - UInt8(ascii: "0") + 52
            case UInt8(ascii: "+"): value = 62
            case UInt8(ascii: "/"): value = 63
            default: return nil
            }
            buffer = buffer << 6 | UInt32(value)
            bitCount += 6
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8(truncatingIfNeeded: buffer >> bitCount))
                buffer &= (1 << bitCount) - 1
            }
        }
        guard bitCount < 6, buffer == 0 else { return nil }
        return bytes
    }
}

extension WrappedAuthKey: CustomStringConvertible, CustomReflectable {
    /// Redacts the auth key and wrapped key.
    package var description: String { "WrappedAuthKey(<redacted>)" }

    /// `dump` bypasses `description`, so omit all children.
    package var customMirror: Mirror { Mirror(self, children: []) }
}

extension NodeKeySignature {
    /// Signs `signatureHash` with Ed25519 to fill `signature` (Go `NLPrivate.SignNKS`, `ed25519.Sign`).
    ///
    /// - Throws: `signingFailed` if CryptoKit could not sign.
    mutating func sign(with key: Curve25519.Signing.PrivateKey) throws(TKAError) {
        do {
            signature = Array(try key.signature(for: signatureHash))
        } catch {
            throw .signingFailed
        }
    }
}
