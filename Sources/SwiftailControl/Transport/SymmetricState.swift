import CryptoKit
import SwiftailCrypto

/// The symmetric state (hash `h` and chaining key `ck`) and operations of Noise_IK_25519_ChaChaPoly_BLAKE2s.
///
/// Each handshake step mixes sent and received values into `h` (the transcript) and mixes the DH result into `ck`
/// to derive the next AEAD key. The final `ck` yields two directional transport keys. `NoiseIK` only calls these operations in the prescribed order.
///
/// HKDF uses HMAC-BLAKE2s (keyed BLAKE2s cannot substitute for it). WireGuard's IKpsk2 differs in that
/// here the ephemeral public key is mixed only into `h` and never into `ck`.
///
/// `docs/protocol-notes/control-transport.md` §4.5 notation and steps 1 and 15
/// (origin: tailscale.com `control/controlbase/handshake.go`).
struct SymmetricState {
    private(set) var hash: [UInt8]
    private(set) var chainingKey: [UInt8]

    /// h = BLAKE2s(protocolName), ck = h. The name is 33 bytes, so the Noise rules also hash it.
    init(protocolName: String) {
        hash = BLAKE2s.hash(Array(protocolName.utf8))
        chainingKey = hash
    }

    /// h = BLAKE2s(h ‖ data).
    mutating func mixHash(_ data: [UInt8]) {
        hash = BLAKE2s.hash(hash + data)
    }

    /// (ck, k) = HKDF(ck, X25519(privateKey, publicKey)). k is used only for the very next AEAD operation.
    ///
    /// Returns `nil` and leaves state intact if the shared secret is all zeros (a low-order point). Stops before passing zero to HKDF.
    mutating func mixDH(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: [UInt8]) -> SymmetricKey? {
        guard let secret = Self.sharedSecret(privateKey, publicKey) else { return nil }
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: secret, outputCount: 2)
        chainingKey = outputs[0]
        return SymmetricKey(data: outputs[1])
    }

    /// c = AEAD(k, 0, plaintext, AAD = h), h = BLAKE2s(h ‖ c).
    mutating func encryptAndHash(_ plaintext: [UInt8], key: SymmetricKey) -> [UInt8] {
        let ciphertext = NoiseAEAD.seal(plaintext, key: key, counter: 0, authenticating: hash)
        mixHash(ciphertext)
        return ciphertext
    }

    /// The inverse of encryptAndHash. Returns `nil` and leaves state intact if the tag is incorrect.
    mutating func decryptAndHash(_ ciphertext: [UInt8], key: SymmetricKey) -> [UInt8]? {
        guard let plaintext = NoiseAEAD.open(ciphertext[...], key: key, counter: 0, authenticating: hash) else { return nil }
        mixHash(ciphertext)
        return plaintext
    }

    /// (k_a, k_b) = HKDF(ck, empty input). The initiator sends with k_a and receives with k_b.
    func split() -> (first: SymmetricKey, second: SymmetricKey) {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: [], outputCount: 2)
        return (SymmetricKey(data: outputs[0]), SymmetricKey(data: outputs[1]))
    }

    /// X25519. Returns `nil` if the peer public key is not 32 bytes or the result is all zeros.
    private static func sharedSecret(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: [UInt8]) -> [UInt8]? {
        guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
              let secret = try? privateKey.sharedSecretFromKeyAgreement(with: peer)
        else { return nil }
        // SharedSecret exposes bytes only through withUnsafeBytes. Copy them into an array inside the closure and
        // keep the pointer from escaping.
        let bytes = secret.withUnsafeBytes { Array($0) }
        guard !constantTimeEqual(bytes, [UInt8](repeating: 0, count: bytes.count)) else { return nil }
        return bytes
    }
}
