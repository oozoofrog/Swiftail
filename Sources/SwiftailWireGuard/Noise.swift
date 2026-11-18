import CryptoKit
import SwiftailCrypto

/// The Noise protocol's symmetric state (chaining key and hash) and its operations.
///
/// Each handshake stage mixes received and sent values into the hash (the transcript) and mixes DH results into the chaining key
/// to derive the next AEAD key. The two transport keys come from the final chaining key.
/// `Handshake` simply calls these operations in the order WireGuard specifies.
///
/// Whitepaper §5.4, Noise specification §5.2, `docs/protocol-notes/wireguard.md` "Basic operations" and "Initial constants"
/// (origin: wireguard-go `device/noise-protocol.go`, `device/noise-helpers.go`).
struct SymmetricState {
    private(set) var chainingKey: [UInt8]
    private(set) var hash: [UInt8]

    /// ck = HASH(construction), h = HASH(ck ‖ identifier).
    static let initial: SymmetricState = {
        let chainingKey = BLAKE2s.hash(Array("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8))
        let hash = BLAKE2s.hash(chainingKey + Array("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8))
        return SymmetricState(chainingKey: chainingKey, hash: hash)
    }()

    /// h = HASH(h ‖ data).
    mutating func mixHash(_ data: [UInt8]) {
        hash = BLAKE2s.hash(hash + data)
    }

    /// ck = KDF1(ck, input).
    mutating func mixKey(_ input: [UInt8]) {
        chainingKey = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: input, outputCount: 1)[0]
    }

    /// (ck, k) = KDF2(ck, input). Use k only for the very next AEAD operation.
    mutating func mixKeyAndDeriveKey(_ input: [UInt8]) -> SymmetricKey {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: input, outputCount: 2)
        chainingKey = outputs[0]
        return SymmetricKey(data: outputs[1])
    }

    /// (ck, τ, k) = KDF3(ck, psk), h = HASH(h ‖ τ). This step runs even when the PSK layer is unused.
    mutating func mixPresharedKey(_ presharedKey: [UInt8]) -> SymmetricKey {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: presharedKey, outputCount: 3)
        chainingKey = outputs[0]
        mixHash(outputs[1])
        return SymmetricKey(data: outputs[2])
    }

    /// c = AEAD(k, 0, plaintext, AAD = h), h = HASH(h ‖ c).
    mutating func encryptAndHash(_ plaintext: [UInt8], key: SymmetricKey) -> [UInt8] {
        let ciphertext = AEAD.seal(plaintext, key: key, counter: 0, authenticating: hash)
        mixHash(ciphertext)
        return ciphertext
    }

    /// The inverse of encryptAndHash. Returns `nil` and leaves state unchanged if the tag is invalid.
    mutating func decryptAndHash(_ ciphertext: [UInt8], key: SymmetricKey) -> [UInt8]? {
        guard let plaintext = AEAD.open(ciphertext, key: key, counter: 0, authenticating: hash) else { return nil }
        mixHash(ciphertext)
        return plaintext
    }

    /// (T1, T2) = KDF2(ck, empty input). The initiator uses them as (send, receive) and the responder as (receive, send).
    func split() -> (first: SymmetricKey, second: SymmetricKey) {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: [], outputCount: 2)
        return (SymmetricKey(data: outputs[0]), SymmetricKey(data: outputs[1]))
    }
}

/// X25519 DH. Returns `nil` if the peer's public key is a low-order point whose result is all 0 ("DH failure" in whitepaper §5.4).
func sharedSecret(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: [UInt8]) -> [UInt8]? {
    guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
          let secret = try? privateKey.sharedSecretFromKeyAgreement(with: peer)
    else { return nil }
    // SharedSecret exposes its bytes only through withUnsafeBytes. Copy them into an array inside the closure
    // without letting the pointer escape.
    let bytes = secret.withUnsafeBytes { Array($0) }
    guard !constantTimeEqual(bytes, [UInt8](repeating: 0, count: 32)) else { return nil }
    return bytes
}
