import CryptoKit

/// The control Noise AEAD, ChaCha20-Poly1305 IETF (CryptoKit), with nonce = 0⁴ ‖ **big-endian** uint64 counter.
///
/// The Noise specification and WireGuard use little-endian counters. Tailscale's controlbase uses big-endian.
/// The representations diverge starting at counter 1, so a handshake alone (counter 0) does not reveal the difference.
/// Handshake AEAD uses counter 0 with AAD = the current hash. Records use per-direction counters and empty AAD.
/// The ciphertext layout is ciphertext ‖ tag(16).
///
/// `docs/protocol-notes/control-transport.md` §3.4, §3.5, and §4.5 notation
/// (origin: tailscale.com `control/controlbase/conn.go`, `handshake.go`).
enum NoiseAEAD {
    static let tagSize = 16

    /// Encrypts and appends the authentication tag.
    static func seal(_ plaintext: [UInt8], key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8] {
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce(counter), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        } catch {
            // CryptoKit fails only if the key is not 32 bytes or the nonce is not 12 bytes.
            // Keys come only from HKDF output (32 bytes) and the nonce below is 12 bytes, so this is unreachable.
            preconditionFailure("ChaChaPoly.seal cannot fail with a fixed-length key and nonce: \(type(of: error))")
        }
    }

    /// Verifies the tag and decrypts. If the input is shorter than the tag or the tag is incorrect, returns `nil` without yielding any plaintext.
    static func open(_ sealed: ArraySlice<UInt8>, key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8]? {
        guard sealed.count >= tagSize,
              let box = try? ChaChaPoly.SealedBox(
                  nonce: nonce(counter),
                  ciphertext: sealed.dropLast(tagSize),
                  tag: sealed.suffix(tagSize)
              ),
              let plaintext = try? ChaChaPoly.open(box, using: key, authenticating: aad)
        else { return nil }
        return Array(plaintext)
    }

    private static func nonce(_ counter: UInt64) throws -> ChaChaPoly.Nonce {
        try ChaChaPoly.Nonce(data: [0, 0, 0, 0] + counter.bigEndianBytes)
    }
}
