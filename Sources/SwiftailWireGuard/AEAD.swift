import CryptoKit
import Foundation

/// The AEAD used by WireGuard, ChaCha20-Poly1305 IETF (CryptoKit), with nonce = 0⁴ ‖ LE uint64 counter.
///
/// AEAD in the handshake uses counter 0 and AAD = the current hash. Transport uses the message's counter and
/// empty AAD. The ciphertext layout is ciphertext ‖ tag (16).
///
/// Whitepaper §5.4, `docs/protocol-notes/wireguard.md` "Basic operations" and "Transport data: sending" 7
/// (origin: wireguard-go `device/noise-protocol.go`, `device/send.go`).
enum AEAD {
    static let tagSize = 16

    /// Encrypts the plaintext and attaches an authentication tag.
    static func seal(_ plaintext: [UInt8], key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8] {
        var sealed: [UInt8] = []
        sealed.reserveCapacity(plaintext.count + tagSize)
        seal(plaintext, key: key, counter: counter, authenticating: aad, appendingTo: &sealed)
        return sealed
    }

    /// Appends the encrypted result (ciphertext ‖ tag) to `output`. The caller can write the header first to build the message in a single array.
    static func seal(_ plaintext: [UInt8], key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = [], appendingTo output: inout [UInt8]) {
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce(counter), authenticating: aad)
            output.append(contentsOf: box.ciphertext)
            output.append(contentsOf: box.tag)
        } catch {
            // CryptoKit fails only if the key is not 32 bytes or the nonce is not 12 bytes.
            // This is unreachable because keys come only from KDF output (32 bytes) and the nonce is constructed above as 12 bytes.
            preconditionFailure("ChaChaPoly.seal cannot fail with a fixed-length key and nonce: \(type(of: error))")
        }
    }

    /// Verifies the tag and decrypts. Returns `nil` without releasing any plaintext if the input is too short or the tag is invalid.
    static func open(_ sealed: some DataProtocol, key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8]? {
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
        var bytes = Data(count: 12)  // 12 bytes fit in Data's inline storage, so there is no allocation.
        for offset in 0..<8 {
            bytes[4 + offset] = UInt8(truncatingIfNeeded: counter >> (8 * UInt64(offset)))
        }
        return try ChaChaPoly.Nonce(data: bytes)
    }
}
