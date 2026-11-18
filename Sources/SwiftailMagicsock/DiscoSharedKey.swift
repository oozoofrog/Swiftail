import CryptoKit
import SwiftailBase
import SwiftailCrypto

/// A NaCl box shared key computed from the local disco private key and the peer's disco public key.
///
/// This is secret. Key bytes are kept inside this type and hidden by `customMirror`, so they do not appear in `print`, `dump`, or debugger summaries.
/// Computing the key with X25519 and HSalsa20 is expensive, so compute it once per peer key and reuse it (`docs/protocol-notes/disco-magicsock.md` 3.2 5).
///
/// `box.Seal` and `box.Open` seal and open with the same key by using `secretbox` with this key (notes 3.2 2 and 3).
struct DiscoSharedKey: Sendable, CustomReflectable {
    private let key: [UInt8]

    /// - Throws: `invalidKey` if the peer's public key is low-order and the shared key is 0 (Go uses 0 as is, while M4 discards it. Notes 3.2).
    init(privateKey: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: DiscoPublicKey) throws(DiscoError) {
        do {
            key = try NaClBox.sharedKey(privateKey: Array(privateKey.rawRepresentation), peerPublicKey: peerPublicKey.rawValue)
        } catch {
            throw .invalidKey
        }
    }

    var customMirror: Mirror {
        Mirror(self, children: [])
    }

    /// Seals `plaintext` with `nonce` (24 bytes). The output layout is tag(16) ‖ ciphertext.
    ///
    /// The caller must supply the correct nonce length. A mismatch traps as a programming error (this is not peer input).
    func seal(_ plaintext: [UInt8], nonce: [UInt8]) -> [UInt8] {
        guard let sealed = try? NaClSecretBox.seal(plaintext, nonce: nonce, key: key) else {
            preconditionFailure("The disco nonce must be \(NaClSecretBox.nonceByteCount) bytes long")
        }
        return sealed
    }

    /// Opens tag ‖ ciphertext and returns plaintext.
    ///
    /// - Throws: `authenticationFailed` if the key, nonce, tag, or ciphertext does not match. `malformed` if the nonce or box is shorter than specified.
    func open(_ box: ArraySlice<UInt8>, nonce: [UInt8]) throws(DiscoError) -> [UInt8] {
        do {
            return try NaClSecretBox.open(box, nonce: nonce, key: key)
        } catch {
            switch error {
            case .invalidLength: throw .malformed
            case .authenticationFailed, .invalidKey: throw .authenticationFailed
            }
        }
    }
}
