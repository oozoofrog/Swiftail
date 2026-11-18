import CryptoKit
import Foundation

/// NaCl crypto_secretbox_xsalsa20poly1305. The output layout is tag(16) ‖ ciphertext.
public enum NaClSecretBox {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static let overhead = 16

    /// Encrypts and authenticates plaintext. Requires a 32-byte key and 24-byte nonce, otherwise throws `invalidLength`.
    public static func seal(_ plaintext: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard key.count == keyByteCount, nonce.count == nonceByteCount else { throw CryptoError.invalidLength }
        let message = Array(plaintext)
        // The first 32 bytes of the keystream are the Poly1305 key. The rest is the encryption stream.
        let stream = Salsa20.xsalsa20Keystream(key: key, nonce: nonce, count: 32 + message.count)
        var ciphertext = [UInt8](repeating: 0, count: message.count)
        for i in 0..<message.count { ciphertext[i] = message[i] ^ stream[32 + i] }
        let tag = Poly1305.authenticate(ciphertext, key: Array(stream[0..<32]))
        return tag + ciphertext
    }

    /// Verifies and decrypts the box (tag ‖ ciphertext). Throws `invalidLength` for an incorrect length or `authenticationFailed` for an incorrect tag.
    /// Returns plaintext only if authentication succeeds.
    public static func open(_ box: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard key.count == keyByteCount, nonce.count == nonceByteCount else { throw CryptoError.invalidLength }
        let bytes = Array(box)
        guard bytes.count >= overhead else { throw CryptoError.invalidLength }
        let tag = Array(bytes[0..<overhead])
        let ciphertext = Array(bytes[overhead...])
        let stream = Salsa20.xsalsa20Keystream(key: key, nonce: nonce, count: 32 + ciphertext.count)
        let expected = Poly1305.authenticate(ciphertext, key: Array(stream[0..<32]))
        guard constantTimeEqual(tag, expected) else { throw CryptoError.authenticationFailed }
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count)
        for i in 0..<ciphertext.count { plaintext[i] = ciphertext[i] ^ stream[32 + i] }
        return plaintext
    }
}

/// Precomputation (beforenm) for NaCl crypto_box_curve25519xsalsa20poly1305.
/// Calling NaClSecretBox.seal or NaClSecretBox.open with the resulting key is equivalent to crypto_box.
public enum NaClBox {
    /// Returns 32 bytes from HSalsa20(key: X25519(privateKey, peerPublicKey), input: 0^16).
    /// Throws `invalidLength` for a length other than 32 bytes or `invalidKey` for an all-zero X25519 result.
    public static func sharedKey(privateKey: [UInt8], peerPublicKey: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard privateKey.count == 32, peerPublicKey.count == 32 else { throw CryptoError.invalidLength }
        let secret: [UInt8]
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            secret = try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Array($0) }
        } catch {
            throw CryptoError.invalidKey
        }
        guard !constantTimeEqual(secret, [UInt8](repeating: 0, count: 32)) else { throw CryptoError.invalidKey }
        return Salsa20.hsalsa20(key: secret, input: [UInt8](repeating: 0, count: 16))
    }
}

/// draft-irtf-cfrg-xchacha-03. The output layout is ciphertext ‖ tag(16).
public enum XChaCha20Poly1305 {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24

    /// Subkey = HChaCha20(key, nonce[0..<16]), ChaCha20-Poly1305 nonce = 0^4 ‖ nonce[16..<24].
    private static func subkeyAndNonce(key: [UInt8], nonce: [UInt8]) throws(CryptoError) -> (SymmetricKey, ChaChaPoly.Nonce) {
        guard key.count == keyByteCount, nonce.count == nonceByteCount else { throw .invalidLength }
        let subkey = hchacha20(key: key, input: Array(nonce[0..<16]))
        // The 12-byte nonce cannot fail, but keep CryptoKit's error type internal.
        guard let chachaNonce = try? ChaChaPoly.Nonce(data: [UInt8](repeating: 0, count: 4) + nonce[16..<24]) else {
            throw .invalidLength
        }
        return (SymmetricKey(data: subkey), chachaNonce)
    }

    /// Encrypts plaintext and authenticates it with aad. Requires a 32-byte key and 24-byte nonce, otherwise throws `invalidLength`.
    public static func seal(_ plaintext: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws(CryptoError) -> [UInt8] {
        let (subkey, chachaNonce) = try subkeyAndNonce(key: key, nonce: nonce)
        guard let box = try? ChaChaPoly.seal(plaintext, using: subkey, nonce: chachaNonce, authenticating: aad) else {
            throw .invalidLength
        }
        return Array(box.ciphertext) + Array(box.tag)
    }

    /// Verifies and decrypts sealed (ciphertext ‖ tag). Throws `invalidLength` for an incorrect length or `authenticationFailed` for an incorrect tag.
    public static func open(_ sealed: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws(CryptoError) -> [UInt8] {
        let (subkey, chachaNonce) = try subkeyAndNonce(key: key, nonce: nonce)
        let bytes = Array(sealed)
        guard bytes.count >= 16 else { throw CryptoError.invalidLength }
        guard let box = try? ChaChaPoly.SealedBox(
            nonce: chachaNonce,
            ciphertext: bytes[0..<(bytes.count - 16)],
            tag: bytes[(bytes.count - 16)...]
        ) else { throw .invalidLength }
        guard let plaintext = try? ChaChaPoly.open(box, using: subkey, authenticating: aad) else {
            throw .authenticationFailed
        }
        return Array(plaintext)
    }
}
