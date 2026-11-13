import CryptoKit
import Foundation

/// NaCl crypto_secretbox_xsalsa20poly1305. 출력 배치는 tag(16) ‖ ciphertext.
public enum NaClSecretBox {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static let overhead = 16

    /// plaintext를 암호화하고 인증한다. key는 32바이트, nonce는 24바이트여야 하며 아니면 `invalidLength`.
    public static func seal(_ plaintext: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws -> [UInt8] {
        guard key.count == keyByteCount, nonce.count == nonceByteCount else { throw CryptoError.invalidLength }
        let message = Array(plaintext)
        // 키스트림의 앞 32바이트는 Poly1305 키, 그 뒤가 암호화 스트림이다.
        let stream = Salsa20.xsalsa20Keystream(key: key, nonce: nonce, count: 32 + message.count)
        var ciphertext = [UInt8](repeating: 0, count: message.count)
        for i in 0..<message.count { ciphertext[i] = message[i] ^ stream[32 + i] }
        let tag = Poly1305.authenticate(ciphertext, key: Array(stream[0..<32]))
        return tag + ciphertext
    }

    /// box(tag ‖ ciphertext)를 검증하고 복호화한다. 길이가 틀리면 `invalidLength`, 태그가 틀리면 `authenticationFailed`.
    /// 인증에 실패하면 평문을 돌려주지 않는다.
    public static func open(_ box: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws -> [UInt8] {
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

/// NaCl crypto_box_curve25519xsalsa20poly1305의 사전 계산(beforenm).
/// 결과 키로 NaClSecretBox.seal·open을 부르면 crypto_box와 같다.
public enum NaClBox {
    /// HSalsa20(key: X25519(privateKey, peerPublicKey), input: 0^16). 32바이트.
    /// 길이가 32바이트가 아니면 `invalidLength`, X25519 결과가 전부 0이면 `invalidKey`.
    public static func sharedKey(privateKey: [UInt8], peerPublicKey: [UInt8]) throws -> [UInt8] {
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

/// draft-irtf-cfrg-xchacha-03. 출력 배치는 ciphertext ‖ tag(16).
public enum XChaCha20Poly1305 {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24

    /// 부분 키 = HChaCha20(key, nonce[0..<16]), ChaCha20-Poly1305 nonce = 0^4 ‖ nonce[16..<24].
    private static func subkeyAndNonce(key: [UInt8], nonce: [UInt8]) throws -> (SymmetricKey, ChaChaPoly.Nonce) {
        guard key.count == keyByteCount, nonce.count == nonceByteCount else { throw CryptoError.invalidLength }
        let subkey = hchacha20(key: key, input: Array(nonce[0..<16]))
        let chachaNonce = try ChaChaPoly.Nonce(data: [UInt8](repeating: 0, count: 4) + nonce[16..<24])
        return (SymmetricKey(data: subkey), chachaNonce)
    }

    /// plaintext를 암호화하고 aad와 함께 인증한다. key는 32바이트, nonce는 24바이트여야 하며 아니면 `invalidLength`.
    public static func seal(_ plaintext: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws -> [UInt8] {
        let (subkey, chachaNonce) = try subkeyAndNonce(key: key, nonce: nonce)
        let box = try ChaChaPoly.seal(plaintext, using: subkey, nonce: chachaNonce, authenticating: aad)
        return Array(box.ciphertext) + Array(box.tag)
    }

    /// sealed(ciphertext ‖ tag)를 검증하고 복호화한다. 길이가 틀리면 `invalidLength`, 태그가 틀리면 `authenticationFailed`.
    public static func open(_ sealed: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws -> [UInt8] {
        let (subkey, chachaNonce) = try subkeyAndNonce(key: key, nonce: nonce)
        let bytes = Array(sealed)
        guard bytes.count >= 16 else { throw CryptoError.invalidLength }
        let box = try ChaChaPoly.SealedBox(
            nonce: chachaNonce,
            ciphertext: bytes[0..<(bytes.count - 16)],
            tag: bytes[(bytes.count - 16)...]
        )
        do {
            return Array(try ChaChaPoly.open(box, using: subkey, authenticating: aad))
        } catch {
            throw CryptoError.authenticationFailed
        }
    }
}
