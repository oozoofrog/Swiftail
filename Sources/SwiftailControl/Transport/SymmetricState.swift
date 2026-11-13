import CryptoKit
import SwiftailCrypto

/// Noise_IK_25519_ChaChaPoly_BLAKE2s의 대칭 상태(hash `h`와 chaining key `ck`)와 그 연산.
///
/// 핸드셰이크의 매 단계는 보낸·받은 값을 `h`에 섞고(transcript), DH 결과를 `ck`에 섞어 다음 AEAD 키를
/// 뽑는다. 마지막 `ck`에서 방향별 전송 키 둘이 나온다. `NoiseIK`는 이 연산들을 정해진 순서로 부를 뿐이다.
///
/// HKDF는 HMAC-BLAKE2s 기반이다(키 있는 BLAKE2s로 대신하면 안 된다). WireGuard의 IKpsk2와 달리
/// 임시 공개 키는 `h`에만 섞고 `ck`에는 섞지 않는다.
///
/// `docs/protocol-notes/control-transport.md` 4.5절 표기·1단계·15단계
/// (출처: tailscale.com `control/controlbase/handshake.go`).
struct SymmetricState {
    private(set) var hash: [UInt8]
    private(set) var chainingKey: [UInt8]

    /// h = BLAKE2s(protocolName), ck = h. 이름이 33바이트라 Noise 규칙으로도 해시를 거친다.
    init(protocolName: String) {
        hash = BLAKE2s.hash(Array(protocolName.utf8))
        chainingKey = hash
    }

    /// h = BLAKE2s(h ‖ data).
    mutating func mixHash(_ data: [UInt8]) {
        hash = BLAKE2s.hash(hash + data)
    }

    /// (ck, k) = HKDF(ck, X25519(privateKey, publicKey)). k는 바로 다음 AEAD 하나에만 쓴다.
    ///
    /// 공유 비밀이 전부 0이면(저차 점) `nil`이고 상태는 그대로다. 0을 HKDF에 넣고 계속하지 않는다.
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

    /// encryptAndHash의 역. 태그가 틀리면 `nil`이고 상태는 그대로다.
    mutating func decryptAndHash(_ ciphertext: [UInt8], key: SymmetricKey) -> [UInt8]? {
        guard let plaintext = NoiseAEAD.open(ciphertext[...], key: key, counter: 0, authenticating: hash) else { return nil }
        mixHash(ciphertext)
        return plaintext
    }

    /// (k_a, k_b) = HKDF(ck, 빈 입력). 초기자는 k_a로 보내고 k_b로 받는다.
    func split() -> (first: SymmetricKey, second: SymmetricKey) {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: [], outputCount: 2)
        return (SymmetricKey(data: outputs[0]), SymmetricKey(data: outputs[1]))
    }

    /// X25519. 상대 공개 키가 32바이트가 아니거나 결과가 전부 0이면 `nil`.
    private static func sharedSecret(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: [UInt8]) -> [UInt8]? {
        guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
              let secret = try? privateKey.sharedSecretFromKeyAgreement(with: peer)
        else { return nil }
        // SharedSecret은 바이트를 withUnsafeBytes로만 내준다. 클로저 안에서 배열로 복사할 뿐
        // 포인터를 밖으로 내보내지 않는다.
        let bytes = secret.withUnsafeBytes { Array($0) }
        guard !constantTimeEqual(bytes, [UInt8](repeating: 0, count: bytes.count)) else { return nil }
        return bytes
    }
}
