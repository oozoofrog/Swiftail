import CryptoKit
import SwiftailCrypto

/// Noise 프로토콜의 대칭 상태(chaining key와 hash)와 그 연산.
///
/// 핸드셰이크의 매 단계는 받은·보낸 값을 hash에 섞고(transcript), DH 결과를 chaining key에 섞어
/// 다음 AEAD 키를 뽑는다. 마지막 chaining key에서 전송 키 둘이 나온다.
/// `Handshake`는 이 연산들을 WireGuard가 정한 순서로 부를 뿐이다.
///
/// 백서 §5.4, Noise 규격 §5.2, `docs/protocol-notes/wireguard.md` "기본 연산"·"초기 상수"
/// (출처: wireguard-go `device/noise-protocol.go`, `device/noise-helpers.go`).
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

    /// (ck, k) = KDF2(ck, input). k는 바로 다음 AEAD 하나에만 쓴다.
    mutating func mixKeyAndDeriveKey(_ input: [UInt8]) -> SymmetricKey {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: input, outputCount: 2)
        chainingKey = outputs[0]
        return SymmetricKey(data: outputs[1])
    }

    /// (ck, τ, k) = KDF3(ck, psk), h = HASH(h ‖ τ). PSK 계층을 쓰지 않아도 이 단계는 그대로 거친다.
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

    /// encryptAndHash의 역. 태그가 틀리면 `nil`이고 상태는 그대로다.
    mutating func decryptAndHash(_ ciphertext: [UInt8], key: SymmetricKey) -> [UInt8]? {
        guard let plaintext = AEAD.open(ciphertext, key: key, counter: 0, authenticating: hash) else { return nil }
        mixHash(ciphertext)
        return plaintext
    }

    /// (T1, T2) = KDF2(ck, 빈 입력). 초기자는 (송신, 수신), 응답자는 (수신, 송신)으로 쓴다.
    func split() -> (first: SymmetricKey, second: SymmetricKey) {
        let outputs = HKDFBLAKE2s.derive(chainingKey: chainingKey, input: [], outputCount: 2)
        return (SymmetricKey(data: outputs[0]), SymmetricKey(data: outputs[1]))
    }
}

/// X25519 DH. 상대 공개 키가 저차 점이라 결과가 전부 0이면 `nil`이다(백서 §5.4의 "DH 실패").
func sharedSecret(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ publicKey: [UInt8]) -> [UInt8]? {
    guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
          let secret = try? privateKey.sharedSecretFromKeyAgreement(with: peer)
    else { return nil }
    // SharedSecret은 바이트를 withUnsafeBytes로만 내준다. 클로저 안에서 배열로 복사할 뿐
    // 포인터를 밖으로 내보내지 않는다.
    let bytes = secret.withUnsafeBytes { Array($0) }
    guard !constantTimeEqual(bytes, [UInt8](repeating: 0, count: 32)) else { return nil }
    return bytes
}
