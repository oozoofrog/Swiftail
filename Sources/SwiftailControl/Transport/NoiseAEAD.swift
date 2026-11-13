import CryptoKit

/// 제어 Noise가 쓰는 AEAD: ChaCha20-Poly1305 IETF(CryptoKit), nonce = 0⁴ ‖ **빅엔디언** uint64 카운터.
///
/// Noise 규격과 WireGuard는 카운터를 리틀엔디언으로 쓰지만 Tailscale의 controlbase는 빅엔디언이다.
/// 둘은 카운터 1부터 달라지므로 핸드셰이크(카운터 0)만으로는 차이가 드러나지 않는다.
/// 핸드셰이크 안의 AEAD는 카운터 0과 AAD = 그 시점의 hash, 레코드는 방향별 카운터와 빈 AAD를 쓴다.
/// 암호문 배치는 ciphertext ‖ tag(16)이다.
///
/// `docs/protocol-notes/control-transport.md` 3.4·3.5절, 4.5절 표기
/// (출처: tailscale.com `control/controlbase/conn.go`, `handshake.go`).
enum NoiseAEAD {
    static let tagSize = 16

    /// 암호화하고 인증 태그를 붙인다.
    static func seal(_ plaintext: [UInt8], key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8] {
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce(counter), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        } catch {
            // CryptoKit은 키가 32바이트가 아니거나 nonce가 12바이트가 아닐 때만 실패한다.
            // 키는 HKDF 출력(32바이트)으로만 만들고 nonce는 아래에서 12바이트로 만들므로 도달하지 않는다.
            preconditionFailure("ChaChaPoly.seal은 고정 길이 키·nonce로 실패하지 않는다: \(type(of: error))")
        }
    }

    /// 태그를 검증하고 복호화한다. 태그보다 짧거나 태그가 틀리면 `nil`이며 평문을 한 바이트도 내놓지 않는다.
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
