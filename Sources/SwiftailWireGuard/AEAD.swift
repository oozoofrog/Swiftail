import CryptoKit

/// WireGuard가 쓰는 AEAD: ChaCha20-Poly1305 IETF(CryptoKit), nonce = 0⁴ ‖ LE uint64 counter.
///
/// 핸드셰이크 안의 AEAD는 counter 0과 AAD = 현재 hash를 쓰고, transport는 메시지의 counter와
/// 빈 AAD를 쓴다. 암호문 배치는 ciphertext ‖ tag(16)이다.
///
/// 백서 §5.4, `docs/protocol-notes/wireguard.md` "기본 연산"·"전송 데이터: 보내기" 7
/// (출처: wireguard-go `device/noise-protocol.go`, `device/send.go`).
enum AEAD {
    static let tagSize = 16

    /// 암호화하고 인증 태그를 붙인다.
    static func seal(_ plaintext: [UInt8], key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8] {
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce(counter), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        } catch {
            // CryptoKit은 키가 32바이트가 아니거나 nonce가 12바이트가 아닐 때만 실패한다.
            // 키는 KDF 출력(32바이트)으로만 만들고 nonce는 위에서 12바이트로 만들므로 도달하지 않는다.
            preconditionFailure("ChaChaPoly.seal은 고정 길이 키·nonce로 실패하지 않는다: \(type(of: error))")
        }
    }

    /// 태그를 검증하고 복호화한다. 짧거나 태그가 틀리면 `nil`이며 평문을 한 바이트도 내놓지 않는다.
    static func open(_ sealed: [UInt8], key: SymmetricKey, counter: UInt64, authenticating aad: [UInt8] = []) -> [UInt8]? {
        guard sealed.count >= tagSize,
              let box = try? ChaChaPoly.SealedBox(
                  nonce: nonce(counter),
                  ciphertext: sealed[..<(sealed.count - tagSize)],
                  tag: sealed[(sealed.count - tagSize)...]
              ),
              let plaintext = try? ChaChaPoly.open(box, using: key, authenticating: aad)
        else { return nil }
        return Array(plaintext)
    }

    private static func nonce(_ counter: UInt64) throws -> ChaChaPoly.Nonce {
        try ChaChaPoly.Nonce(data: [0, 0, 0, 0] + counter.littleEndianBytes)
    }
}
