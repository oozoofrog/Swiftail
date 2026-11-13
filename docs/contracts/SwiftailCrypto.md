# SwiftailCrypto 계약 (M0)

CryptoKit에 없는 암호 기본기를 제공한다. X25519와 ChaCha20-Poly1305(12바이트 nonce)는 CryptoKit을 그대로 쓰므로 여기에 감싸지 않는다.

## 쓰는 곳

| 기본기 | 쓰는 프로토콜 |
| --- | --- |
| BLAKE2s-256, HMAC-BLAKE2s, HKDF-BLAKE2s | WireGuard 핸드셰이크, 제어 프로토콜 Noise |
| 키 있는 BLAKE2s(16바이트 출력) | WireGuard mac1·mac2 |
| XChaCha20-Poly1305 | WireGuard cookie reply |
| NaCl box·secretbox (Curve25519-XSalsa20-Poly1305) | DERP clientInfo·serverInfo, disco |

## 공개 API

입력은 `some DataProtocol`, 키·nonce·출력은 `[UInt8]`이다. 길이가 틀린 키·nonce는 `CryptoError.invalidLength`를 던진다. 던지는 함수는 모두 타입 있는 오류(`throws(CryptoError)`)다. `BLAKE2s.init`만 예외로, 잘못된 길이는 프로그래머 오류이므로 `precondition`으로 막는다.

```swift
public enum CryptoError: Error, Sendable, Equatable {
    case invalidLength          // 키·nonce·암호문 길이가 규격과 다름
    case authenticationFailed   // 태그 불일치
    case invalidKey             // X25519 결과가 전부 0(저차 점)
}

/// RFC 7693 BLAKE2s. 순차 모드만.
public struct BLAKE2s: Sendable {
    /// outputByteCount는 1...32, key는 0...32바이트.
    public init(outputByteCount: Int = 32, key: [UInt8] = [])
    public mutating func update(_ data: some DataProtocol)
    /// 지금까지의 입력에 대한 해시. 상태를 바꾸지 않으므로 이어서 update할 수 있다.
    public func finalize() -> [UInt8]
    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 32, key: [UInt8] = []) -> [UInt8]
}

/// RFC 2104 HMAC, 해시는 BLAKE2s-256(블록 64바이트). 출력 32바이트.
public enum HMACBLAKE2s {
    public static func authenticationCode(for data: some DataProtocol, key: [UInt8]) -> [UInt8]
}

/// Noise·WireGuard의 KDFn.
/// PRK = HMAC(chainingKey, input), T1 = HMAC(PRK, 0x01), T2 = HMAC(PRK, T1 ‖ 0x02), T3 = HMAC(PRK, T2 ‖ 0x03).
public enum HKDFBLAKE2s {
    /// outputCount는 1...3. 각 출력은 32바이트.
    public static func derive(chainingKey: [UInt8], input: some DataProtocol, outputCount: Int) -> [[UInt8]]
}

/// NaCl crypto_secretbox_xsalsa20poly1305. 출력 배치는 tag(16) ‖ ciphertext.
public enum NaClSecretBox {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static let overhead = 16
    public static func seal(_ plaintext: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws(CryptoError) -> [UInt8]
    public static func open(_ box: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws(CryptoError) -> [UInt8]
}

/// NaCl crypto_box_curve25519xsalsa20poly1305의 사전 계산(beforenm).
/// 결과 키로 NaClSecretBox.seal·open을 부르면 crypto_box와 같다.
public enum NaClBox {
    /// HSalsa20(key: X25519(privateKey, peerPublicKey), input: 0^16). 32바이트.
    public static func sharedKey(privateKey: [UInt8], peerPublicKey: [UInt8]) throws(CryptoError) -> [UInt8]
}

/// draft-irtf-cfrg-xchacha-03. 출력 배치는 ciphertext ‖ tag(16).
public enum XChaCha20Poly1305 {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static func seal(_ plaintext: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws(CryptoError) -> [UInt8]
    public static func open(_ sealed: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws(CryptoError) -> [UInt8]
}

/// 길이가 같으면 내용과 무관한 시간에 비교한다. 길이가 다르면 false.
public func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool
```

## 구현 규칙

- Salsa20 코어, HSalsa20, HChaCha20, Poly1305는 `internal`로 두고 시험은 `@testable import`로 한다.
- XChaCha20-Poly1305는 HChaCha20으로 부분 키를 만든 뒤 CryptoKit `ChaChaPoly`에 맡긴다.
- 비밀 값에 따라 달라지는 분기·표 조회를 쓰지 않는다. 태그 비교는 `constantTimeEqual`로 한다.
- 인증에 실패하면 평문을 한 바이트도 돌려주지 않는다.
- 처리량은 목표가 아니다(이 기본기들은 핸드셰이크와 제어 메시지에만 쓰인다). 읽기 쉬운 스칼라 구현으로 쓴다.

## 관문

1. 규격의 공개 벡터: RFC 7693 부록, BLAKE2 공식 KAT(키 있는 BLAKE2s), RFC 8439의 Poly1305 벡터(§2.5.2, 부록 A.3), NaCl 문서의 box·secretbox 벡터, draft-irtf-cfrg-xchacha-03의 HChaCha20·AEAD 벡터, wireguard-go `device/kdf_test.go`의 HMAC·KDF 벡터.
2. Go `golang.org/x/crypto`로 만든 교차 벡터(여러 길이, 블록 경계 포함).
3. 변조 시험: 태그·암호문·nonce·AAD의 한 비트를 바꾸면 `authenticationFailed`.
4. 구현을 쓴 제공자와 다른 제공자의 코드 검토.
