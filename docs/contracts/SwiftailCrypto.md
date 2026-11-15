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

## Ed25519 서명 검증(M8)

Tailnet Lock의 서명 검증에 쓴다. 서명을 만들지 않고 비밀 값을 다루지 않는다. Go와 모든 입력에서 같은 판정을 내기 위해 CryptoKit의 검증 함수를 쓰지 않고 edwards25519를 순수 Swift로 구현한다(`docs/protocol-notes/tailnet-lock.md` 3.7·6.1).

```swift
public enum Ed25519Verification {
    /// ZIP-215 규칙(Go `github.com/hdevalence/ed25519consensus`의 `Verify`와 같은 판정).
    public static func isValidZIP215(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool
    /// Go 표준 라이브러리 `crypto/ed25519`의 `Verify`와 같은 판정.
    public static func isValidStandard(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool
}
```

두 규칙의 정의(Ed25519 순수 변형, k = SHA-512(R ‖ A ‖ M) mod L, R과 A는 받은 바이트 그대로 해시):

| 검사 | `isValidZIP215` | `isValidStandard` |
| --- | --- | --- |
| 길이(서명 64, 공개 키 32) | 아니면 거짓 | 아니면 거짓(Go는 공개 키 길이가 틀리면 panic) |
| `sig[63] & 224 == 0` | 필요 | 필요 |
| A 해독 | 비정준(y ≥ p, x = 0에 부호 비트) 허용, 곡선 밖은 거절 | 같음 |
| R | 같은 규칙으로 해독 | 해독하지 않고 바이트로 비교 |
| S | 정준(S < L) | 정준(S < L) |
| 식 | [8]([S]B − [k]A − R) = 0 | ([S]B − [k]A)의 정준 인코딩 = `sig[0..<32]` |

구현 규칙:

- 필드 GF(2^255−19)는 Go `crypto/internal/fips140/edwards25519/field`의 51비트 림 표현을 옮겼다(출처와 BSD-3-Clause는 `Sources/SwiftailCrypto/Edwards25519/FieldElement.swift` 머리). 점·스칼라·필드 타입은 `internal`이다.
- 입력이 모두 공개 값이므로 이중 스칼라 곱과 비교는 가변 시간이다. 표를 미리 계산하지 않는다(릴리스 빌드에서 서명 하나 0.08~0.21ms).
- 어떤 입력으로도 트랩하지 않는다. 길이가 틀리면 거짓이다.

시험 기준(`Tests/SwiftailCryptoTests/Ed25519VerificationTests.swift`):

1. RFC 8032 7.1 벡터 5개: 두 규칙 모두 참.
2. `ed25519consensus` `zip215_test.go`의 196개: ZIP-215는 모두 참, 표준이 참인 번호 집합은 Go 표준과 같다.
3. `Tools/interop/cmd/ed25519fixtures`가 뽑은 Go 두 구현의 판정(`Vectors/ed25519-verify.json`): 모든 사례에서 두 규칙 모두 Go와 같다. `SWIFTAIL_ED25519FIXTURES`에 도구 경로를 주면 새로 뽑은 판정과도 견준다.
4. 필드·스칼라 경계와 점 해독 실패의 단위 시험.

## BLAKE2b와 Argon2i (M8)

Tailnet Lock의 끄기 비밀 검증(`docs/protocol-notes/tailnet-lock.md` 4.5)이 쓴다. Go `tka.DisablementKDF`는 `argon2.Key(secret, "tailscale network-lock disablement salt", 4, 16·1024, 4, 32)`이고, 이것은 Argon2i(버전 0x13, 비밀 키·연관 자료 없음)다. Apple 프레임워크에 둘 다 없어 Swift로 쓴다.

```swift
/// BLAKE2b(RFC 7693). 출력 1~64바이트, 키 0~64바이트. 범위 밖은 BLAKE2s처럼 precondition으로 멈춘다.
public struct BLAKE2b: Sendable {
    public init(outputByteCount: Int = 64, key: [UInt8] = [])
    public mutating func update(_ data: some DataProtocol)
    public func finalize() -> [UInt8]
    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 64, key: [UInt8] = []) -> [UInt8]
}

/// Argon2i(RFC 9106, 버전 0x13). memoryKiB는 KiB 단위(Go argon2.Key의 memory와 같다).
public enum Argon2i {
    public static func derive(
        password: [UInt8], salt: [UInt8], iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) throws(CryptoError) -> [UInt8]
}
```

- 범위(RFC 9106 3.1): `parallelism ≥ 1`, `iterations ≥ 1`, `memoryKiB ≥ 8 × parallelism`, `outputByteCount` 4~2^32-1, 입력 길이 2^32-1 이하가 아니면 `CryptoError.invalidLength`. 비용 인자용 경우를 `CryptoError`에 더하지 않은 것은 다른 타깃의 전수 `switch`(`SwiftailMagicsock/DiscoSharedKey.swift`)가 깨지기 때문이다. 솔트 길이의 하한은 RFC 9106 3.1에 없어 두지 않는다. Go는 작은 메모리를 조용히 `8p`로 올리고 출력 길이를 검사하지 않지만 여기서는 거절한다.
- 차선은 한 스레드에서 조각(slice)마다 차례로 채운다. 같은 조각의 차선끼리는 서로 참조하지 않으므로(RFC 9106 3.4) 병렬 계산과 결과가 같다.
- 참조 블록은 주소 블록(3.4.1.2)에서만 고른다. 블록 내용에서 색인을 뽑지 않으므로 메모리 접근 순서가 비밀에 따라 달라지지 않는다.
- 메모리 `memoryKiB` KiB를 한 번에 잡는다. 호출자는 TKA 인자(16 MiB)처럼 감당할 수 있는 값만 준다.

관문:

1. BLAKE2b: RFC 7693 부록 A("abc")와 부록 E(자체 시험의 hash of hashes), BLAKE2 공식 KAT(키 없음·키 64바이트 각 256개, `Vectors/blake2b-kat.json`), 출력 길이 1·32·64, 블록 경계 0·1·127·128·129·255·256바이트, 나누어 넣은 `update`의 일치.
2. Argon2i: RFC 9106 5.2 벡터(비밀 키·연관 자료는 `@testable` 내부 함수로)와 H0, Go `argon2.Key` 기준값 75개(`Vectors/argon2i-go.json`, `Tools/interop/cmd/argon2fixtures`가 만든다. 패스 1~4, 메모리 8~16384 KiB와 4p의 배수가 아닌 값, 병렬도 1·2·4·8, 출력 4~1024바이트, 비밀·솔트 길이 0~200), TKA 인자의 `DisablementKDF(0xa5 × 32)`. `SWIFTAIL_ARGON2FIXTURES`에 도구 경로를 주면 새로 뽑아 견준다.
3. 범위 밖 인자의 오류.
