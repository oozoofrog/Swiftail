# SwiftailCrypto Contract (M0)

Provides cryptographic primitives missing from CryptoKit. Use CryptoKit directly for X25519 and ChaCha20-Poly1305 (12-byte nonce), so this module provides no wrappers for them.

## Uses

| Primitive | Protocols that use it |
| --- | --- |
| BLAKE2s-256, HMAC-BLAKE2s, HKDF-BLAKE2s | WireGuard handshake, control protocol Noise |
| Keyed BLAKE2s (16-byte output) | WireGuard mac1 and mac2 |
| XChaCha20-Poly1305 | WireGuard cookie reply |
| NaCl box and secretbox (Curve25519-XSalsa20-Poly1305) | DERP clientInfo and serverInfo, disco |

## Public API

Inputs use `some DataProtocol`, and keys, nonces, and outputs use `[UInt8]`. Keys and nonces of incorrect lengths throw `CryptoError.invalidLength`. All throwing functions use typed errors (`throws(CryptoError)`). The sole exception is `BLAKE2s.init`, which enforces lengths with a `precondition` because an incorrect length is a programmer error.

```swift
public enum CryptoError: Error, Sendable, Equatable {
    case invalidLength          // Key, nonce, or ciphertext length differs from the specification
    case authenticationFailed   // Tag mismatch
    case invalidKey             // The X25519 result is all 0 (low-order point)
}

/// RFC 7693 BLAKE2s in sequential mode only.
public struct BLAKE2s: Sendable {
    /// The outputByteCount is 1...32, and the key is 0...32 bytes.
    public init(outputByteCount: Int = 32, key: [UInt8] = [])
    public mutating func update(_ data: some DataProtocol)
    /// Returns the hash of the input so far. The state is unchanged, so you can continue calling update.
    public func finalize() -> [UInt8]
    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 32, key: [UInt8] = []) -> [UInt8]
}

/// RFC 2104 HMAC using BLAKE2s-256 (64-byte block). The output is 32 bytes.
public enum HMACBLAKE2s {
    public static func authenticationCode(for data: some DataProtocol, key: [UInt8]) -> [UInt8]
}

/// KDFn from Noise and WireGuard.
/// PRK = HMAC(chainingKey, input), T1 = HMAC(PRK, 0x01), T2 = HMAC(PRK, T1 ‖ 0x02), T3 = HMAC(PRK, T2 ‖ 0x03).
public enum HKDFBLAKE2s {
    /// Accepts an outputCount of 1...3. Each output is 32 bytes.
    public static func derive(chainingKey: [UInt8], input: some DataProtocol, outputCount: Int) -> [[UInt8]]
}

/// NaCl crypto_secretbox_xsalsa20poly1305. The output layout is tag(16) ‖ ciphertext.
public enum NaClSecretBox {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static let overhead = 16
    public static func seal(_ plaintext: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws(CryptoError) -> [UInt8]
    public static func open(_ box: some DataProtocol, nonce: [UInt8], key: [UInt8]) throws(CryptoError) -> [UInt8]
}

/// NaCl crypto_box_curve25519xsalsa20poly1305 precomputation (beforenm).
/// Calling NaClSecretBox.seal or NaClSecretBox.open with the resulting key is equivalent to crypto_box.
public enum NaClBox {
    /// HSalsa20(key: X25519(privateKey, peerPublicKey), input: 0^16). 32 bytes.
    public static func sharedKey(privateKey: [UInt8], peerPublicKey: [UInt8]) throws(CryptoError) -> [UInt8]
}

/// draft-irtf-cfrg-xchacha-03. The output layout is ciphertext ‖ tag(16).
public enum XChaCha20Poly1305 {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static func seal(_ plaintext: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws(CryptoError) -> [UInt8]
    public static func open(_ sealed: some DataProtocol, key: [UInt8], nonce: [UInt8], authenticating aad: some DataProtocol) throws(CryptoError) -> [UInt8]
}

/// Compares equal-length inputs in time independent of their contents. Returns false if the lengths differ.
public func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool
```

## Implementation Rules

- Keep the Salsa20 core, HSalsa20, HChaCha20, and Poly1305 `internal` and test them with `@testable import`.
- For XChaCha20-Poly1305, derive the subkey with HChaCha20, then delegate to CryptoKit `ChaChaPoly`.
- Avoid branches and table lookups that depend on secret values. Compare tags with `constantTimeEqual`.
- Return no plaintext bytes if authentication fails.
- Throughput is outside the goals (these primitives are used only for handshakes and control messages). Use readable scalar implementations.

## Gate

1. Public specification vectors include the RFC 7693 appendix, the official BLAKE2 KAT (keyed BLAKE2s), the RFC 8439 Poly1305 vectors (§2.5.2, Appendix A.3), the box and secretbox vectors from the NaCl documentation, the HChaCha20 and AEAD vectors from draft-irtf-cfrg-xchacha-03, and the HMAC and KDF vectors from wireguard-go `device/kdf_test.go`.
2. Cross-implementation vectors generated with Go `golang.org/x/crypto` (multiple lengths, including block boundaries).
3. Tampering tests. Changing one bit of the tag, ciphertext, nonce, or AAD yields `authenticationFailed`.
4. Code review by a provider other than the provider that wrote the implementation.

## Ed25519 Signature Verification (M8)

Tailnet Lock uses this for signature verification. It creates no signatures and handles no secret values. To match Go's verdict for every input, implement edwards25519 in pure Swift without CryptoKit's verification function (`docs/protocol-notes/tailnet-lock.md` §3.7 and §6.1).

```swift
public enum Ed25519Verification {
    /// Applies the ZIP-215 rules (the same verdict as `Verify` in Go's `github.com/hdevalence/ed25519consensus`).
    public static func isValidZIP215(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool
    /// Returns the same verdict as `Verify` in Go's standard library `crypto/ed25519`.
    public static func isValidStandard(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool
}
```

The two rules are defined below (pure Ed25519 variant, k = SHA-512(R ‖ A ‖ M) mod L, hashing R and A exactly as received).

| Check | `isValidZIP215` | `isValidStandard` |
| --- | --- | --- |
| Length (signature 64, public key 32) | False if incorrect | False if incorrect (Go panics if the public key length is wrong) |
| `sig[63] & 224 == 0` | Required | Required |
| Decode A | Allow noncanonical encodings (y ≥ p, sign bit with x = 0), reject points off the curve | Same |
| R | Decode by the same rules | Compare bytes without decoding |
| S | Canonical (S < L) | Canonical (S < L) |
| Equation | [8]([S]B − [k]A − R) = 0 | Canonical encoding of ([S]B − [k]A) = `sig[0..<32]` |

Implementation rules follow.

- Port the 51-bit limb representation for the field GF(2^255−19) from Go's `crypto/internal/fips140/edwards25519/field` (origin and BSD-3-Clause at the top of `Sources/SwiftailCrypto/Edwards25519/FieldElement.swift`). Point, scalar, and field types are `internal`.
- All inputs are public, so double-scalar multiplication and comparison take variable time. No tables are precomputed (0.08~0.21ms per signature in a release build).
- No input causes a trap. Incorrect lengths return false.

Test criteria (`Tests/SwiftailCryptoTests/Ed25519VerificationTests.swift`) follow.

1. The 5 RFC 8032 §7.1 vectors return true under both rules.
2. The 196 vectors in `ed25519consensus` `zip215_test.go` all return true under ZIP-215. The set of vector numbers that return true under the standard rules matches standard Go.
3. Verdicts from both Go implementations collected by `Tools/interop/cmd/ed25519fixtures` (`Vectors/ed25519-verify.json`). Both rules match Go in every case. Supplying the tool path in `SWIFTAIL_ED25519FIXTURES` also compares against freshly generated verdicts.
4. Unit tests for field and scalar boundaries and point decoding failures.

## BLAKE2b and Argon2i (M8)

Tailnet Lock disablement secret verification (`docs/protocol-notes/tailnet-lock.md` §4.5) uses these primitives. Go's `tka.DisablementKDF` is `argon2.Key(secret, "tailscale network-lock disablement salt", 4, 16·1024, 4, 32)`, which is Argon2i (version 0x13, no secret key or associated data). Apple frameworks provide neither primitive, so implement both in Swift.

```swift
/// BLAKE2b (RFC 7693) with a 1~64-byte output and a 0~64-byte key. A precondition stops execution for out-of-range values, as in BLAKE2s.
public struct BLAKE2b: Sendable {
    public init(outputByteCount: Int = 64, key: [UInt8] = [])
    public mutating func update(_ data: some DataProtocol)
    public func finalize() -> [UInt8]
    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 64, key: [UInt8] = []) -> [UInt8]
}

/// Argon2i (RFC 9106, version 0x13). memoryKiB is in KiB (the same as memory in Go argon2.Key).
public enum Argon2i {
    public static func derive(
        password: [UInt8], salt: [UInt8], iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) throws(CryptoError) -> [UInt8]
}
```

- Ranges (RFC 9106 §3.1) are `parallelism ≥ 1`, `iterations ≥ 1`, `memoryKiB ≥ 8 × parallelism`, `outputByteCount` of 4~2^32-1, and input lengths no greater than 2^32-1. Values outside these ranges yield `CryptoError.invalidLength`. Adding a cost-parameter case to `CryptoError` would break an exhaustive `switch` in another target (`SwiftailMagicsock/DiscoSharedKey.swift`). RFC 9106 §3.1 specifies no minimum salt length, so there is none here. Go silently raises small memory values to `8p` and skips output length validation. This implementation rejects those out-of-range values.
- Fill the lanes sequentially, slice by slice, on one thread. Lanes in the same slice do not reference one another (RFC 9106 §3.4), so the result matches parallel computation.
- Select reference blocks only from address blocks (§3.4.1.2). The memory access order is independent of secrets because the index does not come from block contents.
- Allocate `memoryKiB` KiB at once. The caller supplies only values it can afford, such as the TKA parameter (16 MiB).

Gate criteria follow.

1. BLAKE2b. RFC 7693 Appendix A ("abc") and Appendix E (self-test hash of hashes), the official BLAKE2 KAT (256 each unkeyed and with a 64-byte key, `Vectors/blake2b-kat.json`), output lengths 1, 32, and 64, block boundaries at 0, 1, 127, 128, 129, 255, and 256 bytes, and matching results when splitting input across `update` calls.
2. Argon2i. RFC 9106 §5.2 vectors (secret key and associated data through an internal `@testable` function) and H0, 75 Go `argon2.Key` reference values (`Vectors/argon2i-go.json`, generated by `Tools/interop/cmd/argon2fixtures`, with passes 1~4, memory 8~16384 KiB and values that are not multiples of 4p, parallelism 1, 2, 4, and 8, output 4~1024 bytes, and secret and salt lengths 0~200), and `DisablementKDF(0xa5 × 32)` with the TKA parameters. Supplying the tool path in `SWIFTAIL_ARGON2FIXTURES` generates fresh values for comparison.
3. Errors for out-of-range parameters.

## Independent Review Results (2026-11-15, Ed25519 Verification, BLAKE2b, and Argon2i)

Another session compared the three components against the original Go code line by line and generated new inputs using seeds and input types different from those in the authoring session's reference values. **It found no verdicts that differed from Go** (58,854 new inputs. Scalar reduction 6,131, field operations 10,955 pairs, point decoding and operations 3,892, double-scalar multiplication 2,000, verification 6,649, BLAKE2b 29,120, Argon2i 107. Includes 1,556 existing Ed25519 reference values). The 2,350 inputs of new types were saved in `Tests/SwiftailCryptoTests/Vectors/crypto-review-go.json` (a temporary Go program generated them, so they cannot be regenerated with a command in this repository).

Decisions follow.

- Out-of-range arguments to `Argon2i.derive` yield `CryptoError.invalidLength` without a separate error case. The only call site uses TKA's constant arguments, so it has no use for distinguishing error kinds.
- Argon2i leaves its working memory and intermediate values without clearing them to 0 on completion. The input (the disablement secret) comes from the control server, and successful verification uses it to disable the lock, ending its use. Assignments of 0 without unsafe pointers can be optimized away, so erasure cannot be guaranteed in any case.
- There is no upper limit on `memoryKiB` (as in Go). The caller supplies only values it can afford.
- Go accepts 1~3-byte outputs and memory below `8p`, and Swift rejects them (RFC 9106 ranges). This does not affect the TKA parameters.

Unverified items are a ZIP-215 signature that returns true using a noncanonical encoding of a large-order point (it cannot be constructed without knowing the discrete logarithm of such a point, and the decoding rules and verification equation were checked separately), and empirical confirmation that Argon2i execution time is independent of the secret (verified by reading the code).
