# Test vector origins

All cross-check vector keys and inputs are generated from a fixed seed used only for tests. The 16-byte and 32-byte BLAKE2s results are also checked against `x/crypto` where possible. The tests use `github.com/dchest/blake2s` because `x/crypto/blake2s` supports neither arbitrary output lengths nor unkeyed 16-byte output.

| File | Origin | Generation command | License |
| --- | --- | --- | --- |
| `cross.json` | `golang.org/x/crypto` v0.43.0, `github.com/dchest/blake2s` v1.0.0 | `cd Tools/vectors && GOMODCACHE="$(eyebuild dir m0-vectors)/gomod" eyebuild run m0-vectors -- go run .` | `x/crypto`: BSD-3-Clause; `dchest/blake2s`: CC0-1.0 |
| `blake2s-kat.json` | [Official BLAKE2 testvectors/blake2-kat.json](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json), 256 keyed BLAKE2s vectors | Extraction command below | CC0-1.0 or OpenSSL or Apache-2.0 |
| `wireguard-kdf.json` | [wireguard-go device/kdf_test.go](https://git.zx2c4.com/wireguard-go/tree/device/kdf_test.go), 3 vectors | Manually transcribed the original KDF test data to JSON | MIT |

Run this command from the repository root to extract the official KAT vectors.

```sh
curl -fsSL https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json | python3 -c 'import json,sys; x=json.load(sys.stdin); y=[dict(kind="blake2s",key=v["key"],input=v["in"],output=v["out"]) for v in x if v["hash"]=="blake2s" and v["key"]==bytes(range(32)).hex()]; assert len(y)==256; json.dump(y,sys.stdout,indent=2); print()' > Tests/SwiftailCryptoTests/Vectors/blake2s-kat.json
```

The specified `device/kdf_test.go` has no separate HMAC expected values. Cross-check vectors verify HMAC.

## Ed25519 verification

| File | Origin | Generation command | License |
| --- | --- | --- | --- |
| `rfc8032-ed25519.json` | 5 Ed25519 vectors from [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.txt) §7.1 (TEST 1, 2, 3, 1024, SHA(abc)). Only the public keys, messages, and signatures were transcribed | Mechanically collected the base-16 lines from the original RFC text in §7.1 (checking lengths against "length N bytes" in the original) | IETF Trust (code components, Revised BSD) |
| `ed25519-verify.json` | Verdicts from Go 1.27.3 `crypto/ed25519` and `github.com/hdevalence/ed25519consensus` v0.2.0. Inputs use a fixed seed, and deliberately crafted signatures are computed with `filippo.io/edwards25519` v1.2.0. The first 196 are vectors from `ed25519consensus/zip215_test.go` | `"$(sh Scripts/build-interop-tools.sh ed25519fixtures)" Tests/SwiftailCryptoTests/Vectors` (`ed25519fixtures` in `Tools/interop/README.md`) | Go, ed25519consensus, and edwards25519 (BSD-3-Clause) |

## BLAKE2b and Argon2i vectors

| File | Origin | Generation command | License |
| --- | --- | --- | --- |
| `blake2b-kat.json` | [Official BLAKE2 testvectors/blake2-kat.json](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json), 256 unkeyed BLAKE2b vectors and 256 with a 64-byte key | Extraction command below | CC0-1.0 or OpenSSL or Apache-2.0 |
| `argon2i-go.json` | `golang.org/x/crypto` v0.58.0 `argon2.Key`, `tailscale.com` v1.104.6 `tka.DisablementKDF`, 75 vectors | `"$(sh Scripts/build-interop-tools.sh argon2fixtures)" > Tests/SwiftailCryptoTests/Vectors/argon2i-go.json` | BSD-3-Clause |

```sh
curl -fsSL https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json | python3 -c 'import json,sys; x=json.load(sys.stdin); y=[dict(kind="blake2b",key=v["key"],input=v["in"],output=v["out"]) for v in x if v["hash"]=="blake2b" and v["key"] in ("", bytes(range(64)).hex())]; assert len(y)==512; json.dump(y,sys.stdout,indent=2); print()' > Tests/SwiftailCryptoTests/Vectors/blake2b-kat.json
```

`crypto-review-go.json` contains outputs collected during an independent review from Go 1.27.3, `filippo.io/edwards25519` v1.2.0, `ed25519consensus` v0.2.0, and `golang.org/x/crypto` v0.58.0 (`argon2` and `blake2b`). They cover scalar reduction, field arithmetic, point decoding, both verification rules, BLAKE2b, and Argon2i. See the header of `CryptoReviewTests.swift` for the categories. The inputs were selected from those a temporary Go program outside the repository generated using ChaCha8 with seed `SHA-256("swiftail-crypto-review/2")`, so the commands in this repository do not regenerate them. License is BSD-3-Clause.
