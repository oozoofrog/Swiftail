# 시험 벡터 출처

모든 교차 벡터 키와 입력은 시험 전용 고정 시드에서 생성한다. 16·32바이트 BLAKE2s 결과는 가능한 경우 `x/crypto`와도 대조한다. `x/crypto/blake2s`는 임의 출력 길이와 키 없는 16바이트 출력을 지원하지 않아 `github.com/dchest/blake2s`를 사용한다.

| 파일 | 출처 | 생성 명령 | 라이선스 |
| --- | --- | --- | --- |
| `cross.json` | `golang.org/x/crypto` v0.43.0, `github.com/dchest/blake2s` v1.0.0 | `cd Tools/vectors && GOMODCACHE="$(eyebuild dir m0-vectors)/gomod" eyebuild run m0-vectors -- go run .` | `x/crypto`: BSD-3-Clause; `dchest/blake2s`: CC0-1.0 |
| `blake2s-kat.json` | [BLAKE2 공식 testvectors/blake2-kat.json](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json), 키 있는 BLAKE2s 256개 | 아래 추출 명령 | CC0-1.0 또는 OpenSSL 또는 Apache-2.0 |
| `wireguard-kdf.json` | [wireguard-go device/kdf_test.go](https://git.zx2c4.com/wireguard-go/tree/device/kdf_test.go), 3개 | 원본 KDF 시험 데이터를 수동으로 JSON 전사 | MIT |

공식 KAT 추출 명령(저장소 루트에서 실행):

```sh
curl -fsSL https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json | python3 -c 'import json,sys; x=json.load(sys.stdin); y=[dict(kind="blake2s",key=v["key"],input=v["in"],output=v["out"]) for v in x if v["hash"]=="blake2s" and v["key"]==bytes(range(32)).hex()]; assert len(y)==256; json.dump(y,sys.stdout,indent=2); print()' > Tests/SwiftailCryptoTests/Vectors/blake2s-kat.json
```

지정된 `device/kdf_test.go`에는 별도의 HMAC 기대값이 없으며, HMAC은 교차 벡터로 검증한다.

## Ed25519 검증

| 파일 | 출처 | 생성 명령 | 라이선스 |
| --- | --- | --- | --- |
| `rfc8032-ed25519.json` | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.txt) 7.1 Ed25519 벡터 5개(TEST 1, 2, 3, 1024, SHA(abc)). 공개 키·메시지·서명만 옮겼다 | RFC 원문 텍스트에서 7.1절의 16진 줄을 기계적으로 모았다(길이를 원문의 "length N bytes"와 대조) | IETF Trust(코드 구성 요소, Revised BSD) |
| `ed25519-verify.json` | Go 1.27.3 `crypto/ed25519`와 `github.com/hdevalence/ed25519consensus` v0.2.0의 판정. 입력은 고정 씨앗으로 만들고, 일부러 만든 서명은 `filippo.io/edwards25519` v1.2.0으로 계산한다. 앞의 196개는 `ed25519consensus/zip215_test.go`의 벡터다 | `"$(sh Scripts/build-interop-tools.sh ed25519fixtures)" Tests/SwiftailCryptoTests/Vectors` (`Tools/interop/README.md`의 `ed25519fixtures`) | Go·ed25519consensus·edwards25519: BSD-3-Clause |

## BLAKE2b·Argon2i 벡터

| 파일 | 출처 | 생성 명령 | 라이선스 |
| --- | --- | --- | --- |
| `blake2b-kat.json` | [BLAKE2 공식 testvectors/blake2-kat.json](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json), BLAKE2b 키 없음 256개와 키 64바이트 256개 | 아래 추출 명령 | CC0-1.0 또는 OpenSSL 또는 Apache-2.0 |
| `argon2i-go.json` | `golang.org/x/crypto` v0.58.0 `argon2.Key`, `tailscale.com` v1.104.6 `tka.DisablementKDF`, 75개 | `"$(sh Scripts/build-interop-tools.sh argon2fixtures)" > Tests/SwiftailCryptoTests/Vectors/argon2i-go.json` | BSD-3-Clause |

```sh
curl -fsSL https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json | python3 -c 'import json,sys; x=json.load(sys.stdin); y=[dict(kind="blake2b",key=v["key"],input=v["in"],output=v["out"]) for v in x if v["hash"]=="blake2b" and v["key"] in ("", bytes(range(64)).hex())]; assert len(y)==512; json.dump(y,sys.stdout,indent=2); print()' > Tests/SwiftailCryptoTests/Vectors/blake2b-kat.json
```

`crypto-review-go.json`: 독립 검토에서 뽑은 Go 1.27.3·`filippo.io/edwards25519` v1.2.0·`ed25519consensus` v0.2.0·`golang.org/x/crypto` v0.58.0(`argon2`·`blake2b`)의 출력(스칼라 환원·필드 연산·점 해독·두 검증 규칙·BLAKE2b·Argon2i, 종류는 `CryptoReviewTests.swift` 머리). 저장소 밖의 임시 Go 프로그램이 씨앗 `SHA-256("swiftail-crypto-review/2")`의 ChaCha8로 만든 입력에서 고른 것이라 이 저장소의 명령으로는 다시 만들지 않는다. 라이선스: BSD-3-Clause.
