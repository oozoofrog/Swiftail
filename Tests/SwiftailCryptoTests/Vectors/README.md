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

## BLAKE2b·Argon2i 벡터

| 파일 | 출처 | 생성 명령 | 라이선스 |
| --- | --- | --- | --- |
| `blake2b-kat.json` | [BLAKE2 공식 testvectors/blake2-kat.json](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json), BLAKE2b 키 없음 256개와 키 64바이트 256개 | 아래 추출 명령 | CC0-1.0 또는 OpenSSL 또는 Apache-2.0 |
| `argon2i-go.json` | `golang.org/x/crypto` v0.58.0 `argon2.Key`, `tailscale.com` v1.104.6 `tka.DisablementKDF`, 75개 | `"$(sh Scripts/build-interop-tools.sh argon2fixtures)" > Tests/SwiftailCryptoTests/Vectors/argon2i-go.json` | BSD-3-Clause |

```sh
curl -fsSL https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json | python3 -c 'import json,sys; x=json.load(sys.stdin); y=[dict(kind="blake2b",key=v["key"],input=v["in"],output=v["out"]) for v in x if v["hash"]=="blake2b" and v["key"] in ("", bytes(range(64)).hex())]; assert len(y)==512; json.dump(y,sys.stdout,indent=2); print()' > Tests/SwiftailCryptoTests/Vectors/blake2b-kat.json
```
