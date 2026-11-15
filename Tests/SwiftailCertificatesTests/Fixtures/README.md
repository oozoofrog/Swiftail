# 인증서 시험 자료

`acme-fixtures.json`은 Swift 소스를 읽거나 실행하지 않고 `tailscale.com/tempfork/acme`와 Go 표준 라이브러리로 만든 기준 자료다. 만드는 법과 검증 명령 전체 규약은 `Tools/interop/README.md`의 **ACME 기준 자료 생성 (`acmefixtures`)** 절에 있다.

머리는 `reference`(`go`, `tailscale` 버전)와 `caseCount: 22`다. 모든 hex는 소문자이며 base64url은 채움이 없다.

| 배열 | 수 | 필드와 뜻 |
| --- | --- | --- |
| `keys` | 3 | `id`로 다른 배열에서 참조한다. `testOnly: true`, 공개 씨앗 `seed`, 32바이트 개인 스칼라 `scalarHex`, 공개 좌표 JWK `publicKey`, RFC 7638 정규형 문자열 `jwkJSON`, `thumbprint`, `sec1PEM`, `pkcs8PEM` |
| `challenges` | 9 | `keyID`, `token`, `keyAuthorization`, `dns01TXT`. 각 키에 token 세 개 |
| `jws` | 6 | `keyID`, `mode`(`jwk`·`kid`), `protectedJSON`, `payloadJSON`, `signingInput`, `verifiedExample`(`protected`, `payload`, `signature`). 각 키에 계정 등록과 POST-as-GET 예 하나씩 |
| `csrs` | 4 | `name`, `keyID`, `domain`, 전체 DER `derHex`, 서명 입력 DER `certificationRequestInfoHex`, CN 문자열 태그 `cnStringTag`(19) |

`keys`의 `account`, `leading-zero-x`, `leading-zero-y`는 각각 일반 키, X 좌표 첫 바이트 0, Y 좌표 첫 바이트 0 사례다. 좌표는 선행 0을 포함해 각각 32바이트다. **개인 키는 공개된 고정 씨앗에서 만든 시험 전용 값으로 운영에 쓰면 안 된다.** 실제 tailnet·기기·인증 키는 없다.

CSR은 `account` 키로 `a.ts.net`, `rd-mac-1a2b3c4d.tail0001.ts.net`, 63자 레이블, 전체 253자 이름을 쓴다. 마지막 사례는 DER 길이 경계 시험용이다. `_acme-challenge.`를 붙이면 DNS 이름 한도를 넘으므로 실제 DNS-01 발급 대상 예시가 아니다. 템플릿은 CN 하나, 같은 이름의 SAN 하나, `ExtraExtensions: nil`이다.

JWK 문자열·지문·키 인가·TXT는 바이트로 견준다. CSR Info도 같은 키·extensionRequest의 SAN 하나·PrintableString·DER 규칙을 택한 경우 바이트로 견준다. JWS JSON은 복호화한 의미와 실제 `protected + "." + payload`의 서명 검증으로 견준다. POST-as-GET의 `payloadJSON`과 JWS `payload`는 둘 다 빈 문자열이다.

서명 예제는 Go RFC 6979로 재현 가능하게 만들고 생성 때 Go로 검증한다. **서명 바이트는 Swift 대조의 기준이 아니다.** Swift가 만든 JWS는 `verify-jws`, CSR은 `verify-csr`, SEC1·PKCS#8 키는 `parse-key`로 검증한다. `Tests/**/*.swift`와 패키지의 리소스 등록은 이 도구 작업에 포함하지 않는다.
