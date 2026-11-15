# TKA 시험 자료

Go 기준값(`Tools/interop`의 `tkafixtures`)과 노트 8.1의 실행 기록에서 온 자료를 둔다. 파일마다 출처를 여기에 적는다.

## `cbor-vectors.json`(TL-1)

CBOR 항목 수준의 판정 벡터 63개. 출처는 노트 `docs/protocol-notes/tailnet-lock.md` 8.1의 "디코딩: 받아들임"·"디코딩: 거절" 표와 검증 세션의 "맵 키 종류"·"`Meta` 맵"·"그 밖의 디코딩" 줄, 3.1의 한도(16/17단, 4,096/4,097개, 1,024/1,025쌍)다. `genesis 체크포인트`는 `tailscale.com/tka/aum_test.go:181`(v1.104.7)의 base64를 풀어 16진으로 옮겼다(노트 7.1).

입력 바이트는 노트의 서술에 맞춰 이 단위가 지었다(대개 `{1: 3, 2: null}`인 NoOp AUM에 쌍 하나를 더한 꼴). 노트가 이 바이트 그대로 Go를 돌린 기록은 아니다. TL-5의 `tkafixtures`가 Go로 확정한다.

| 필드 | 뜻 |
| --- | --- |
| `section` | 판정을 옮긴 노트의 절과 표 |
| `cbor` | `CBOR.decode`의 판정. `accept`이거나 `CBORError`의 경우 이름 |
| `aum` | 노트가 적은 Go `AUM` 디코딩(`Unmarshal`)의 판정, `accept`·`reject`. `cbor`가 `accept`인데 `reject`이면 구조 수준(TL-2)의 거절이다. 정적 검사는 포함하지 않는다 |
| `canonical` | 받아들인 값을 정준(맵 키는 인코딩 바이트 사전순, 같은 키는 받은 순서)으로 다시 쓴 바이트. 모르는 필드를 지우지 않은 일반 CBOR 값의 다시 쓰기이고, AUM으로 다시 인코딩한 바이트가 아니다. 음수·단순값·실수가 든 값은 없다 |
| `note` | 판정에 덧붙일 것 |

## `tka-fixtures.json` (`tkafixtures`)

출처: `Tools/interop/cmd/tkafixtures`가 `tailscale.com` v1.104.6의 `tka` 공개 API(피어 집합만 `ipn/ipnlocal`의 `tkaFilterNetmapLocked`를 overlay로)로 낸 Go 판정. Go 1.27.3. 키는 `SHA-256("swiftail-fixtures/tka/<역할>/<번호>")`에서 나온 공개된 시험 전용 값이고, `bootstrap/go-test-genesis`와 `authKeys`의 `go-test-string`은 Go 시험 파일(`tka/aum_test.go:181`, `tka/sig_test.go:479`)의 값이다. JSON의 모양과 시나리오 목록은 `Tools/interop/README.md`의 "TKA 기준 자료 생성" 절에 있다. 판정 523개(`caseCount`) 가운데 60개(`unorderedPeerSets`·`limits`·`padded`·`openedStates`와 다른 배열에 더한 줄)는 TL-5 대조 시험이 계약 5절의 미확정 입력을 확정하려고 더했고, 37개(`reviewChains` 22·`reviewSignatures` 15)는 TL-11a 검토가 더했다. `review*` 배열은 `TKAReviewTests.swift`가, 나머지는 `GoComparisonTests.swift`가 견준다.

다시 뽑기(저장소 루트에서, 환경 변수는 그 절과 같다):

```sh
fixture_tool="$(sh Scripts/build-interop-tools.sh tkafixtures)"
(cd Tools/interop && "$fixture_tool" ../../Tests/SwiftailTKATests/Fixtures)
(cd Tools/interop && go test -count=1 ./cmd/tkafixtures)
# 새로 뽑아 저장본과 견주는 Swift 시험(위 Go 환경 변수를 그대로 둔다)
SWIFTAIL_TKAFIXTURES="$fixture_tool" eyebuild swift tl5 -- test --filter GoComparisonTests
```
