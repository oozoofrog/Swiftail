# TKA 시험 자료

Go 기준값(`Tools/interop`의 `tkafixtures`)과 노트 8.1의 실행 기록에서 온 자료를 둔다. 파일마다 출처를 여기에 적는다.

## `tka-fixtures.json` (`tkafixtures`)

출처: `Tools/interop/cmd/tkafixtures`가 `tailscale.com` v1.104.6의 `tka` 공개 API(피어 집합만 `ipn/ipnlocal`의 `tkaFilterNetmapLocked`를 overlay로)로 낸 Go 판정. Go 1.27.3. 키는 `SHA-256("swiftail-fixtures/tka/<역할>/<번호>")`에서 나온 공개된 시험 전용 값이고, `bootstrap/go-test-genesis`와 `authKeys`의 `go-test-string`은 Go 시험 파일(`tka/aum_test.go:181`, `tka/sig_test.go:479`)의 값이다. JSON의 모양과 시나리오 목록은 `Tools/interop/README.md`의 "TKA 기준 자료 생성" 절에 있다.

다시 뽑기(저장소 루트에서, 환경 변수는 그 절과 같다):

```sh
fixture_tool="$(sh Scripts/build-interop-tools.sh tkafixtures)"
(cd Tools/interop && "$fixture_tool" ../../Tests/SwiftailTKATests/Fixtures)
(cd Tools/interop && go test -count=1 ./cmd/tkafixtures)
```
