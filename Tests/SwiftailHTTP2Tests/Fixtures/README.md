# 시험 자료

파일마다 출처(문서·절, 또는 생성 도구와 명령)와 라이선스를 적는다.

| 파일 | 출처 | 생성 명령 | 라이선스 |
| --- | --- | --- | --- |
| `hpack.json` | Go 1.27.3, `golang.org/x/net/http2/hpack` v0.60.0 Encoder | 아래 명령 | 기준 구현 BSD-3-Clause, 시험용 생성 자료 |

저장소 루트에서 실행한다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go run ./cmd/h2server -hpack-fixtures ../../Tests/SwiftailHTTP2Tests/Fixtures/hpack.json)
```

2연결·10블록이다. 연결마다 별도 HPACK 해독기를 만들고 `blocks` 순서대로 동적 표를 유지한다. 각 블록은 `hex`와 기대 `headers`(`name`, `value`, `sensitive`)를 가진다. 허용 최대 표 크기는 4096이다. 상세 형식은 [시험 도구 README](../../../Tools/interop/README.md)의 HPACK 절을 따른다.

기준 `http2/hpack/encode.go` SHA-256: `b39a13dcfd94e03231ab39fe0cfdde3695a6674a481575385237f34dc669d846`.
