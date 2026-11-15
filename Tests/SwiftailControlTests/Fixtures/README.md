# 시험 자료

파일마다 출처(문서·절, 또는 생성 도구와 명령)와 라이선스를 적는다.

| 파일 | 출처 | 생성 명령 | 라이선스 |
| --- | --- | --- | --- |
| `map-sessions.json` | `tailscale.com` v1.104.6 실제 `control/controlclient/map.go`의 mapSession, Go 1.27.3 | 아래 명령 | 기준 구현 BSD-3-Clause, 시험용 생성 자료 |
| `requests.json` | 같은 버전의 `tailcfg.RegisterRequest`·`MapRequest`를 `encoding/json.Marshal` | 아래 명령 | 기준 구현 BSD-3-Clause, 시험용 생성 자료 |
| `tka-peer-sets.json` | `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`(Go `tka`·`ipnlocal`의 판정, `tkafixtures` 도구)의 `peerSets` 전부와 그것이 가리키는 `authorities`의 `name`·`aums`를 그대로 옮긴 것. 키는 공개된 시험 전용 값이다 | 맨 아래 명령 | 기준 구현 BSD-3-Clause, 시험용 생성 자료 |

저장소 루트에서 실행한다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go run ./cmd/mapfixtures ../../Tests/SwiftailControlTests/Fixtures)
```

10시나리오·73단계, 요청 10사례다. 시나리오마다 세션을 새로 만든다. `response`는 JSON 원문 **문자열**이며 키 생략·null·빈 배열을 보존한다. `netmap`은 이전 단계와 정규화한 상태가 같으면 null이다. 실제 Go mapSession을 호출하기 위해 빌드 폴더의 임시 기준 모듈 복사본에만 `go -overlay`를 얹는다. 적용 로직을 복제하지 않으며 모듈 캐시는 수정하지 않는다. `PeerSeenChange`의 기준 시각은 `2026-01-02T03:04:05.123456789Z`다.

정규화 필드명과 형식, 요청 input의 zero 기본값 규칙, 시나리오별 주의점은 [시험 도구 README](../../../Tools/interop/README.md)의 mapfixtures 절을 따른다. Swift 비교 시 64비트 ID를 부동소수점으로 바꾸지 않는다.

기준 `control/controlclient/map.go` SHA-256: `96aea2fa89b642ea0679e78b50a0133c7780b7ed787792542187a20c76fbee1e`.

`tka-peer-sets.json`은 다른 시험 타깃의 자료를 읽을 수 없어 옮겨 둔 것이다. `tka-fixtures.json`을 다시 만들면 이것도 다시 만든다.

```sh
python3 - <<'PY'
import json
source = json.load(open('Tests/SwiftailTKATests/Fixtures/tka-fixtures.json'))
names = {peerSet['authority'] for peerSet in source['peerSets']}
json.dump({
    'reference': source['reference'],
    'authorities': [{'name': a['name'], 'aums': a['aums']} for a in source['authorities'] if a['name'] in names],
    'peerSets': source['peerSets'],
}, open('Tests/SwiftailControlTests/Fixtures/tka-peer-sets.json', 'w'), indent=2)
PY
```
