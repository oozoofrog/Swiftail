# 프로토콜 노트

Swiftail 구현에 필요한 수준으로 각 프로토콜을 정리한 문서다. 기억이 아니라 소스에서 확인한 내용만 적는다.

## 기준 소스

| 모듈 | 버전 | 라이선스 |
| --- | --- | --- |
| `tailscale.com` | v1.104.6 (CapabilityVersion 148) | BSD-3-Clause |
| `github.com/tailscale/wireguard-go` | v0.0.0-20261106233718-9e0ab45c16ca | MIT |

`Scripts/fetch-reference-sources.sh`가 소스를 내려받고 루트 경로를 출력한다. 노트의 출처는 모듈 루트 기준 상대 경로와 줄 번호로 적는다(예: `tailscale.com/control/controlbase/handshake.go:120`, `wireguard-go/device/noise-protocol.go:60`).

## 노트 목록과 검증 상태

검증은 작성한 세션과 다른 세션이 Go 소스와 대조하는 것을 말한다. 해당 마일스톤을 시작하기 전에 검증을 끝낸다.

| 노트 | 쓰는 마일스톤 | 작성 | 검증 |
| --- | --- | --- | --- |
| [wireguard.md](wireguard.md) | M1 | Claude Opus 5.5 | GPT-6.1 Sol, 2026-11-14, 수정 31건 |
| [control-transport.md](control-transport.md) | M2 | Claude Opus 5.5 | GPT-6.1 Sol, 2026-11-14, 수정 28건 |
| [control-map.md](control-map.md) | M2 | GPT-6.1 Sol | Claude Opus 5.5, 2026-11-14, 수정 16건 |
| [derp-stun.md](derp-stun.md) | M3 | GPT-6.1 Terra | Claude Opus 5.5, 2026-11-14, 수정 13건 + 빠진 절차 보충 |
| [disco-magicsock.md](disco-magicsock.md) | M4 | GPT-6.1 Sol | Claude Opus 5.5, 2026-11-15, 수정 7건 + M4 절차 보충 |
| [netmap-engine.md](netmap-engine.md) | M3·M5 | Claude Sonnet 5.5 | GPT-6.1 Sol, 2026-11-14, 수정 10건 + M3 절차 보충 |
| [dns-state-node.md](dns-state-node.md) | M5~M7 | Claude Sonnet 5.5 | 미검증 |

## 노트 형식

1. 머리말: 기준 버전, 작성 모델, 검증 상태.
2. 범위: 다루는 것과 다루지 않는 것.
3. 와이어 형식: 메시지마다 바이트 단위 표(오프셋, 길이, 필드, 인코딩·엔디언).
4. 절차와 상태 기계: 번호 매긴 단계. 암호 연산은 입력·출력을 정확히 적는다.
5. 상수와 타이머: 값과 출처 표.
6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분(생략의 근거 포함).
7. 상호 운용 시험에서 확인할 것.
8. 확인하지 못한 것.

모든 사실 문장에 출처(`경로:줄`)를 붙인다. Go 코드를 옮겨 적지 않는다. 상수 값과 짧은 식만 인용한다.
