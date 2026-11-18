> 이 문서는 한국어 참고용 번역입니다. [영문 원본](../../README.md)을 기준으로 합니다.

# Swiftail

[![CI](https://github.com/oozoofrog/Swiftail/actions/workflows/ci.yml/badge.svg)](https://github.com/oozoofrog/Swiftail/actions/workflows/ci.yml)
[![Swift versions](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Foozoofrog%2FSwiftail%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/oozoofrog/Swiftail)
[![Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Foozoofrog%2FSwiftail%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/oozoofrog/Swiftail)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](../../LICENSE)

Swift로만 작성한 Tailscale tailnet 노드입니다. Swiftail을 쓰면 Go 클라이언트를 내장하지 않고도 앱 프로세스 안에서 tailnet에 가입하거나 iOS Network Extension 패킷 터널을 구동할 수 있습니다.

> **현재 1.0 이전 버전입니다.** 실제 운영 중인 Tailscale 제어 평면에 등록하고 표준 Tailscale 노드와 트래픽을 주고받을 수 있습니다. 공개 API는 아직 바뀔 수 있습니다.
>
> Swiftail은 독립 프로젝트입니다. Tailscale Inc.는 Swiftail을 제작하거나 승인하거나 지원하지 않습니다.

## 지원 기능

| 영역 | 구현된 기능 |
| --- | --- |
| 제어 평면 | Noise (ts2021) 전송 위의 HTTP/2, 등록(인증 키, 대화형 로그인), netmap 스트리밍, 로그아웃 |
| 데이터 평면 | WireGuard (Noise IK, 쿠키, 키 갱신), tailnet 정책을 반영한 패킷 필터, MagicDNS 응답기 |
| 연결 | DERP 릴레이, STUN, disco 경로 탐색, 직접 UDP 경로와 중계 경로 간 전환(직접 경로를 쓸 수 없으면 중계로 전환하고, 직접 경로가 확보되면 직접 연결로 전환) |
| 소켓 | Swift로 작성한 TCP 스택. 프로세스 안에서 tailnet 주소로 `listen` 및 `connect` |
| 터널 | iOS/macOS 패킷 터널 확장용 `utun` 장치 모드 |
| 신원 | `whoIs` (tailnet 주소로 노드와 사용자 조회), Tailnet Lock 서명 검증 |
| TLS | `ts.net` 인증서 발급과 갱신(ACME DNS-01), OS의 TLS 리스너에 연결하는 루프백 브리지 |
| 페어링 | QR 코드나 링크로 앱 간 페어링, 일회용 인증 키 발급 |

아직 구현하지 않은 기능은 서브넷 라우터, 출구 노드, Taildrop, Tailscale SSH, Funnel, Serve입니다.

## 요구 사항

- Swift 6 (언어 모드 6, strict concurrency)
- iOS 18 이상 또는 macOS 15 이상
- 서드파티 패키지와 C 코드를 사용하지 않습니다. 핵심 타깃은 CryptoKit, Network, Foundation을 사용합니다. 선택 제품은 Security(인증서)와 CoreImage(QR 코드)를 추가로 사용합니다.

## 설치

Swiftail은 1.0 이전 버전입니다. MINOR 릴리스에서는 API 호환성이 깨질 수 있으며 PATCH 릴리스는 호환성을 유지합니다. PATCH 업데이트를 받으려면 `Package.swift`에 다음 MINOR 버전 미만을 허용하는 조건으로 패키지를 추가합니다.

```swift
dependencies: [
    .package(url: "https://github.com/oozoofrog/Swiftail.git", .upToNextMinor(from: "0.1.1"))
]
```

| 제품 | 용도 |
| --- | --- |
| `Swiftail` | 노드(`TailnetNode`), 연결, 상태, 이벤트 |
| `SwiftailBase` | `IPAddress`, `IPEndpoint` 등 공용 값 타입 |
| `SwiftailPairing` | 두 앱 간 QR 코드·링크 페어링, 인증 키 발급 |
| `SwiftailCertificates` | `ts.net` TLS 인증서 |
| `SwiftailLoopback` | tailnet 연결을 `127.0.0.1` 리스너로 전달 |

나머지 제품(`SwiftailControl`, `SwiftailWireGuard`, `SwiftailDERP` 등)은 구성 요소입니다. 대부분의 앱은 이 제품들을 직접 임포트하지 않습니다.

## 빠른 시작

다음은 앱 프로세스 안에서 실행하며 자기 tailnet 주소로 들어오는 TCP 연결을 받는 노드입니다.

```swift
import Swiftail

let configuration = NodeConfiguration(
    stateDirectory: stateDirectoryURL,   // must not be writable by other users
    hostname: "my-app",
    authKey: authKey                     // omit to use a stored identity or interactive login
)
let node = try TailnetNode(configuration: configuration, device: .inProcess)

// run() returns when its task is cancelled.
let running = Task { try await node.run() }

// Follow state changes. `.needsLogin(url)` carries the login URL.
Task {
    for await event in node.events {
        if case .stateChanged(let state) = event { print(state) }
    }
}

let listener = try await node.listen(port: 8080)
for await connection in listener {
    Task {
        let peer = await node.whoIs(connection.remoteEndpoint.address)
        while let bytes = try await connection.read() {
            try await connection.write(bytes)
        }
    }
}
```

상대 노드에 연결하려면 `try await node.connect(to: "peer-name", port: 8080)`을 호출합니다.

QR 페어링을 포함한 완전한 macOS 및 iOS 예제 앱은 [`Examples/PairingDemo`](../../Examples/PairingDemo/)에 있습니다.

## 저장소 구성

| 경로 | 내용 |
| --- | --- |
| `Sources/` | 라이브러리 타깃. 프로토콜 로직은 값 타입 상태 기계로 구현하며, 경계의 액터가 소켓과 시계를 관리합니다 |
| `Tests/` | 단위 테스트(swift-testing)와 Go 피어를 상대로 한 상호 운용 테스트 |
| `Examples/PairingDemo/` | macOS 및 iOS 예제 앱(XcodeGen 프로젝트) |
| `Tools/` | Go 테스트 도구(테스트 제어 서버, DERP, 테스트 벡터 생성기). 라이브러리에 포함되지 않습니다 |
| `docs/plan.md` | 범위, 결정 사항, 마일스톤, 검증 관문 |
| `docs/contracts/` | 모듈별 계약(API, 동작, 제한 사항, 테스트, 검토 기록) |
| `docs/protocol-notes/` | Tailscale 소스와 대조해 확인한 프로토콜 노트 |
| `AGENTS.md` | 기여자와 코딩 에이전트의 작업 규칙 |

설계 문서, 계약, 소스 코드 주석은 영어로 작성합니다. 식별자와 프로토콜 용어도 영어로 씁니다. README, 보안 정책, 릴리스 가이드의 한국어 참고본은 [`docs/ko/`](./)에 있습니다.

## 테스트

```sh
swift test
```

상호 운용 테스트에는 Go 1.27.3 이상이 필요합니다. 도구 경로를 설정하지 않으면 해당 테스트를 자동으로 건너뜁니다.

```sh
SWIFTAIL_TAILNET="$(sh Scripts/build-interop-tools.sh tailnet)" \
SWIFTAIL_WGPEER="$(sh Scripts/build-interop-tools.sh)" \
SWIFTAIL_AUTHKEYRECORDER="$(sh Scripts/build-interop-tools.sh authkeyrecorder)" \
swift test --filter "SwiftailInteropTests|SwiftailWireGuardInteropTests|SwiftailDERPInteropTests"
```

이 테스트는 테스트 제어 서버, DERP 릴레이, Go tsnet 피어를 로컬에서 실행합니다. 실행 시간은 몇 분이며 운영 서버에는 접속하지 않습니다.

## 보안

의심되는 취약점을 비공개로 보고하는 방법은 [보안 정책](../../SECURITY.md)을 참고하세요.

Swiftail은 **독립적인 보안 전문가가 직접 수행하는 감사**를 받은 적이 없습니다.

- **AI를 활용한 검토(2026-11-17).** Claude Mythos 5.2로 소스 전체를 세 영역에 걸쳐 검토했습니다. 앱에 노출되는 계층(페어링, 루프백 브리지, 인증서, 상태 파일), 암호 기술과 인증된 채널(WireGuard, 제어 프로토콜, Tailnet Lock), 데이터 평면(경로 탐색, DERP, TCP 스택, 패킷 필터, DNS)입니다. 의심되는 문제는 테스트로 재현했습니다. 치명적이거나 심각도가 높은 문제는 발견되지 않았고, 중간 등급 3건과 낮은 등급 11건이 발견됐습니다. 모두 수정했고 같은 모델로 수정 사항을 두 차례 다시 검토했습니다. 수용한 제한 사항은 `docs/contracts/` 아래의 계약에 기록했습니다.
- **이 검토가 보안을 보증하지는 않습니다.** 독립적인 감사를 대신할 수 없습니다.
- **직접 구현한 암호 기술.** 일부 암호 기본 요소(BLAKE2s, BLAKE2b, XSalsa20-Poly1305, Argon2i, Ed25519 검증)는 Swift로 구현했으며, 공개 테스트 벡터와 Go에서 얻은 대조용 벡터로 검증했습니다. 키 데이터는 해제할 때 0으로 지우지 않습니다.
- **비공식 프로토콜.** Tailscale 제어 프로토콜은 공개된 계약이 아닙니다. 서버가 바뀌면 이 라이브러리가 동작하지 않을 수 있습니다.
- 보안 보장이 필요한 환경에서는 공식 Tailscale 클라이언트를 사용하세요.

## 코딩 에이전트 안내

- 변경하기 전에 [`AGENTS.md`](../../AGENTS.md)를 읽으세요. 언어, 동시성, 의존성, 개인정보 보호, 빌드 규칙을 정리한 문서입니다.
- 동작과 제한 사항의 기준은 `docs/contracts/`에 있는 각 모듈의 계약입니다. 코드를 바꿀 때 계약도 함께 바꾸세요.
- 프로토콜 세부 사항은 기억에 의존하지 마세요. `docs/protocol-notes/` 또는 `Scripts/fetch-reference-sources.sh`가 가져오는 Tailscale 소스를 확인하세요.
- 키, 인증 키, 실제 tailnet 이름이나 기기 이름, 실명, 이메일 주소, 로컬 경로를 커밋하지 마세요. `tail0001`, `rd-mac-1a2b3c4d`, `100.64.0.1` 같은 예시 값을 쓰세요.
- 단위 테스트를 갖추고, 변경의 영향을 받는 상호 운용 테스트를 통과하며, 경고 없이 빌드되면 변경이 완료된 것입니다.

## 라이선스

BSD-3-Clause입니다. [`LICENSE`](../../LICENSE)를 참고하세요. 다른 프로젝트의 코드를 옮겨 쓰거나 수정한 파일은 머리말에 출처와 라이선스를 적어 두었습니다. 라이선스 전문은 [`THIRD-PARTY-NOTICES.md`](../../THIRD-PARTY-NOTICES.md)에 있습니다.

Tailscale과 WireGuard는 각 소유자의 상표입니다.
