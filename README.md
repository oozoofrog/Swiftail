# Swiftail

Swift로 쓴 tailnet 노드 라이브러리. 앱 프로세스와 iOS Network Extension 패킷 터널 안에서 Tailscale 네트워크의 노드로 동작하는 것이 목표다.

실제 tailnet에 등록해 통신한다: 제어 프로토콜, WireGuard, DERP 중계, 직접 경로 탐색, Swift로 쓴 TCP 스택, Tailnet Lock, ts.net 인증서 발급, 앱끼리의 QR·링크 페어링. 공개 API는 아직 바뀔 수 있다. 진행 상황과 단계별 관문은 [docs/plan.md](docs/plan.md), 모듈별 계약은 [docs/contracts/](docs/contracts/)에 있다. Mac과 iPhone에서 돌려 보는 샘플 앱은 [Examples/PairingDemo](Examples/PairingDemo/)에 있다.

## 보안 고지

- **사람 전문가의 독립 보안 감사는 받지 않았다.**
- 2026-11-17에 AI 모델(Claude Mythos 5.2)로 전체 소스의 보안 검토를 했다. 세 범위(앱과 맞닿는 층, 암호·WireGuard·제어 프로토콜·Tailnet Lock, 데이터면)를 읽고 재현 시험으로 확인했다. 치명·높음 등급은 없었고 중간 3건과 낮음 11건이 나왔다. 모두 고친 뒤 같은 모델로 두 번 다시 확인했다. 받아들인 한계는 각 계약 문서에 적었다. 이 검토는 결함이 없다는 보증이 아니다.
- 일부 암호 기본기(BLAKE2s, XSalsa20-Poly1305, Ed25519 서명 검증 등)를 직접 구현했고 공개 시험 벡터와 Go 구현의 교차 벡터로 검증했다.
- Tailscale Inc.가 만들거나 보증하는 제품이 아니다. Tailscale의 프로토콜은 공개 계약이 아니므로 제어 서버의 변경으로 동작이 멈출 수 있다.
- 보호가 필요한 환경에는 공식 Tailscale 클라이언트를 쓴다.

## 요구 사항

- Swift 6, iOS 18 이상, macOS 15 이상
- 전부 Swift. 외부 패키지와 C 코드 없음. 코어는 CryptoKit, Network, Foundation만 쓰고, 선택 제품이 Security(인증서)와 CoreImage(QR)를 더 쓴다

## 시험

```sh
swift test
```

wireguard-go와의 상호 운용 시험은 Go(1.27 이상)가 필요하고 실제 시간으로 2분 남짓 걸린다. `SWIFTAIL_WGPEER`가 없으면 건너뛴다.

```sh
SWIFTAIL_WGPEER="$(sh Scripts/build-interop-tools.sh)" swift test --filter SwiftailWireGuardInteropTests
```

## 라이선스

BSD-3-Clause(`LICENSE`). 다른 프로젝트의 코드를 옮겨 적은 파일은 머리말에 출처와 라이선스를 적었고, 그 원문은 `THIRD-PARTY-NOTICES.md`에 모았다.
