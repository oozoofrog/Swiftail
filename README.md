# Swiftail

Swift로 쓴 tailnet 노드 라이브러리. 앱 프로세스와 iOS Network Extension 패킷 터널 안에서 Tailscale 네트워크의 노드로 동작하는 것이 목표다.

**개발 초기 단계이며 아직 tailnet에 접속하지 못한다.** 진행 상황과 단계별 관문은 [docs/plan.md](docs/plan.md)에 있다.

## 보안 고지

- 이 라이브러리는 **보안 감사를 받지 않았다.** 일부 암호 기본기(BLAKE2s, XSalsa20-Poly1305 등)를 직접 구현했고 공개 시험 벡터로만 검증했다.
- Tailscale Inc.가 만들거나 보증하는 제품이 아니다. Tailscale의 프로토콜은 공개 계약이 아니므로 제어 서버의 변경으로 동작이 멈출 수 있다.
- 보호가 필요한 환경에는 공식 Tailscale 클라이언트를 쓴다.

## 요구 사항

- Swift 6, iOS 18 이상, macOS 15 이상
- 전부 Swift. 외부 패키지와 C 코드 없음(CryptoKit, Network, Foundation만 사용)

## 시험

```sh
swift test
```

상호 운용 시험은 Go(1.27 이상)가 필요하다. 방법은 마일스톤 M1부터 `docs/plan.md`에 적는다.
