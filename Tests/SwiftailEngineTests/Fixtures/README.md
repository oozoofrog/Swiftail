# Go 패킷 필터 판정 자료

`filter-verdicts.json`은 `tailscale.com` v1.104.6의 실제 `wgengine/filter`로 생성한다.
91개 시나리오(IPv4 46개, IPv6 45개), 2,429개 단계(수신 333개, 송신 2,058개,
규칙 교체 38개)이며 M3의 의도한 차이 표시는 34개다.

재생성 환경·명령·키의 뜻·전체 시나리오 목록은
[interop 도구 설명](../../../Tools/interop/README.md#filterfixtures)을 따른다.
생성 도구는 모든 시나리오를 새 필터로 두 번 실행하고 바이트 단위로 비교한다.
시각·난수·소켓·실제 tailnet과 Swift 구현을 사용하지 않는다.

`GoFilterComparisonTests`는 규칙 원문을 `[FilterRule]`로 해독하고 공개 계약의
`IPPacket`·`PacketFilter`만으로 순서대로 재현한다. Swift 구현이 없는 worktree에서
작성했으므로 이 시험은 아직 컴파일·실행하지 않았다. 병합 뒤 검증해야 한다.

계약 누락을 드러내는 표시 없는 사례도 보존했다. Go는 와이어 프로토콜 0·255를
Unknown으로 버리고, SCTP(132)는 일부 목적 포트 허용과 송신 응답 캐시를 지원한다.
계약의 일반 프로토콜 규칙(번호 일치·전체 포트만 허용)과 UDP만 기록한다는 문구로는
같은 판정이 나오지 않는다. 이는 승인된 M3 차이가 아니므로 `swiftailDiffers`로 숨기지 않는다.

TSMP 표시 단계는 `.tsmp` 해석만 확인한다. `TailnetEngine.receive`의 제어 패킷 소비와
WireGuard 인증·AllowedIPs 검사는 이 필터 대조의 범위 밖이다.
