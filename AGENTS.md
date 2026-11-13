# Swiftail 작업 규칙

Swiftail은 Go의 Tailscale 내장 노드(tsnet)를 대체하려는 순수 Swift tailnet 노드 라이브러리다. 기획은 `docs/plan.md`, 프로토콜 정리는 `docs/protocol-notes/`, 모듈 계약은 `docs/contracts/`에 있다.

- 문서·주석·보고는 한국어로 쓴다. 식별자와 프로토콜 용어는 원문 그대로 둔다.
- Swift 6 언어 모드, strict concurrency, 경고 0. 공개 API에는 문서 주석을 단다. 시험은 swift-testing으로 쓴다.
- 구현은 최소로 한다. 요청받지 않은 추상화·옵션·래퍼·"나중을 위한" 코드를 만들지 않는다. 검증(시험 벡터, 상호 운용 시험), 경계 입력 검사, 보안은 줄이지 않는다.
- 프로토콜 세부는 기억으로 쓰지 않는다. `Scripts/fetch-reference-sources.sh`가 받는 Go 소스나 `docs/protocol-notes/`에서 확인한다. Go 코드를 옮겨 적으면 파일 머리에 출처와 라이선스를 남긴다.
- 빌드·시험은 `eyebuild swift <용도> -- test`처럼 `eyebuild`로 돌린다(산출물은 `/Volumes/eyedisk/build` 아래). `.build`를 저장소 안에 만들지 않는다. 끝나면 자기가 만든 용도 폴더를 `eyebuild rm <용도>`로 지운다.
- 키, 인증 키, 실제 tailnet 이름, 기기 이름, 실명, 개인 메일, `/Users/...` 경로를 코드·문서·시험·로그·보고에 넣지 않는다. 예시는 `tail0001`, `rd-mac-1a2b3c4d`, `100.64.0.1` 같은 가짜 값을 쓴다.
- 비밀 값 비교는 상수 시간으로 한다. 비밀을 로그에 남기지 않는다.
- 맡은 파일 범위 밖은 고치지 않는다. 고쳐야 할 것이 보이면 보고에 적는다.
- GitHub 저장소 생성, push, 공개를 하지 않는다. `/Volumes/eyedisk/develop/oozoofrog/remotedebug`는 읽기만 한다.
- 확인하지 못한 것과 실패한 시험은 출력과 함께 그대로 보고한다.
