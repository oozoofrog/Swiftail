# Swiftail 작업 규칙

Swiftail은 Go의 Tailscale 내장 노드(tsnet)를 대체하려는 순수 Swift tailnet 노드 라이브러리다. 기획은 `docs/plan.md`, 프로토콜 정리는 `docs/protocol-notes/`, 모듈 계약은 `docs/contracts/`에 있다.

- 문서·주석·보고는 한국어로 쓴다. 식별자와 프로토콜 용어는 원문 그대로 둔다.
- Swift 6 언어 모드, strict concurrency, 경고 0. 공개 API에는 문서 주석을 단다. 시험은 swift-testing으로 쓴다.
- 라이브러리는 전부 Swift로 쓴다. C·다른 언어 코드나 외부 Swift 패키지를 들이지 않는다(`Tools/`의 Go 시험 도구는 예외).
- 코드는 Swift 개발자의 본보기가 되게 쓴다. 기준은 `docs/plan.md` 5절 "코드 기준"이다: 값 타입 상태 기계와 가장자리 입출력, 타입 있는 오류, 안전하지 않은 도구 금지, 경계에서의 입력 검증, Swift API Design Guidelines, 무엇을·왜를 적는 문서 주석.
- 구현은 최소로 한다. 요청받지 않은 추상화·옵션·래퍼·"나중을 위한" 코드를 만들지 않는다. 검증(시험 벡터, 상호 운용 시험), 경계 입력 검사, 보안은 줄이지 않는다.
- 프로토콜 세부는 기억으로 쓰지 않는다. `Scripts/fetch-reference-sources.sh`가 받는 Go 소스나 `docs/protocol-notes/`에서 확인한다. Go 코드를 옮겨 적으면 파일 머리에 출처와 라이선스를 남긴다.
- 빌드·시험은 `eyebuild swift <용도> -- test`처럼 `eyebuild`로 돌린다(산출물은 `eyebuild dir <용도>`가 알려 주는 빌드 디스크 아래). `.build`를 저장소 안에 만들지 않는다. 끝나면 자기가 만든 용도 폴더를 `eyebuild rm <용도>`로 지운다.
- 키, 인증 키, 실제 tailnet 이름, 기기 이름, 실명, 개인 메일, `/Users/...` 경로를 코드·문서·시험·로그·보고에 넣지 않는다. 예시는 `tail0001`, `rd-mac-1a2b3c4d`, `100.64.0.1` 같은 가짜 값을 쓴다.
- 비밀 값 비교는 상수 시간으로 한다. 비밀을 로그에 남기지 않는다.
- 맡은 파일 범위 밖은 고치지 않는다. 고쳐야 할 것이 보이면 보고에 적는다.
- 저장소는 GitHub에 공개돼 있다. 커밋한 것은 다음 push에 공개된다고 보고 쓴다. 이 저장소 옆의 `../remotedebug`(첫 사용처 RemoteDebug의 저장소)는 읽기만 한다.
- The lead session may tag and push PATCH releases once the [release conditions](docs/releasing.md) hold. MINOR and 1.0 releases, any action on an existing tag, other pushes, and repository settings changes require the owner's instruction and may only be performed by the lead. Other sessions never tag or push.
- 확인하지 못한 것과 실패한 시험은 출력과 함께 그대로 보고한다.
- `_context/` 아래 파일(인계 문서)은 만들거나 고치지 않는다. 총괄만 쓴다.
