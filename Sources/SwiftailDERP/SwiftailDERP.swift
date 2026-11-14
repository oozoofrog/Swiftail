// SwiftailDERP: DERP 중계 서버 하나와의 연결.
//
// 프레임 해석과 핸드셰이크는 입출력 없는 값 타입 상태 기계(`DERPConnection`)가 맡고, TLS 소켓·시계·재연결은 그것을
// 감싼 actor(`DERPClient`)가 맡는다. `SwiftailControl`에는 의존하지 않는다. 계약은 `docs/contracts/SwiftailDERP.md`.
// 이 파일은 타깃 자리이며 구현이 들어오면 지운다.
