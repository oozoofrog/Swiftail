/// 피어 사이의 직접 경로를 찾고 유지하는 상태 기계. 소켓·시계·actor를 갖지 않는다.
///
/// 아직 자리만 있다. 상태와 진입점은 M4 단위 4가 채운다(`docs/contracts/SwiftailMagicsock.md` "공개 API").
/// 함께 쓰는 입력 타입(`Peer`, `Region`, `Endpoint`)은 `Magicsock+Inputs.swift`에 있다.
public struct Magicsock: Sendable {}
