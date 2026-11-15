// Tailnet Lock의 거절 까닭. 계약 `docs/contracts/SwiftailTailnetLock.md` 2절의 선언이다.

/// TKA 자료를 읽거나 검증하다 거절한 까닭. 판정이 갈린 단계를 구분하고, 키·바이트 같은 내용은 담지 않는다(동작 K5).
package enum TKAError: Error, Sendable, Equatable {
    /// CBOR 항목 수준의 거절(동작 D1).
    case cbor(CBORError)
    /// CBOR로는 읽히지만 구조에 맞지 않는다: 맨 바깥이 맵이 아님, 받지 않는 키 종류, 중복 키, 알려진 필드의 타입·범위,
    /// 잘못된 UTF-8, 체크포인트 `State`의 null이 아닌 `LastAUMHash`(동작 D3~D8).
    case invalidStructure
    /// 정적 검사 실패(`StaticValidate`, 체크포인트 상태 검사. 동작 A1).
    case invalidAUM
    case emptyUpdate
    case missingParent
    case unsigned
    case untrustedSigner
    case invalidSignature
    /// 적용 실패: 부모 해시 불일치, 이미 있는 키, 없는 키, 마지막 키 제거, StateID 불일치, 고친 키의 검사 실패.
    case rejectedUpdate
    case notACheckpoint
    /// 저장된 AUM이 사슬을 이루지 않는다(동작 T3).
    case corruptStore
    case iterationLimit
    case noIntersection
    /// node 키가 인가되지 않는다(동작 S의 어느 단계든).
    case unauthorized
    /// `--TL` 뒤가 동작 R3에 어긋난다.
    case invalidAuthKey
    case signingFailed
    /// 이 계약의 한도(동작 M). 자료 형식에서는 디코딩 전에 보는 바이트 길이다.
    case limitExceeded
}
