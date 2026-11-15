// CBOR(RFC 8949)의 자료 항목 가운데 TKA가 다루는 모양. 노트 `docs/protocol-notes/tailnet-lock.md` 3.1·6.2.

/// 디코딩한 CBOR 자료 항목. TKA 구조가 쓰는 종류와, 모르는 필드를 건너뛰는 데 필요한 나머지다.
///
/// 정수는 받은 인코딩 길이를 잊는다(`18 01`과 `01`은 같은 `.unsigned(1)`). 맵은 받은 순서와
/// 중복을 그대로 쥔다: 중복 키를 거절할지는 그 맵이 구조의 맵인지 모르는 필드의 값인지에 달려 있어
/// 구조를 읽는 쪽이 정한다(계약 동작 D4).
package enum CBORValue: Sendable, Equatable {
    case unsigned(UInt64)
    /// 음의 정수 `-1 - n`. 모르는 필드의 키와 값으로만 나타난다.
    case negative(UInt64)
    case bytes([UInt8])
    /// 텍스트의 바이트. 여기서는 UTF-8을 검사하지 않는다(모르는 필드의 값은 잘못된 UTF-8이어도 건너뛴다. 동작 D6).
    case text([UInt8])
    case array([CBORValue])
    case map([CBORPair])
    /// null(`f6`)과 undefined(`f7`). Go 디코더는 둘을 같게 다룬다: 알려진 필드에서는 그 필드의 0 값이 되고
    /// 모르는 필드에서는 버린다(`fxamacker/cbor` v2.9.3 `decode.go`의 `nextCBORNil`). 쓸 때는 null이다.
    case null
    /// major 7의 나머지(false·true·단순값·실수). 값을 쥐지 않는다. 알려진 필드에는 올 수 없다.
    case simpleOrFloat
}

/// 맵의 한 쌍.
package struct CBORPair: Sendable, Equatable {
    package var key: CBORValue
    package var value: CBORValue
}
