/// disco 메시지를 열거나 해석하지 못한 이유.
///
/// 어느 것이든 받는 쪽은 아무 응답 없이 그 패킷을 버린다(`docs/protocol-notes/disco-magicsock.md` 3.2 6).
/// `Magicsock`은 `unknownType`을 처리하지 않는 종류(`Drop.unsupportedDisco`)로, 나머지를 열리지 않거나 해석할 수
/// 없는 메시지(`Drop.malformedDisco`)로 알린다(계약 동작 C1).
enum DiscoError: Error, Sendable, Equatable {
    /// 길이나 형식이 노트 3.1·3.3·3.4 표와 다르다. 봉한 패킷이 nonce와 tag를 담기에 짧은 경우를 포함한다.
    case malformed
    /// type이 `0x01`–`0x03`이 아니다. peer relay 종류(`0x04`–`0x09`)도 여기에 든다(M4가 처리하지 않는다).
    case unknownType(UInt8)
    /// secretbox가 열리지 않는다: 키가 다르거나 nonce·tag·암호문이 바뀌었다.
    case authenticationFailed
    /// 상대의 공개 키가 저차수라 공유 키가 0이다.
    case invalidKey
}
