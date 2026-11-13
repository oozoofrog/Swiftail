/// HPACK 헤더 블록을 해제하지 못한 이유.
///
/// 헤더 블록 하나라도 해제에 실패하면 압축 상태가 상대와 어긋나므로, 연결은 COMPRESSION_ERROR로
/// 끝난다(RFC 9113 §4.3). 한도를 넘은 경우만 ENHANCE_YOUR_CALM이다.
enum HPACKError: Error, Equatable {
    /// 정수나 문자열이 블록 끝에서 잘렸다.
    case truncated
    /// 정수가 한도를 넘는다(RFC 7541 §5.1은 구현이 한도를 정하라고 한다).
    case integerOverflow
    /// 색인이 0이거나 정적·동적 표 밖이다.
    case invalidIndex
    /// 허프만 부호가 아니거나, EOS가 들어 있거나, 패딩이 규칙에 맞지 않는다(§5.2).
    case invalidHuffman
    /// 문자열이 UTF-8이 아니다. 이 모듈의 헤더는 `String`이다.
    case invalidUTF8
    /// 동적 표 크기 갱신이 필드 표현 뒤에 왔거나, 알린 한도(SETTINGS_HEADER_TABLE_SIZE)보다 크다(§4.2).
    case invalidTableSizeUpdate
    /// 해제한 헤더 목록이 한도를 넘는다.
    case headerListTooLarge
}
