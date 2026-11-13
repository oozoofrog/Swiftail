/// 헤더 필드 하나(이름과 값).
///
/// HTTP/2는 헤더 이름을 소문자로만 허용한다(RFC 9113 §8.2.1). 요청을 보낼 때는 `startRequest`가
/// 이를 확인하고, 받은 응답에서는 대문자가 섞인 이름을 잘못된 응답으로 본다.
public struct HeaderField: Sendable, Equatable {
    /// 소문자 이름. 의사 헤더는 `:`로 시작한다.
    public var name: String
    public var value: String

    public init(_ name: String, _ value: String) {
        self.name = name
        self.value = value
    }
}
