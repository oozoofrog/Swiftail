/// 검증을 마친 응답 머리.
///
/// 응답의 첫 헤더 블록은 한 번 여기서 해석한다. 의사 헤더 `:status`는 정확히 하나, 세 자리 숫자여야
/// 하고, 일반 헤더보다 앞에 와야 하며, 다른 의사 헤더는 없어야 한다. 이름에 대문자가 있으면 잘못된
/// 응답이다(RFC 9113 §8.1.1, §8.2.1, §8.3.2). 이를 어기면 스트림 오류다.
struct ResponseHead: Equatable {
    var status: Int
    /// 의사 헤더를 뺀 나머지.
    var headers: [HeaderField]

    /// 규격에 맞지 않으면 `nil`.
    init?(validating fields: [HeaderField]) {
        var status: Int?
        var headers: [HeaderField] = []
        for field in fields {
            guard !field.name.utf8.contains(where: { $0 >= 0x41 && $0 <= 0x5a }) else { return nil }
            if field.name.utf8.first == UInt8(ascii: ":") {
                // 의사 헤더는 `:status` 하나만, 일반 헤더 앞에서만 나온다.
                guard field.name == ":status", status == nil, headers.isEmpty, let code = Self.statusCode(field.value) else { return nil }
                status = code
            } else {
                headers.append(field)
            }
        }
        guard let status else { return nil }
        self.status = status
        self.headers = headers
    }

    private static func statusCode(_ value: String) -> Int? {
        let digits = Array(value.utf8)
        guard digits.count == 3, digits.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }) else { return nil }
        return digits.reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) }
    }
}
