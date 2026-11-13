/// 검증을 마친 응답 머리.
///
/// 응답의 첫 헤더 블록은 한 번 여기서 해석한다. 의사 헤더 `:status`는 정확히 하나, 세 자리 숫자여야
/// 하고, 일반 헤더보다 앞에 와야 하며, 다른 의사 헤더는 없어야 한다(RFC 9113 §8.1.1, §8.3.2). 일반
/// 헤더는 `HeaderValidation`의 규칙을 따라야 하고, `content-length`는 하나뿐인 십진수여야 한다(§8.1.1).
/// 이를 어기면 스트림 오류다.
struct ResponseHead: Equatable {
    var status: Int
    /// 의사 헤더를 뺀 나머지.
    var headers: [HeaderField]
    /// `content-length`가 알린 본문 길이. 헤더가 없으면 `nil`.
    var contentLength: Int?

    /// 규격에 맞지 않으면 `nil`.
    init?(validating fields: [HeaderField]) {
        var status: Int?
        var contentLength: Int?
        var headers: [HeaderField] = []
        for field in fields {
            if field.name.utf8.first == UInt8(ascii: ":") {
                // 의사 헤더는 `:status` 하나만, 일반 헤더 앞에서만 나온다.
                guard field.name == ":status", status == nil, headers.isEmpty, let code = Self.statusCode(field.value) else { return nil }
                status = code
                continue
            }
            guard HeaderValidation.isValid(field) else { return nil }
            if field.name == "content-length" {
                guard contentLength == nil, let length = Self.decimal(field.value) else { return nil }
                contentLength = length
            }
            headers.append(field)
        }
        guard let status else { return nil }
        self.status = status
        self.headers = headers
        self.contentLength = contentLength
    }

    private static func statusCode(_ value: String) -> Int? {
        value.utf8.count == 3 ? decimal(value) : nil
    }

    /// ASCII 숫자만으로 이뤄진 비어 있지 않은 문자열의 값. 부호·공백이 있거나 `Int`를 넘으면 `nil`.
    private static func decimal(_ value: String) -> Int? {
        let digits = Array(value.utf8)
        guard !digits.isEmpty, digits.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }) else { return nil }
        var result = 0
        for digit in digits {
            let (shifted, shiftOverflow) = result.multipliedReportingOverflow(by: 10)
            let (sum, sumOverflow) = shifted.addingReportingOverflow(Int(digit - UInt8(ascii: "0")))
            guard !shiftOverflow, !sumOverflow else { return nil }
            result = sum
        }
        return result
    }
}
