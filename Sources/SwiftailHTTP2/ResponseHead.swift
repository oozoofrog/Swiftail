/// A validated response head.
///
/// Parses the response's first header block once. Exactly one `:status` pseudo-header is required, with a three-digit value
/// before the regular headers. All other pseudo-headers are forbidden (RFC 9113 §8.1.1, §8.3.2). Regular
/// headers must follow `HeaderValidation`, and `content-length` must be a single decimal number (§8.1.1).
/// A violation is a stream error.
struct ResponseHead: Equatable {
    var status: Int
    /// The fields excluding pseudo-headers.
    var headers: [HeaderField]
    /// The body length declared in `content-length`, or `nil` if the header is absent.
    var contentLength: Int?

    /// Returns `nil` if the fields violate the specification.
    init?(validating fields: [HeaderField]) {
        var status: Int?
        var contentLength: Int?
        var headers: [HeaderField] = []
        for field in fields {
            if field.name.utf8.first == UInt8(ascii: ":") {
                // Only the `:status` pseudo-header is allowed, and it must precede regular headers.
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

    /// The numeric value of a nonempty string of ASCII digits. Returns `nil` for a sign, whitespace, or a value outside `Int` range.
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
