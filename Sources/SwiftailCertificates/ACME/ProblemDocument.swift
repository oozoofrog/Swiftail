import Foundation

/// ACME 오류의 문제 문서(RFC 7807 3.1, RFC 8555 6.7). 오류 응답의 본문, 주문의 `error`, challenge의 `error`가 이 형식이다.
///
/// 오류 응답에 문제 문서를 붙이는 것은 SHOULD일 뿐이고(RFC 8555 6.7), `type`은 ACME URN만이 아니라 서버 고유 URI나
/// `about:blank`일 수 있다(RFC 7807 3.1·4.2). 그래서 읽기는 실패하지 않는다: 본문이 JSON 객체가 아니거나 `type`이
/// 없거나 문자열이 아니면 `type`은 빈 문자열이다. RFC 7807의 기본값 `about:blank`로 채우지 않는다(계약 동작 C12).
///
/// `detail`·`title`·`instance`·`subproblems`는 읽지 않는다: 식별자가 들어 있을 수 있어 실패 값과 로그에 싣지 않는다
/// (계약 동작 K2). `type`만으로 종류를 가린다.
struct ProblemDocument: Sendable, Equatable, Decodable {
    /// `type` 전체 문자열을 UTF-8 문자 경계에서 256바이트로 자른 것. 없으면 빈 문자열.
    let type: String

    /// 문제 문서의 `type` 한도(계약 한도 표).
    static let maximumTypeByteCount = 256

    /// 따로 다루는 ACME 오류 종류(RFC 8555 6.7). `type`이 `urn:ietf:params:acme:error:` + 이름과 **정확히 같을 때만**
    /// 그 종류로 본다. 접미사만 같은 서버 고유 URI는 일반 오류다.
    enum Kind: String, Sendable {
        case badNonce, accountDoesNotExist, rateLimited, orderNotReady
    }

    /// 따로 다루는 종류이면 그 종류.
    var kind: Kind? {
        let prefix = "urn:ietf:params:acme:error:"
        guard type.hasPrefix(prefix) else { return nil }
        return Kind(rawValue: String(type.dropFirst(prefix.count)))
    }

    init(type: String) {
        self.type = Self.truncated(type)
    }

    /// HTTP 오류 응답의 본문을 읽는다. 크기 한도를 넘거나 JSON 객체가 아니면 `type`이 빈 문서다.
    init(responseBody body: [UInt8]) {
        guard body.count <= ACMEInputRules.maximumJSONByteCount,
              let document = try? JSONDecoder().decode(ProblemDocument.self, from: Data(body))
        else {
            self.init(type: "")
            return
        }
        self = document
    }

    init(from decoder: any Decoder) throws {
        // 객체가 아니거나 `type`이 문자열이 아니어도 실패하지 않는다(위 설명).
        let container = try? decoder.container(keyedBy: CodingKeys.self)
        let type = (try? container?.decodeIfPresent(String.self, forKey: .type)) ?? nil
        self.init(type: type ?? "")
    }

    private enum CodingKeys: String, CodingKey {
        case type
    }

    /// UTF-8 문자 경계에서 256바이트 이하로 자른다.
    private static func truncated(_ text: String) -> String {
        guard text.utf8.count > maximumTypeByteCount else { return text }
        var result = String.UnicodeScalarView()
        var byteCount = 0
        for scalar in text.unicodeScalars {
            let size = String(scalar).utf8.count
            guard byteCount + size <= maximumTypeByteCount else { break }
            result.append(scalar)
            byteCount += size
        }
        return String(result)
    }
}
