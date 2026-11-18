import Foundation

/// An ACME `error` problem document (RFC 7807 3.1, RFC 8555 6.7). Error response bodies and order and challenge error fields use this format.
///
/// Including a problem document in an error response is only a SHOULD (RFC 8555 6.7), and `type` can be an ACME URN, a server-specific URI,
/// or `about:blank` (RFC 7807 3.1 and 4.2). Parsing therefore never fails. If the body is not a JSON object or `type` is missing or is not
/// a string, `type` is empty. It does not substitute the RFC 7807 default of `about:blank` (contract behavior C12).
///
/// Skip `detail`, `title`, `instance`, and `subproblems` because they may contain identifiers and must stay out of failure values and logs
/// (contract behavior K2). Classify the error using `type` alone.
struct ProblemDocument: Sendable, Equatable, Decodable {
    /// The full `type` string truncated to 256 bytes at a UTF-8 character boundary, or an empty string if absent.
    let type: String

    /// The limit on the problem document's `type` (contract limits table).
    static let maximumTypeByteCount = 256

    /// The ACME error kinds handled separately (RFC 8555 6.7). A `type` identifies one of these kinds only if it **exactly matches**
    /// `urn:ietf:params:acme:error:` plus the name. A server-specific URI that merely shares the suffix is a general error.
    enum Kind: String, Sendable {
        case badNonce, accountDoesNotExist, rateLimited, orderNotReady
    }

    /// The separately handled kind, if applicable.
    var kind: Kind? {
        let prefix = "urn:ietf:params:acme:error:"
        guard type.hasPrefix(prefix) else { return nil }
        return Kind(rawValue: String(type.dropFirst(prefix.count)))
    }

    init(type: String) {
        self.type = Self.truncated(type)
    }

    /// Reads an HTTP error response body. Returns a document with an empty `type` if the body exceeds the size limit or is not a JSON object.
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
        // Even a non-object body or non-string `type` does not cause parsing to fail (see above).
        let container = try? decoder.container(keyedBy: CodingKeys.self)
        let type = (try? container?.decodeIfPresent(String.self, forKey: .type)) ?? nil
        self.init(type: type ?? "")
    }

    private enum CodingKeys: String, CodingKey {
        case type
    }

    /// Truncates to at most 256 bytes at a UTF-8 character boundary.
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
