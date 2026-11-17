import Foundation

/// 제안의 링크: `<base>#v=1&h=<host>&p=<port>&s=<비밀>&e=<만료>[&k=<인증 키>]`(계약 동작 O1~O4).
///
/// 값은 전부 조각(`#` 뒤)에 있다. 조각은 서버 요청과 Referer에 실리지 않는다. 값의 글자는 모두 URL에서 인코딩이 필요 없는
/// 것이라, 읽는 쪽은 `%`를 풀지 않고 바이트 그대로 본다. 같은 제안이 두 가지 글로 읽히지 않는다.
extension PairingOffer {
    /// 조각의 한도(동작 O2).
    static let maximumFragmentLength = 2048

    /// 조각의 키. 이 여섯 개만 받는다.
    private enum Key: String {
        case version = "v", host = "h", port = "p", secret = "s", expiry = "e", authKey = "k"
    }

    /// 받은 URL(`url.absoluteString`)이나 QR에서 읽은 문자열을 제안으로 읽는다.
    ///
    /// 첫 `#` 뒤만 본다. 그 앞(`base`)은 보지 않으므로, 어느 URL이 자기 앱의 것인지는 앱이 가린다. 만료가 지난 제안도
    /// 읽힌다(동작 O4). 링크는 어디서든 올 수 있으니, 링크로 시작한 페어링은 짝을 맺기 전에 `host`를 보여 주고 사용자에게
    /// 묻는다.
    ///
    /// - Throws: 읽지 못한 까닭. 값은 싣지 않는다(동작 O3).
    public init(link: String) throws(PairingOfferError) {
        let bytes = Array(link.utf8)
        guard let hash = bytes.firstIndex(of: UInt8(ascii: "#")) else { throw .notAnOffer }
        let fragment = bytes[(hash + 1)...]
        guard fragment.count <= Self.maximumFragmentLength, !fragment.contains(UInt8(ascii: "%")) else {
            throw .notAnOffer
        }

        var fields: [Key: ArraySlice<UInt8>] = [:]
        for pair in fragment.split(separator: UInt8(ascii: "&"), omittingEmptySubsequences: false) {
            guard let equals = pair.firstIndex(of: UInt8(ascii: "=")),
                  let key = Key(rawValue: String(decoding: pair[..<equals], as: UTF8.self)),
                  fields.updateValue(pair[(equals + 1)...], forKey: key) == nil
            else { throw .notAnOffer }
        }
        guard let version = fields[.version], version.elementsEqual("1".utf8) else { throw .notAnOffer }
        guard let host = fields[.host].flatMap(OfferField.host) else { throw .invalidHost }
        guard let port = fields[.port].flatMap(OfferField.port) else { throw .invalidPort }
        guard let secret = fields[.secret].flatMap(OfferField.secret) else { throw .invalidSecret }
        guard let expires = fields[.expiry].flatMap(OfferField.expiry) else { throw .invalidExpiry }
        let authKey: String?
        if let key = fields[.authKey] { authKey = try OfferField.authKey(key) } else { authKey = nil }

        self.init(host: host, port: port, expires: expires, authKey: authKey, secret: secret)
    }

    /// 이 제안을 실은 링크. `base`는 앱의 것이다(`myapp://pair`, `https://example.com/pair`). `base`에 조각이 있으면 버린다.
    ///
    /// 결과는 비밀이다. OS가 배달하는 사용자 지정 스킴은 같은 스킴을 선언한 다른 앱이 받을 수 있으므로, 인증 키를 실은
    /// 링크는 연결 도메인(universal link)으로 낸다.
    public func url(base: URL) -> URL {
        let text = base.absoluteString
        let stem = text.firstIndex(of: "#").map { String(text[..<$0]) } ?? text
        // 조각의 글자는 모두 URL에 그대로 쓸 수 있는 것이라, `base`가 URL이면 이것도 URL이다.
        guard let url = URL(string: stem + "#" + fragment) else {
            preconditionFailure("URL에 허용된 글자만 더했으므로 올바른 URL이다")
        }
        return url
    }

    /// 조각의 글(`#` 뒤).
    var fragment: String {
        var text = "v=1&h=\(host)&p=\(port)&s=\(OfferField.secretText(secret))"
            + "&e=\(Int64(expires.timeIntervalSince1970))"
        if let authKey { text += "&k=\(authKey)" }
        return text
    }
}

/// 조각의 값 하나하나를 읽는 규칙(동작 O2). 바이트를 받아 검증된 값을 낸다. 어긋나면 nil이다.
///
/// 여는 쪽도 같은 규칙으로 자기 FQDN과 받은 인증 키를 본다. 그래야 낸 링크가 반드시 읽힌다.
enum OfferField {
    /// 인증 키의 한도.
    static let maximumAuthKeyLength = 256

    /// 올바른 DNS 이름: 라벨은 1~63자의 `a-z0-9-`이고 하이픈으로 시작·끝나지 않는다. 전체 253자 이하, 라벨 둘 이상.
    ///
    /// 끝 라벨이 숫자뿐이면 이름이 아니라 IP 주소 꼴이다(`192.168.1.1`). 받지 않는다: 주소를 적은 링크가 들어오는 쪽을
    /// MagicDNS를 거치지 않고 tailnet 밖의 곳에 걸게 하지 못한다(`SwiftailCertificates`의 이름 규칙과 같다).
    static func host(_ bytes: some BidirectionalCollection<UInt8>) -> String? {
        let labels = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard (1...253).contains(bytes.count), labels.count >= 2, let last = labels.last, !last.allSatisfy(\.isDigit)
        else { return nil }
        for label in labels {
            guard (1...63).contains(label.count), label.first != UInt8(ascii: "-"), label.last != UInt8(ascii: "-"),
                  label.allSatisfy({ $0.isLowercaseLetter || $0.isDigit || $0 == UInt8(ascii: "-") })
            else { return nil }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// 앞자리 0이 없는 1~65535의 10진수.
    static func port(_ bytes: some Collection<UInt8>) -> UInt16? {
        guard let value = decimal(bytes, maximumDigits: 5) else { return nil }
        return UInt16(exactly: value)
    }

    /// 부호와 앞자리 0이 없는 1~11자리 10진수(유닉스 초).
    static func expiry(_ bytes: some Collection<UInt8>) -> Date? {
        decimal(bytes, maximumDigits: 11).map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// 채움 없는 base64url 43자이고 정확히 32바이트로 풀린다. 남는 비트는 0이어야 한다.
    static func secret(_ bytes: some Collection<UInt8>) -> [UInt8]? {
        guard bytes.count == 43,
              bytes.allSatisfy({ $0.isLetter || $0.isDigit || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_") })
        else { return nil }
        let text = String(decoding: bytes, as: UTF8.self)
        let standard = text.replacing("-", with: "+").replacing("_", with: "/") + "="
        guard let secret = Data(base64Encoded: standard).map(Array.init), secret.count == PairingOffer.secretLength,
              // 남는 비트가 0이 아닌 글은 다시 적으면 달라진다.
              secretText(secret) == text
        else { return nil }
        return secret
    }

    /// 비밀을 링크에 적는 글(채움 없는 base64url).
    static func secretText(_ secret: [UInt8]) -> String {
        Data(secret).base64EncodedString()
            .replacing("+", with: "-").replacing("/", with: "_").replacing("=", with: "")
    }

    /// `tskey-auth-`로 시작하고 `A-Za-z0-9-`만 쓰는 256바이트 이하의 인증 키.
    ///
    /// - Throws: 감싼 키(`--TL`)면 `wrappedAuthKey`, 그 밖에 어긋나면 `invalidAuthKey`. 감싼 키는 뒤쪽이 표준 base64라
    ///   글자 검사에도 걸리므로 먼저 가린다.
    static func authKey(_ bytes: some Collection<UInt8>) throws(PairingOfferError) -> String {
        let text = String(decoding: bytes, as: UTF8.self)
        guard !text.contains("--TL") else { throw .wrappedAuthKey }
        guard bytes.starts(with: "tskey-auth-".utf8), bytes.count <= maximumAuthKeyLength,
              bytes.allSatisfy({ $0.isLetter || $0.isDigit || $0 == UInt8(ascii: "-") })
        else { throw .invalidAuthKey }
        return text
    }

    /// 앞자리 0이 없는 양의 10진수. 자릿수가 `maximumDigits`를 넘으면 nil(11자리까지는 `Int64`에 든다).
    private static func decimal(_ bytes: some Collection<UInt8>, maximumDigits: Int) -> Int64? {
        guard (1...maximumDigits).contains(bytes.count), bytes.first != UInt8(ascii: "0"),
              bytes.allSatisfy(\.isDigit)
        else { return nil }
        return bytes.reduce(Int64(0)) { $0 * 10 + Int64($1 - UInt8(ascii: "0")) }
    }
}

private extension UInt8 {
    var isDigit: Bool { (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(self) }
    var isLowercaseLetter: Bool { (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(self) }
    var isLetter: Bool { isLowercaseLetter || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(self) }
}
