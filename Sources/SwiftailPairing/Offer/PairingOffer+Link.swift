import Foundation

/// The offer link: `<base>#v=1&h=<host>&p=<port>&s=<secret>&e=<expiration>[&k=<auth key>]` (contract behaviors O1–O4).
///
/// All values are in the fragment (after `#`). The fragment is omitted from server requests and Referer. Value characters require no URL encoding,
/// so the reader uses the original bytes without decoding `%`. The same offer cannot be read from two different spellings.
extension PairingOffer {
    /// The fragment size limit (behavior O2).
    static let maximumFragmentLength = 2048

    /// Fragment keys. Only these six are accepted.
    private enum Key: String {
        case version = "v", host = "h", port = "p", secret = "s", expiry = "e", authKey = "k"
    }

    /// Parses an offer from a received URL (`url.absoluteString`) or a string read from a QR code.
    ///
    /// Reads only after the first `#`. The prefix (`base`) is ignored, so the app determines which URLs belong to it. Expired offers can still
    /// be read (behavior O4). Links can come from anywhere, so pairing started from a link shows `host` and asks for the user's confirmation
    /// before pairing.
    ///
    /// - Throws: The reason reading failed. Omits the values (behavior O3).
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

    /// A link carrying this offer. `base` belongs to the app (`myapp://pair`, `https://example.com/pair`). Discards any fragment on base.
    ///
    /// The result is a secret. Another app that declares the same custom scheme can receive URLs delivered by the OS, so links carrying
    /// auth keys use an associated domain (universal link).
    public func url(base: URL) -> URL {
        let text = base.absoluteString
        let stem = text.firstIndex(of: "#").map { String(text[..<$0]) } ?? text
        // All fragment characters can appear directly in a URL, so a URL `base` yields another valid URL.
        guard let url = URL(string: stem + "#" + fragment) else {
            preconditionFailure("The URL is valid because only URL-safe characters were appended")
        }
        return url
    }

    /// The fragment text after `#`.
    var fragment: String {
        var text = "v=1&h=\(host)&p=\(port)&s=\(OfferField.secretText(secret))"
            + "&e=\(Int64(expires.timeIntervalSince1970))"
        if let authKey { text += "&k=\(authKey)" }
        return text
    }
}

/// The rules for reading each fragment value (behavior O2). Takes bytes and returns a validated value, or nil on failure.
///
/// The host applies the same rules to its FQDN and the supplied auth key so the generated link can always be read.
enum OfferField {
    /// The auth key limit.
    static let maximumAuthKeyLength = 256

    /// A valid DNS name has at least two labels, at most 253 characters total, and labels of 1–63 characters from `a-z0-9-` that neither start nor end with hyphens.
    ///
    /// The final label must start with a letter (`a-z`), because top-level domains do not start with digits. A digit-starting final label resembles
    /// an IP address (`192.168.1.1`, `192.168.1.0x1`), and the OS parses the hexadecimal form as IPv4. Reject these to prevent an address in a link
    /// from making the joiner dial outside the tailnet without using MagicDNS.
    static func host(_ bytes: some BidirectionalCollection<UInt8>) -> String? {
        let labels = bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard (1...253).contains(bytes.count), labels.count >= 2, labels.last?.first?.isLowercaseLetter == true
        else { return nil }
        for label in labels {
            guard (1...63).contains(label.count), label.first != UInt8(ascii: "-"), label.last != UInt8(ascii: "-"),
                  label.allSatisfy({ $0.isLowercaseLetter || $0.isDigit || $0 == UInt8(ascii: "-") })
            else { return nil }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// A decimal number from 1 to 65535 without leading zeros.
    static func port(_ bytes: some Collection<UInt8>) -> UInt16? {
        guard let value = decimal(bytes, maximumDigits: 5) else { return nil }
        return UInt16(exactly: value)
    }

    /// A decimal number of 1–11 digits with no sign or leading zeros (Unix seconds).
    static func expiry(_ bytes: some Collection<UInt8>) -> Date? {
        decimal(bytes, maximumDigits: 11).map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// Exactly 43 unpadded base64url characters that decode to exactly 32 bytes. Unused bits must be zero.
    static func secret(_ bytes: some Collection<UInt8>) -> [UInt8]? {
        guard bytes.count == 43,
              bytes.allSatisfy({ $0.isLetter || $0.isDigit || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_") })
        else { return nil }
        let text = String(decoding: bytes, as: UTF8.self)
        let standard = text.replacing("-", with: "+").replacing("_", with: "/") + "="
        guard let secret = Data(base64Encoded: standard).map(Array.init), secret.count == PairingOffer.secretLength,
              // Reencoding text with nonzero unused bits changes it.
              secretText(secret) == text
        else { return nil }
        return secret
    }

    /// The link encoding of the secret (unpadded base64url).
    static func secretText(_ secret: [UInt8]) -> String {
        Data(secret).base64EncodedString()
            .replacing("+", with: "-").replacing("/", with: "_").replacing("=", with: "")
    }

    /// An auth key of at most 256 bytes that starts with `tskey-auth-` and uses only `A-Za-z0-9-`.
    ///
    /// - Throws: `wrappedAuthKey` for a wrapped key (`--TL`), or `invalidAuthKey` for other violations. Check wrapped keys first because the standard base64
    ///   suffix would also fail character validation.
    static func authKey(_ bytes: some Collection<UInt8>) throws(PairingOfferError) -> String {
        let text = String(decoding: bytes, as: UTF8.self)
        guard !text.contains("--TL") else { throw .wrappedAuthKey }
        guard bytes.starts(with: "tskey-auth-".utf8), bytes.count <= maximumAuthKeyLength,
              bytes.allSatisfy({ $0.isLetter || $0.isDigit || $0 == UInt8(ascii: "-") })
        else { throw .invalidAuthKey }
        return text
    }

    /// A positive decimal number without leading zeros. Returns nil above `maximumDigits` (up to 11 digits fit in `Int64`).
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
