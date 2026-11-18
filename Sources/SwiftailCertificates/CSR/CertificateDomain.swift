/// A name to obtain a certificate for. Only values that pass the name check (contract behavior C2) can be created.
///
/// Used as a file name (`certs/<name>.crt`), a DNS record name (`_acme-challenge.<name>`), an ACME identifier, and the CSR's
/// subject CN and SAN. A single DNS name rule ensures both path safety and DNS validity (RFC 1034
/// 3.1 and 3.5, RFC 1123 2.1). After removing one trailing dot, the name must meet these rules.
///
/// 1. It has at least two dot-separated labels.
/// 2. Each label has 1–63 characters, starts and ends with an alphanumeric character, and uses alphanumeric characters and hyphens in between.
/// 3. The entire name has at most 253 characters, as does the record name with `_acme-challenge.` prepended (so the name has at most 237).
///
/// Only lowercase English letters are accepted. The contract narrows the rule to prevent file name collisions
/// on case-insensitive file systems. This excludes `..`, `/`, `\`, `:`, NUL, `*`, and `_` and leaves only characters in both `PrintableString`
/// and `IA5String` (contract behavior C7, notes §3.6).
///
/// The name includes the tailnet name, so there is no `description` to keep it out of logs (contract behavior K2).
struct CertificateDomain: Sendable, Hashable {
    /// The name without a trailing dot (`rd-mac-1a2b3c4d.tail0001.ts.net`).
    let name: String

    /// The maximum length without a trailing dot. Subtracts the 16 characters in `_acme-challenge.` from the DNS name limit of 253.
    static let maximumLength = 253 - challengeLabelPrefix.utf8.count

    /// Removes one trailing dot and validates the name. Returns `nil` on failure (the caller reports `domainNotAllowed`, contract H23).
    init?(_ fqdn: String) {
        let name = fqdn.hasSuffix(".") ? String(fqdn.dropLast()) : fqdn
        let labels = name.utf8.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard name.utf8.count <= Self.maximumLength, labels.count >= 2, labels.allSatisfy(Self.isValidLabel),
              // An all-digit final label resembles an IP address (`100.64.0.1`). The certificate authority does not accept it as a name.
              let last = labels.last, !last.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) })
        else {
            return nil
        }
        self.name = name
    }

    /// The DNS-01 TXT record name (RFC 8555 8.4).
    var challengeRecordName: String {
        Self.challengeLabelPrefix + name
    }

    private static let challengeLabelPrefix = "_acme-challenge."

    private static func isValidLabel(_ label: Substring.UTF8View) -> Bool {
        guard (1...63).contains(label.count), let first = label.first, let last = label.last,
              isLowercaseAlphanumeric(first), isLowercaseAlphanumeric(last)
        else { return false }
        return label.allSatisfy { isLowercaseAlphanumeric($0) || $0 == UInt8(ascii: "-") }
    }

    private static func isLowercaseAlphanumeric(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }
}
