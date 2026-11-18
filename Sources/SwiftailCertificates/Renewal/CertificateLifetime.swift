import Foundation

/// The name and validity period of a held certificate, used as input to `RenewalSchedule`.
///
/// Security extracts these values from a verified leaf (`VerifiedCertificate.lifetime`).
struct CertificateLifetime: Sendable, Equatable {
    /// The certificate name. If the node name changes, it differs from this value and triggers fresh issuance (contract behavior S4).
    let domain: CertificateDomain
    let notBefore: Date
    let notAfter: Date

    /// The time to begin renewal, at 2/3 of the lifetime (contract behavior R1, H6).
    ///
    /// Go uses this rule when its ARI lookup fails (`feature/acme/cert.go:233-251`, notes §4.4 item 1). It is not guaranteed to avoid Let's Encrypt's
    /// rate limits (notes §4.5).
    // shortcut: Omits ARI (RFC 9773) and `replaces`. Revisit if a certificate authority announces an earlier renewal time (mass revocation)
    // or a rate limit exemption for ARI renewal becomes necessary (contract §8 `shortcut:` table).
    var renewalDate: Date {
        notBefore.addingTimeInterval(notAfter.timeIntervalSince(notBefore) * 2 / 3)
    }
}
