// Matches the declaration in contract §2 of `docs/contracts/SwiftailHost.md`. The ACME order flow (M7-4) and `CertificateManager` (M7-6)
// create these values and expose them to the app through `CertificateStatus.lastFailure`.

import Foundation

/// The reason issuance failed. The app chooses user-facing wording by kind and uses associated strings only for diagnostics.
public enum CertificateFailure: Sendable, Equatable {
    /// The node is not `.running`.
    case nodeNotRunning
    /// MagicDNS is disabled on the tailnet. The user must enable it in the admin console.
    case magicDNSDisabled
    /// HTTPS certificates are disabled on the tailnet (netmap `DNSConfig.CertDomains` is empty). The user must enable them in the admin console.
    case httpsNotEnabled
    /// The node name is absent from the netmap's cert domains or fails the name check in behavior C2.
    case domainNotAllowed
    /// The control server rejected the DNS record request. The associated value is the HTTP status code.
    case controlRejected(status: Int)
    /// The ACME server rejected the request with an unsuccessful HTTP response. `status` is the HTTP status code, and `type` is the full
    /// type string from the problem document (`urn:ietf:params:acme:error:badCSR`, a server-specific URI, or `about:blank`). If the problem
    /// document is absent, is not JSON, or lacks `type`, the string is empty. Truncate it to 256 bytes. Omit the problem document's `detail`
    /// because it may contain identifiers (behavior K2).
    case acme(status: Int, type: String)
    /// The ACME server's rate limit (`type` is `urn:ietf:params:acme:error:rateLimited`), with the retry time supplied by the server.
    case rateLimited(retryAfter: Date?)
    /// The certificate authority failed to verify ownership of the name. The authorization is `invalid` (the DNS record was missing or its value differed).
    /// `type` is the type of that challenge's `error` problem document (same rules as `acme`).
    case validationFailed(type: String)
    /// The order became `invalid` for a reason other than authorization failure (expiration, CSR or issuance rejection, etc.), or an authorization
    /// prevents the order from proceeding (`deactivated`, `expired`, or `revoked`). `type` is the type of the order's `error` problem document.
    case orderFailed(type: String)
    /// The ACME server's response violated the specification or the contract limits (unknown status, authorization for another name,
    /// oversized body, a URL with a scheme other than `https`, etc., behaviors C5 and X).
    case unexpectedResponse
    /// The certificate received failed verification (name, validity period, chain, or key).
    case invalidCertificate
    /// The ACME server or control server could not be reached.
    case network(String)
    /// Issuance did not finish before the deadline.
    case timedOut
}
