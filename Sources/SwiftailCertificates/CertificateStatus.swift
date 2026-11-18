import Foundation

/// The current `CertificateManager` status. Apps use it to display the expiration time, failure message, and next attempt time. They also use it to decide
/// whether to offer "Retry Now".
public struct CertificateStatus: Sendable, Equatable {
    /// The name for which a certificate is requested, or nil if the node name is still unknown.
    public var domain: String?
    /// The expiration time of the currently held certificate, or nil if absent.
    public var notAfter: Date?
    /// An unmet issuance prerequisite, if any, or the reason the last attempt failed. A successful attempt clears the last attempt's failure.
    public var lastFailure: CertificateFailure?
    /// The time to attempt issuance or renewal again. If the ACME server's `Retry-After` time is later, uses that time (capped at 7 days,
    /// behavior X5). Returns nil when waiting for conditions (login, MagicDNS, HTTPS, cert domains), with no timer-based retry.
    public var nextAttempt: Date?

    /// Sets the values directly. The manager builds this from its own state and does not use this initializer. Use it to test consumers without a manager.
    public init(domain: String? = nil, notAfter: Date? = nil, lastFailure: CertificateFailure? = nil, nextAttempt: Date? = nil) {
        self.domain = domain
        self.notAfter = notAfter
        self.lastFailure = lastFailure
        self.nextAttempt = nextAttempt
    }
}

extension CertificateStatus: CustomStringConvertible, CustomReflectable {
    /// Omits `domain` because it contains the tailnet name (behavior K2). Includes `lastFailure` and its associated values.
    public var description: String {
        """
        CertificateStatus(notAfter: \(String(describing: notAfter)), lastFailure: \(String(describing: lastFailure)), \
        nextAttempt: \(String(describing: nextAttempt)))
        """
    }

    /// Omits `domain` from reflection and dumps.
    public var customMirror: Mirror {
        Mirror(
            self,
            children: ["notAfter": notAfter as Any, "lastFailure": lastFailure as Any, "nextAttempt": nextAttempt as Any],
            displayStyle: .struct
        )
    }
}
