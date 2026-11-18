/// An unrecoverable `CertificateManager` failure. `run()` throws it because restarting would not help (behavior R4).
///
/// Issuance failures (ACME server rejection, lost connections, or unmet conditions) are recorded in `CertificateStatus.lastFailure`.
public enum CertificateError: Error, Sendable, Equatable {
    /// An invalid directory URL. Also covers calling `run()` twice.
    case invalidConfiguration(String)
    /// Failed to create, write, or read `certs/`. Also covers an existing certs/ writable by the group or others (behavior S1).
    /// The message contains only an error code.
    case storage(String)
    /// `certs/acme-account.key.pem` exists but could not be read as a P-256 account key (an RSA key left by Go, a corrupt file, or an oversized file).
    /// Preserve the file because creating a new account would lose the account it identified (behavior C4).
    case accountKeyUnreadable
}

extension CertificateError {
    /// Maps a store failure to the same-named case.
    init(_ error: CertificateStoreError) {
        switch error {
        case .storage(let message): self = .storage(message)
        case .accountKeyUnreadable: self = .accountKeyUnreadable
        }
    }
}
