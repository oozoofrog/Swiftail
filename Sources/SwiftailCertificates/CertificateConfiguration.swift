import Foundation

/// Configuration for `CertificateManager`.
public struct CertificateConfiguration: Sendable {
    /// The Let's Encrypt production directory.
    public static let letsEncryptDirectoryURL: URL = {
        // Go's `LetsEncryptURL` in `tempfork/acme/acme.go:47` (notes chapter 5).
        guard let url = URL(string: "https://acme-v02.api.letsencrypt.org/directory") else {
            preconditionFailure("The fixed Let's Encrypt directory URL is valid")
        }
        return url
    }()

    /// The ACME directory URL. Requires `https`. Override it in tests and staging.
    public var directoryURL: URL

    /// Trusted root certificates (DER) for verifying received and stored chains. nil uses the system trust store.
    ///
    /// Leave nil in production. For a directory from a certificate authority the system does not trust (Let's Encrypt staging or a test server), supply that
    /// authority's roots. This trusts **only those roots** and excludes system roots. Browsers and other devices do not trust certificates
    /// obtained this way. An empty list is rejected because it would trust nothing.
    public var trustAnchors: [[UInt8]]?

    /// - Parameters:
    ///   - directoryURL: The ACME directory URL. Defaults to Let's Encrypt production.
    ///   - trustAnchors: Trusted root certificates (DER). Defaults to nil (the system trust store).
    public init(directoryURL: URL = CertificateConfiguration.letsEncryptDirectoryURL, trustAnchors: [[UInt8]]? = nil) {
        self.directoryURL = directoryURL
        self.trustAnchors = trustAnchors
    }
}
