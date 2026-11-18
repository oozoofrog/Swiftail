import CryptoKit
import Foundation

/// A certificate issued for the node's ts.net name and its private key.
///
/// The string representation and `dump` expose only the validity period, keeping the private key and tailnet name out of logs (behaviors K1 and K2).
public struct TailnetCertificate: Sendable {
    /// The certificate name (`rd-mac-1a2b3c4d.tail0001.ts.net`).
    public let domain: String
    /// DER certificates with the leaf first, followed by intermediates. As the ACME server may include the root (RFC 8555 9.1),
    /// non-leaf self-signed certificates are removed after verification (behavior S6). Use the result directly in the TLS identity.
    public let chain: [[UInt8]]
    /// The leaf private key. Pass `x963Representation` to `SecKeyCreateWithData` to create a `SecKey`.
    public let privateKey: P256.Signing.PrivateKey
    /// The start of the leaf's validity period.
    public let notBefore: Date
    /// The end of the leaf's validity period. The manager renews before this time, at the 2/3 point of its lifetime.
    public let notAfter: Date

    /// Creates a value only from a verified chain (behaviors C8 and S3).
    init(_ certificate: VerifiedCertificate) {
        domain = certificate.lifetime.domain.name
        chain = certificate.chain
        privateKey = certificate.privateKey
        notBefore = certificate.lifetime.notBefore
        notAfter = certificate.lifetime.notAfter
    }
}

extension TailnetCertificate: CustomStringConvertible, CustomReflectable {
    /// Displays only the validity period, which is safe to log.
    public var description: String {
        "TailnetCertificate(notBefore: \(notBefore), notAfter: \(notAfter))"
    }

    /// Exposes only the validity period through reflection and dumps.
    public var customMirror: Mirror {
        Mirror(self, children: ["notBefore": notBefore, "notAfter": notAfter], displayStyle: .struct)
    }
}
