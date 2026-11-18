import CryptoKit
import Foundation
import Security

/// Roots to trust during chain verification (contract behaviors S3 ⑤, X3 ④, and C8).
///
/// Production uses only `system`. Go falls back to embedded Let's Encrypt roots if system roots fail, and lets
/// "unknown certificate authority" errors pass for non-production directories (`feature/acme/certstore.go:440-477`). Swiftail omits both
/// behaviors. Tests and staging supply explicit anchors (the role of Go's `testRoots`).
package enum CertificateTrustAnchors: Sendable, Equatable {
    /// The OS default trust store (`SecTrust`'s default anchors).
    case system
    /// Trusts only these DER certificates and excludes system roots (`SecTrustSetAnchorCertificatesOnly`).
    case only([[UInt8]])
}

/// The reason the received chain failed verification. `CertificateManager` reports all of these as `CertificateFailure.invalidCertificate`.
///
/// Omits names and paths (contract behavior K3). The status code in `untrusted` is a Security error code (`errSec…` in `SecBase.h`).
enum CertificateVerificationError: Error, Sendable, Equatable {
    /// Invalid PEM, a block other than `CERTIFICATE`, or a count outside 1–5 certificates (behavior X3 ① and ②).
    case malformedChain(PEMError)
    /// DER could not be read as an X.509 certificate (`SecCertificateCreateWithData` returned nil).
    case unparsableCertificate
    /// The leaf public key differs from the public key of the held private key (behaviors X3 ③ and S3 ④).
    case keyMismatch
    /// The validity period could not be extracted from the leaf.
    case validityUnavailable
    /// `notAfter − notBefore` is less than 1 hour (behavior X3 ⑤).
    case lifetimeTooShort
    /// `SecTrust` rejected the name, validity at the current time, or chain up to the anchor (behaviors X3 ④ and S3 ⑤).
    case untrusted(status: Int)
}

/// A verified certificate chain and its private key. Values can be created only through the checks in `init`.
///
/// Chains returned by ACME (behaviors C8 and X3) and read from `certs/` (behavior S3) undergo the same checks. The store uses only this type,
/// so unverified chains are never persisted to disk.
///
/// Because this holds a private key, `description` and `dump` expose only the validity period (the name contains the tailnet name, behavior K).
struct VerifiedCertificate: Sendable {
    /// The certificate's name and validity period (from the leaf).
    let lifetime: CertificateLifetime
    /// The original chain as received (DER, leaf first). Write this to `<name>.crt` (behavior S6, same as Go).
    let receivedChain: [[UInt8]]
    /// The chain for the TLS identity, with non-leaf self-signed certificates (roots) removed from the received chain (behavior S6).
    /// This is `TailnetCertificate.chain`.
    let chain: [[UInt8]]
    /// The leaf private key.
    let privateKey: P256.Signing.PrivateKey

    /// The minimum certificate lifetime (behavior X3 ⑤). A shorter lifetime makes renewal decisions run pointlessly.
    static let minimumLifetime: TimeInterval = 3600

    /// Reads and verifies a PEM chain.
    ///
    /// In order: ① check all PEM and the count of 1–5 certificates (`PEM.certificateChain`), ② match the leaf public key to `privateKey`,
    /// ③ require a lifetime of at least 1 hour, and ④ require `SecTrust` acceptance (SSL server policy and `domain`, verification time `now`, `anchors`).
    /// On success, builds `chain` according to behavior S6.
    ///
    /// `SecTrustEvaluateWithError` blocks the calling thread. Network fetching for missing intermediate certificates is disabled
    /// (`SecTrustSetNetworkFetchAllowed`), so verification uses only the chain sent by the server.
    ///
    /// - Parameter maximumByteCount: The PEM input limit (256KiB for ACME responses, 64KiB for disk files, behavior M).
    init(
        pemChain: [UInt8],
        maximumByteCount: Int,
        privateKey: P256.Signing.PrivateKey,
        domain: CertificateDomain,
        at now: Date,
        anchors: CertificateTrustAnchors
    ) throws(CertificateVerificationError) {
        let der: [[UInt8]]
        do {
            der = try PEM.certificateChain(from: pemChain, maximumByteCount: maximumByteCount)
        } catch {
            throw .malformedChain(error)
        }
        let facts = try Self.evaluate(der, publicKey: privateKey.publicKey, domain: domain, at: now, anchors: anchors)
        lifetime = CertificateLifetime(domain: domain, notBefore: facts.notBefore, notAfter: facts.notAfter)
        receivedChain = der
        chain = der.enumerated().filter { index, certificate in index == 0 || certificate != facts.anchor }.map(\.element)
        self.privateKey = privateKey
    }

    /// Chain facts obtained from Security. Security types (`SecCertificate`, `SecTrust`) never leave this function.
    private struct Facts {
        var notBefore: Date
        var notAfter: Date
        /// The trust anchor (DER) of the chain selected by evaluation, or nil for a chain consisting only of the leaf.
        var anchor: [UInt8]?
    }

    private static func evaluate(
        _ der: [[UInt8]],
        publicKey: P256.Signing.PublicKey,
        domain: CertificateDomain,
        at now: Date,
        anchors: CertificateTrustAnchors
    ) throws(CertificateVerificationError) -> Facts {
        let certificates = der.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard certificates.count == der.count, let leaf = certificates.first else { throw .unparsableCertificate }

        // ② Public key: Compare uncompressed X9.63 points (04 ‖ X ‖ Y, the EC external representation in `SecKey.h`). The values are public, so comparison need not be constant-time.
        guard let leafKey = SecCertificateCopyKey(leaf),
              let leafPoint = SecKeyCopyExternalRepresentation(leafKey, nil) as Data?,
              leafPoint == publicKey.x963Representation
        else { throw .keyMismatch }

        // ③ Validity period: `SecCertificateCopyNotValidBeforeDate` and `…AfterDate` in macOS 15 and iOS 18.
        guard let notBefore = SecCertificateCopyNotValidBeforeDate(leaf) as Date?,
              let notAfter = SecCertificateCopyNotValidAfterDate(leaf) as Date?
        else { throw .validityUnavailable }
        guard notAfter.timeIntervalSince(notBefore) >= minimumLifetime else { throw .lifetimeTooShort }

        // ④ Chain, name, and current time.
        let policy = SecPolicyCreateSSL(true, domain.name as CFString)
        var created: SecTrust?
        try check(SecTrustCreateWithCertificates(certificates as CFArray, policy, &created))
        guard let trust = created else { throw .untrusted(status: Int(errSecParam)) }
        try check(SecTrustSetNetworkFetchAllowed(trust, false))
        try check(SecTrustSetVerifyDate(trust, now as CFDate))
        if case .only(let anchorDER) = anchors {
            let anchorCertificates = anchorDER.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
            // Dropping unreadable anchors would not broaden trust, but it could hide test mistakes, so fail closed.
            guard anchorCertificates.count == anchorDER.count else { throw .untrusted(status: Int(errSecParam)) }
            try check(SecTrustSetAnchorCertificates(trust, anchorCertificates as CFArray))
            try check(SecTrustSetAnchorCertificatesOnly(trust, true))
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw .untrusted(status: error.map { CFErrorGetCode($0) } ?? Int(errSecNotTrusted))
        }

        // Behavior S6: Remove the trust anchor from `chain` if the server sent it. The last certificate in the evaluated chain is the anchor
        // (`SecTrustCopyCertificateChain` in `SecTrust.h`). Matching subject and issuer names alone do not warrant removal. A self-issued intermediate
        // with the same name and a different key supports key rollover and is needed by the peer to build the chain.
        let evaluated = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        let anchor = evaluated.count > 1 ? evaluated.last.map { [UInt8](SecCertificateCopyData($0) as Data) } : nil
        return Facts(notBefore: notBefore, notAfter: notAfter, anchor: anchor)
    }

    private static func check(_ status: OSStatus) throws(CertificateVerificationError) {
        guard status == errSecSuccess else { throw .untrusted(status: Int(status)) }
    }
}

extension VerifiedCertificate: CustomStringConvertible, CustomReflectable {
    var description: String {
        "VerifiedCertificate(notBefore: \(lifetime.notBefore), notAfter: \(lifetime.notAfter))"
    }

    var customMirror: Mirror {
        Mirror(self, children: ["notBefore": lifetime.notBefore, "notAfter": lifetime.notAfter], displayStyle: .struct)
    }
}
