// The verification rules follow `SetConfigExpectedCert` and `SetConfigExpectedCertHash` in tailscale.com v1.104.6
// `net/tlsdial/tlsdial.go`, `derp/derpconst/derpconst.go`, and `hostnameInSNI` in Go 1.27.3
// `crypto/tls/handshake_client.go`
// (tailscale: Copyright (c) Tailscale Inc & contributors, BSD-3-Clause. Go: Copyright The Go Authors, BSD-3-Clause).

import CryptoKit
import Foundation
import Security
import SwiftailBase

/// Verifies the certificates presented by a TLS server using only the list of DER certificates, name, and time, without a connection.
///
/// The `.named` and `.pinned` cases of `NetworkSocket.TLS` call this from the TLS verification block. Tests call it
/// directly with fixed certificates (contract `docs/contracts/SwiftailDERP.md` "M8 ③" behavior V).
package enum ServerCertificate {
    /// The reason verification failed. Contains no names, keys, or hashes.
    package enum Failure: Error, Sendable, Equatable {
        /// The server presented no certificates or at least one could not be parsed as X.509.
        case unparsable
        /// No certificates remain after excluding meta certificates.
        case noCandidate
        /// Two or more certificates remain after excluding meta certificates.
        case multipleCandidates
        /// The one remaining certificate is not first. The TLS handshake proves key ownership only for the first certificate.
        case candidateNotLeaf
        /// The SHA-256 of the one remaining certificate differs from the pinned value.
        case hashMismatch
        /// `SecTrust` rejected the name, validity period, or chain. `status` is the Security error code.
        case untrusted(status: Int)
    }

    /// The subject CN prefix of the meta certificate appended by the DERP server (Go `derpconst.MetaCertCommonNamePrefix`).
    static let metaCommonNamePrefix = "derpkey"

    /// Verifies a `sha256-raw:` pin (Go `SetConfigExpectedCertHash`).
    ///
    /// After excluding all certificates whose subject CN starts with `derpkey` (meta certificates), exactly one
    /// certificate must remain.
    /// That certificate must meet all these conditions.
    /// ⓪ It comes first in the list. ① The SHA-256 of the entire DER, in lowercase hex, exactly matches `sha256Hex`.
    /// ② It is valid for `serverName` if that name is sent as SNI (if it is not an IP literal). ③ `now` is within the
    /// validity period. The chain is not checked.
    ///
    /// Go does not impose condition ⓪. The TLS handshake proves possession of only the first certificate's key. If position is
    /// ignored, as in Go, a server can pass verification by appending the publicly retrievable pinned certificate after
    /// a `derpkey…` certificate for its own key. derper presents the server certificate first and the meta certificate
    /// afterward (`derpserver.ModifyTLSConfigToAddMetaCert`), so normal servers pass.
    ///
    /// `SecTrust` checks ② and ③ with that certificate as the only anchor, using the SSL server policy when there is a
    /// name and the default X.509 policy otherwise. The SSL server policy also applies Apple's TLS server certificate
    /// requirements that Go does not check (server authentication EKU, validity of 825 days or less, RSA at least 2048
    /// bits, no Ed25519 keys, and so on). Certificates derper generates for IP addresses satisfy these requirements.
    // shortcut: When pinning an operator-generated self-signed certificate (no EKU, 10-year validity, and so on) for a
    // DERP reached by name, Go connects and this implementation rejects it. Checking the name and validity period
    // directly requires parsing the X.509 SAN. Add that when such a DERP must be supported.
    ///
    /// - Parameters:
    ///   - certificates: The DER certificates in the order presented by the server.
    ///   - serverName: The TLS server name (the DERP node's `hostName`).
    package static func checkPinned(
        _ certificates: [[UInt8]], sha256Hex: String, serverName: String, at now: Date
    ) throws(Failure) {
        let parsed = try parse(certificates)
        let candidates = parsed.filter { !isMeta($0.ref) }
        guard let candidate = candidates.first else { throw .noCandidate }
        guard candidates.count == 1 else { throw .multipleCandidates }
        guard !isMeta(parsed[0].ref) else { throw .candidateNotLeaf }
        // The hash of a public certificate is public. Constant-time comparison is unnecessary.
        guard Array(SHA256.hash(data: candidate.der)).hex == sha256Hex else { throw .hashMismatch }
        try evaluate([candidate.ref], name: sniHostName(serverName), at: now, anchors: [candidate.ref], fetch: false)
    }

    /// Performs system verification with a separately specified name (Go `SetConfigExpectedCert`).
    ///
    /// Treats the first certificate as the leaf and the remaining certificates as candidates for building the chain,
    /// then evaluates against `name` with the SSL server policy. Unlike Go, it skips retrying with a bundled Let's
    /// Encrypt root because the system trust store already contains the root.
    ///
    /// - Parameter anchors: Nil uses the system trust store. Tests supply DER to trust only their own root.
    package static func checkNamed(
        _ certificates: [[UInt8]], name: String, at now: Date, anchors: [[UInt8]]? = nil
    ) throws(Failure) {
        let parsed = try parse(certificates)
        let anchorRefs = try anchors.map { anchors throws(Failure) in try parse(anchors).map(\.ref) }
        try evaluate(parsed.map(\.ref), name: name, at: now, anchors: anchorRefs, fetch: true)
    }

    /// Returns the name sent through SNI in the TLS ClientHello (Go `hostnameInSNI`). Returns nil for an IP literal and
    /// strips trailing dots.
    ///
    /// Go's `sha256-raw:` check skips name verification when this value is empty (a connection to derper by IP).
    package static func sniHostName(_ name: String) -> String? {
        var host = Substring(name)
        if host.count > 1, host.first == "[", host.last == "]" { host = host.dropFirst().dropLast() }
        if let zone = host.lastIndex(of: "%"), zone > host.startIndex { host = host[..<zone] }
        if IPAddress(String(host)) != nil { return nil }
        var result = Substring(name)
        while result.last == "." { result = result.dropLast() }
        return result.isEmpty ? nil : String(result)
    }

    /// Whether the subject CN starts with the meta certificate prefix. A missing CN means the certificate is not meta.
    /// In Go, an empty CN also does not start with the prefix.
    private static func isMeta(_ certificate: SecCertificate) -> Bool {
        var commonName: CFString?
        guard SecCertificateCopyCommonName(certificate, &commonName) == errSecSuccess, let commonName else { return false }
        return (commonName as String).hasPrefix(metaCommonNamePrefix)
    }

    private static func parse(_ certificates: [[UInt8]]) throws(Failure) -> [(der: [UInt8], ref: SecCertificate)] {
        guard !certificates.isEmpty else { throw .unparsable }
        return try certificates.map { der throws(Failure) in
            guard let ref = SecCertificateCreateWithData(nil, Data(der) as CFData) else { throw .unparsable }
            return (der, ref)
        }
    }

    /// `SecTrustEvaluateWithError` blocks the calling thread. Call it on the TLS verification block's queue.
    private static func evaluate(
        _ certificates: [SecCertificate], name: String?, at now: Date, anchors: [SecCertificate]?, fetch: Bool
    ) throws(Failure) {
        var created: SecTrust?
        let policy = name.map { SecPolicyCreateSSL(true, $0 as CFString) } ?? SecPolicyCreateBasicX509()
        try check(SecTrustCreateWithCertificates(certificates as CFArray, policy, &created))
        guard let trust = created else { throw .untrusted(status: Int(errSecParam)) }
        try check(SecTrustSetVerifyDate(trust, now as CFDate))
        if !fetch { try check(SecTrustSetNetworkFetchAllowed(trust, false)) }
        if let anchors {
            try check(SecTrustSetAnchorCertificates(trust, anchors as CFArray))
            try check(SecTrustSetAnchorCertificatesOnly(trust, true))
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw .untrusted(status: error.map { CFErrorGetCode($0) } ?? Int(errSecNotTrusted))
        }
    }

    private static func check(_ status: OSStatus) throws(Failure) {
        guard status == errSecSuccess else { throw .untrusted(status: Int(status)) }
    }
}
