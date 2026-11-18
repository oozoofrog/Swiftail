import Foundation
import Network
import Security

extension NetworkSocket {
    /// TLS options for a connection.
    package enum TLS: Sendable, Equatable {
        /// Plaintext TCP.
        case none
        /// Verifies the server certificate against the system trust store. Uses `serverName` for SNI and name verification.
        case system(serverName: String)
        /// Verifies the chain against the system trust store and checks the certificate name against `certificateName`.
        /// Sends `serverName` only as SNI (when a DERP node's `CertName` differs from `HostName`, Go
        /// `SetConfigExpectedCert`).
        case named(serverName: String, certificateName: String)
        /// Requires the SHA-256 of the server's one non-meta certificate to match `sha256Hex`. Skips chain verification
        /// (when a DERP node's `CertName` uses `sha256-raw:`, Go `SetConfigExpectedCertHash`). Uses
        /// `ServerCertificate.checkPinned` to check it.
        case pinned(serverName: String, sha256Hex: String)
        /// Skips server certificate verification. **For test servers only.** It cannot identify the server and offers
        /// no protection against man-in-the-middle attacks on real servers. Sends `serverName` only as SNI.
        case insecureForTests(serverName: String)

        /// The TLS options to pass to `NWParameters`. Nil for plaintext.
        var options: NWProtocolTLS.Options? {
            switch self {
            case .none:
                return nil
            case .system(let serverName):
                return Self.options(serverName: serverName, verify: nil)
            case .named(let serverName, let certificateName):
                return Self.options(serverName: serverName) { certificates in
                    do throws(ServerCertificate.Failure) {
                        try ServerCertificate.checkNamed(certificates, name: certificateName, at: Date())
                        return true
                    } catch {
                        return false
                    }
                }
            case .pinned(let serverName, let sha256Hex):
                return Self.options(serverName: serverName) { certificates in
                    do throws(ServerCertificate.Failure) {
                        try ServerCertificate.checkPinned(certificates, sha256Hex: sha256Hex, serverName: serverName, at: Date())
                        return true
                    } catch {
                        return false
                    }
                }
            case .insecureForTests(let serverName):
                // Accept any certificate the server presents.
                return Self.options(serverName: serverName) { _ in true }
            }
        }

        /// If provided, `verify` checks the DER certificates in the order the server presented them and replaces platform verification.
        private static func options(
            serverName: String, verify: (@Sendable ([[UInt8]]) -> Bool)?
        ) -> NWProtocolTLS.Options {
            let options = NWProtocolTLS.Options()
            // The Network framework does not send SNI for names with a trailing dot. Go strips the dot before sending (`hostnameInSNI`).
            sec_protocol_options_set_tls_server_name(
                options.securityProtocolOptions, ServerCertificate.sniHostName(serverName) ?? serverName
            )
            if let verify {
                // Resumed sessions skip the verification block (verified experimentally). Disable resumption so
                // verification runs for every connection.
                sec_protocol_options_set_tls_resumption_enabled(options.securityProtocolOptions, false)
                sec_protocol_options_set_tls_tickets_enabled(options.securityProtocolOptions, false)
                sec_protocol_options_set_verify_block(
                    options.securityProtocolOptions,
                    { metadata, _, complete in
                        var certificates: [[UInt8]] = []
                        let accessed = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                            certificates.append([UInt8](SecCertificateCopyData(sec_certificate_copy_ref(certificate).takeRetainedValue()) as Data))
                        }
                        complete(accessed && verify(certificates))
                    },
                    // Verification blocks the queue in `SecTrustEvaluateWithError`, so use a separate queue for each connection.
                    DispatchQueue(label: "Swiftail.NetworkSocket.verify")
                )
            }
            return options
        }
    }
}
