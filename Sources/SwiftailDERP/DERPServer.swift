import SwiftailBase

/// The connection details for one DERP server. The engine derives them from `tailcfg.DERPNode`.
///
/// A region can have several servers. `DERPClient` tries TCP in list order and uses the first server that connects
/// (`docs/protocol-notes/derp-stun.md` §4.1). Within a server, it races the `targets` and uses the first connection.
public struct DERPServer: Sendable, Equatable {
    /// The TLS server name and HTTP `Host`.
    public var hostName: String
    /// The connection targets. `DERPClient` tries all of them concurrently, uses the first connection, and closes the rest.
    ///
    /// The engine includes at most one address from each IPv4 and IPv6 field, without duplicates (one `hostName` target if
    /// both fields are empty). An empty target list makes this server unreachable.
    public var targets: [Target]
    public var port: UInt16
    public var verification: Verification

    /// One connection target.
    public enum Target: Sendable, Equatable {
        /// Resolves `hostName` via DNS and connects. The Network framework chooses which resolved address to connect to.
        case hostName
        /// Connects to this IP address.
        case address(IPAddress)
    }

    /// How to verify the server certificate.
    public enum Verification: Sendable, Equatable {
        /// Verifies the server certificate for `hostName` using the system trust store.
        case system
        /// Verifies the certificate chain using the system trust store and validates the certificate against the name supplied here. SNI and the HTTP `Host` still use
        /// `hostName`. Used for DERPMap nodes whose `CertName` differs from `HostName`.
        case named(String)
        /// Requires exactly one server certificate after excluding meta certificates (subject CN starts with `derpkey`). The lowercase hexadecimal
        /// SHA-256 of its entire DER must match this value exactly. The certificate must be currently valid and,
        /// if `hostName` is not an IP literal, valid for that name. Skips chain verification. Used for DERPMap nodes with
        /// `CertName` set to `sha256-raw:<hex>` (a self-signed derper).
        case pinned(sha256Hex: String)
        /// Skips verification. Used only for DERPMap nodes with `InsecureForTests`.
        case noneForTests
    }

    // shortcut: skips fast-start (using the meta certificate's server key to avoid waiting for the upgrade response). Add it if
    // one round trip in DERP connection setup becomes a problem.
    public init(hostName: String, targets: [Target] = [.hostName], port: UInt16 = 443, verification: Verification = .system) {
        self.hostName = hostName
        self.targets = targets
        self.port = port
        self.verification = verification
    }
}
