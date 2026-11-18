import Foundation

/// The configuration needed to start a `TailnetNode`.
///
/// Contains an auth key, which is redacted in `description` and `dump`. Logging the configuration value as is does not
/// expose the secret. `docs/contracts/SwiftailEngine.md`, “Node API,” and `docs/contracts/SwiftailTunnel.md`, “Public
/// API.”
public struct NodeConfiguration: Sendable {
    /// The Tailscale control server (Go `ipn.DefaultControlURL`, `ipn/prefs.go`).
    public static let defaultControlURL: URL = {
        guard let url = URL(string: "https://controlplane.tailscale.com") else {
            preconditionFailure("The fixed control server URL is valid")
        }
        return url
    }()

    /// The directory for the identity file (`identity.json`). Must be a file URL. Two nodes in the same process cannot
    /// run with the same directory at the same time (`NodeError.stateDirectoryInUse`).
    ///
    /// **The directory must be protected against writes by other users.** The node reads its private keys (identity)
    /// and tailnet lock trust state here. Anyone who can write to this directory can replace the files and determine
    /// the node's identity and trust state. The library creates a missing directory with mode 0700 and does not check
    /// the owner or permissions of existing directories. Use an OS-protected location, such as the app sandbox
    /// container or an iOS app group container.
    public var stateDirectory: URL
    /// The node's hostname. The control server uses it to name the node. Must be nonempty.
    public var hostname: String
    /// The control server URL, using `http://` or `https://`.
    ///
    /// **`http://` does not authenticate the server.** With `https://`, TLS verifies the server certificate before
    /// receiving the control server's public key. With `http://`, the key arrives in plaintext. An on-path party can
    /// present its own key and impersonate the control server, gaining control of both registration (including the auth
    /// key) and the netmap. Use only for test and loopback servers.
    public var controlURL: URL
    /// The auth key. Used only for first registration and registration of a new node key. It is not saved.
    public var authKey: String?
    /// Registers as a node the control server deletes after prolonged inactivity.
    public var ephemeral: Bool

    public init(
        stateDirectory: URL,
        hostname: String,
        controlURL: URL = Self.defaultControlURL,
        authKey: String? = nil,
        ephemeral: Bool = false
    ) {
        self.stateDirectory = stateDirectory
        self.hostname = hostname
        self.controlURL = controlURL
        self.authKey = authKey
        self.ephemeral = ephemeral
    }

    /// Checks only what can be checked without creating files or sockets. The control client checks URL details (port
    /// range, user information, and so on) again in `run()`. That failure also reports `invalidConfiguration`. Messages
    /// omit paths and keys.
    func validate() throws(NodeError) {
        guard stateDirectory.isFileURL else { throw .invalidConfiguration("State directory must be a file URL") }
        guard let scheme = controlURL.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw .invalidConfiguration("Control server URL must use http:// or https://")
        }
        guard controlURL.host(percentEncoded: false)?.isEmpty == false else {
            throw .invalidConfiguration("Control server URL has no host")
        }
        guard !hostname.isEmpty else { throw .invalidConfiguration("Hostname is empty") }
    }
}

extension NodeConfiguration: CustomStringConvertible, CustomReflectable {
    /// Redacts the auth key.
    public var description: String {
        "NodeConfiguration(hostname: \(hostname), controlURL: \(controlURL), authKey: \(redactedAuthKey), ephemeral: \(ephemeral))"
    }

    /// `dump` bypasses `description`, so redact the auth key here too.
    public var customMirror: Mirror {
        Mirror(self, children: [
            "stateDirectory": stateDirectory,
            "hostname": hostname,
            "controlURL": controlURL,
            "authKey": redactedAuthKey,
            "ephemeral": ephemeral,
        ])
    }

    private var redactedAuthKey: String { authKey == nil ? "none" : "<redacted>" }
}
