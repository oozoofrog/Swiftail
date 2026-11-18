import Foundation

/// An offer from the host. `PairingHost.openOffer(lifetime:authKey:)` creates it, and the joiner creates it from the received link or QR string
/// using `init(link:)`.
///
/// This holds a secret and an auth key, so `description` and `dump` redact them. Logging the value as is does not reveal them, but `url(base:)` and
/// `qrCode(base:)` produce outputs that contain the secret itself. Keep those outputs out of logs, analytics, and chat history. The type intentionally omits `Equatable`
/// because it would permit comparing secrets. See contract `docs/contracts/SwiftailPairing.md` §3.
public struct PairingOffer: Sendable {
    /// The host node's MagicDNS FQDN in lowercase and without a trailing dot (`rd-mac-1a2b3c4d.tail0001.ts.net`).
    public let host: String
    /// The tailnet port where the host accepts pairing connections.
    public let port: UInt16
    /// The offer expiration time in seconds. The joiner uses it for guidance only. The host rejects expired offers because clocks may differ (behavior O4).
    public let expires: Date
    /// A single-use tailnet auth key. If the joiner is outside the tailnet, set it once in the node configuration (`NodeConfiguration.authKey`).
    /// Do not store it.
    ///
    /// Starting a node with this key **joins the tailnet identified by this link**. The administrator of that tailnet can see this device's node
    /// and set policy. Links can come from anywhere, so the app shows this information and asks the user before starting a node
    /// with an offer that contains a key.
    ///
    /// The key is independent of pairing. Anyone who obtains the link can join the tailnet while the key is valid, regardless of the host's approval
    /// (`PairingHost.openOffer(lifetime:authKey:)`).
    public let authKey: String?
    /// The 32-byte offer secret. This is the pairing protocol's HMAC key and is not exposed to apps.
    package let secret: [UInt8]

    /// The secret length.
    static let secretLength = 32

    init(host: String, port: UInt16, expires: Date, authKey: String?, secret: [UInt8]) {
        self.host = host
        self.port = port
        self.expires = expires
        self.authKey = authKey
        self.secret = secret
    }
}

extension PairingOffer: CustomStringConvertible, CustomReflectable {
    /// Redacts the secret and auth key.
    public var description: String {
        "PairingOffer(host: \(host), port: \(port), expires: \(expires), authKey: \(redactedAuthKey), secret: <redacted>)"
    }

    /// `dump` bypasses `description`, so redact them here too.
    public var customMirror: Mirror {
        Mirror(self, children: [
            "host": host,
            "port": port,
            "expires": expires,
            "authKey": redactedAuthKey,
            "secret": "<redacted>",
        ])
    }

    private var redactedAuthKey: String { authKey == nil ? "none" : "<redacted>" }
}
