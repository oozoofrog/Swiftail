import Foundation
import SwiftailBase

/// The body of `POST /machine/register`. Go `tailcfg.RegisterRequest`.
///
/// Registers a node key with the control server (initial registration or key rotation), waits for login completion (`followup`),
/// or logs out (with `expiry` in the past). Notes §4.1 covers the registration flow.
///
/// Fields without `omitempty` are sent even when empty. A zero key is `nodekey:000…`. An absent timestamp is
/// `0001-01-01T00:00:00Z`. Absent Hostinfo and signature are `null`. Device certificate signing (`SignatureType` and related fields) is unused.
/// `docs/protocol-notes/control-map.md` §3.1, §3.2 (origin: `RegisterRequest` in tailscale.com `tailcfg/tailcfg.go`).
public struct RegisterRequest: Encodable, Sendable {
    /// The level of protocol semantics the client understands (capability version).
    public var version: Int
    /// The node key to register.
    public var nodeKey: NodePublicKey
    /// The previous node key during rotation, or a zero key for initial registration.
    public var oldNodeKey: NodePublicKey
    /// This node's NL public key (tailnet lock). `ControlClient` always includes a nonzero key. Omission means a zero key.
    public var nlKey: NLPublicKey
    /// The credentials for auth key login. Omitted from JSON if absent.
    public var auth: RegisterResponseAuth?
    /// The requested key expiration time. `nil` defers to server policy. A timestamp in the past logs out.
    public var expiry: Date?
    /// The previous response's `AuthURL`. If nonempty, waits for a response until the user completes login.
    public var followup: String
    /// Node information. Sent populated because testcontrol reads `Hostname`.
    public var hostinfo: Hostinfo?
    /// Requests a node that the server removes after prolonged inactivity.
    public var ephemeral: Bool
    /// The tailnet lock signature for the new node key (canonical CBOR of the NKS). `null` if empty.
    public var nodeKeySignature: [UInt8]

    public init(
        version: Int = 148,
        nodeKey: NodePublicKey,
        oldNodeKey: NodePublicKey = .zero,
        nlKey: NLPublicKey = .zero,
        auth: RegisterResponseAuth? = nil,
        expiry: Date? = nil,
        followup: String = "",
        hostinfo: Hostinfo?,
        ephemeral: Bool = false,
        nodeKeySignature: [UInt8] = []
    ) {
        self.version = version
        self.nodeKey = nodeKey
        self.oldNodeKey = oldNodeKey
        self.nlKey = nlKey
        self.auth = auth
        self.expiry = expiry
        self.followup = followup
        self.hostinfo = hostinfo
        self.ephemeral = ephemeral
        self.nodeKeySignature = nodeKeySignature
    }

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case oldNodeKey = "OldNodeKey"
        case nlKey = "NLKey"
        case auth = "Auth"
        case expiry = "Expiry"
        case followup = "Followup"
        case hostinfo = "Hostinfo"
        case ephemeral = "Ephemeral"
        case nodeKeySignature = "NodeKeySignature"
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(nodeKey, forKey: .nodeKey)
        try container.encode(oldNodeKey, forKey: .oldNodeKey)
        try container.encode(nlKey, forKey: .nlKey)
        try container.encodeIfPresent(auth, forKey: .auth)
        try container.encodeTime(expiry, forKey: .expiry)
        try container.encode(followup, forKey: .followup)
        try container.encode(hostinfo, forKey: .hostinfo)
        try container.encodeUnlessEmpty(ephemeral, forKey: .ephemeral)
        try container.encodeBytesOrNull(nodeKeySignature, forKey: .nodeKeySignature)
    }
}

/// The credentials for a registration request. Go `tailcfg.RegisterResponseAuth`.
///
/// Used only for auth key login. If the auth key has tailnet lock material after `--TL`, include only the part before it
/// (notes §4.1, item 2). Omits the legacy Android-only `Oauth2Token`.
public struct RegisterResponseAuth: Encodable, Sendable {
    /// The auth key (`tskey-auth-…`). A secret that must stay out of logs.
    public var authKey: String

    public init(authKey: String) {
        self.authKey = authKey
    }

    private enum CodingKeys: String, CodingKey {
        case authKey = "AuthKey"
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeUnlessEmpty(authKey, forKey: .authKey)
    }
}

extension RegisterResponseAuth: CustomStringConvertible, CustomReflectable {
    /// Redacts the auth key so logging the request value as is does not leak the secret.
    public var description: String { "RegisterResponseAuth(authKey: <\(authKey.count) characters>)" }

    /// `dump` and `Mirror` also show only the length in place of the auth key. With `description` alone, `dump` exposes the stored properties as is.
    /// Dumping a `RegisterRequest` that contains this value also goes through this mirror.
    public var customMirror: Mirror {
        Mirror(self, children: ["authKey": "<\(authKey.count) characters>"])
    }
}
