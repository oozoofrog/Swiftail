import Foundation

/// The response to `POST /machine/register`. Go `tailcfg.RegisterResponse`.
///
/// A nonempty `error` is a failure even with HTTP 200, and other fields are ignored. Otherwise,
/// branches in `nodeKeySignature` → `nodeKeyExpired` → `authURL` order (notes §4.1, items 3~5).
/// A `false` value for `machineAuthorized` is allowed. Device authorization follows the self `Node` in the map.
/// `docs/protocol-notes/control-map.md` §3.2 (origin: `RegisterResponse` in tailscale.com `tailcfg/tailcfg.go`).
public struct RegisterResponse: Decodable, Sendable, Equatable {
    /// The user who owns the node.
    public internal(set) var user: User
    /// The identity used to log in.
    public internal(set) var login: Login
    /// The node key has expired. Register again with a fresh key.
    public internal(set) var nodeKeyExpired: Bool
    /// Whether the device is authorized. Independent of registration success.
    public internal(set) var machineAuthorized: Bool
    /// A nonempty value is the URL where the user must complete login.
    public internal(set) var authURL: String
    /// A nonempty value requires re-signing the tailnet lock signature with the new key.
    public internal(set) var nodeKeySignature: [UInt8]
    /// A nonempty value explains why registration was rejected.
    public internal(set) var error: String

    private enum CodingKeys: String, CodingKey {
        case user = "User"
        case login = "Login"
        case nodeKeyExpired = "NodeKeyExpired"
        case machineAuthorized = "MachineAuthorized"
        case authURL = "AuthURL"
        case nodeKeySignature = "NodeKeySignature"
        case error = "Error"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        user = try container.decodeIfPresent(User.self, forKey: .user) ?? User()
        login = try container.decodeIfPresent(Login.self, forKey: .login) ?? Login()
        nodeKeyExpired = try container.decodeIfPresent(Bool.self, forKey: .nodeKeyExpired) ?? false
        machineAuthorized = try container.decodeIfPresent(Bool.self, forKey: .machineAuthorized) ?? false
        authURL = try container.decodeIfPresent(String.self, forKey: .authURL) ?? ""
        nodeKeySignature = try container.decodeBytesIfPresent(forKey: .nodeKeySignature) ?? []
        error = try container.decodeIfPresent(String.self, forKey: .error) ?? ""
    }
}

/// The user who owns the node. Go `tailcfg.User`. Arrives only in a registration response.
public struct User: Decodable, Sendable, Equatable {
    /// The user ID. `Node.User` and `UserProfile.ID` refer to the same value.
    public internal(set) var id: Int64
    /// The display name.
    public internal(set) var displayName: String
    /// The profile photo URL, or an empty string if absent.
    public internal(set) var profilePicURL: String
    /// The account creation time, or `nil` if unknown.
    public internal(set) var created: Date?

    init() {
        id = 0
        displayName = ""
        profilePicURL = ""
        created = nil
    }

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case displayName = "DisplayName"
        case profilePicURL = "ProfilePicURL"
        case created = "Created"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(Int64.self, forKey: .id) ?? 0
        displayName = try container.decodeIfPresent(String.self, forKey: .displayName) ?? ""
        profilePicURL = try container.decodeIfPresent(String.self, forKey: .profilePicURL) ?? ""
        created = try container.decodeTimeIfPresent(forKey: .created).flatMap(GoTime.nonZero)
    }
}

/// Information from the identity provider used for login. Go `tailcfg.Login`. Arrives only in a registration response.
public struct Login: Decodable, Sendable, Equatable {
    /// The login ID, unused by the client.
    public internal(set) var id: Int64
    /// The identity provider (for example, `"google"` or `"github"`).
    public internal(set) var provider: String
    /// The login name (email format).
    public internal(set) var loginName: String
    /// The display name supplied by the identity provider.
    public internal(set) var displayName: String
    /// The profile photo URL, or an empty string if absent.
    public internal(set) var profilePicURL: String

    init() {
        id = 0
        provider = ""
        loginName = ""
        displayName = ""
        profilePicURL = ""
    }

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case provider = "Provider"
        case loginName = "LoginName"
        case displayName = "DisplayName"
        case profilePicURL = "ProfilePicURL"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(Int64.self, forKey: .id) ?? 0
        provider = try container.decodeIfPresent(String.self, forKey: .provider) ?? ""
        loginName = try container.decodeIfPresent(String.self, forKey: .loginName) ?? ""
        displayName = try container.decodeIfPresent(String.self, forKey: .displayName) ?? ""
        profilePicURL = try container.decodeIfPresent(String.self, forKey: .profilePicURL) ?? ""
    }
}
