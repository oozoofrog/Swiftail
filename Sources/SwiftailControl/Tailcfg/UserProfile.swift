/// A user's display information. Go `tailcfg.UserProfile`. Arrives in `UserProfiles` in a map response.
///
/// Deltas add or replace profiles by ID, with no removals (notes §4.3, item 7). WhoIs looks them up by a node's `user`.
/// `docs/protocol-notes/control-map.md` §3.7 (origin: `UserProfile` in tailscale.com `tailcfg/tailcfg.go`).
public struct UserProfile: Decodable, Sendable, Equatable {
    /// The user ID referenced by `Node.user` and `Node.sharer`.
    public internal(set) var id: Int64
    /// The login name (email format), for display.
    public internal(set) var loginName: String
    /// The display name.
    public internal(set) var displayName: String
    /// The profile photo URL, or an empty string if absent.
    public internal(set) var profilePicURL: String

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case loginName = "LoginName"
        case displayName = "DisplayName"
        case profilePicURL = "ProfilePicURL"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(Int64.self, forKey: .id) ?? 0
        loginName = try container.decodeIfPresent(String.self, forKey: .loginName) ?? ""
        displayName = try container.decodeIfPresent(String.self, forKey: .displayName) ?? ""
        profilePicURL = try container.decodeIfPresent(String.self, forKey: .profilePicURL) ?? ""
    }
}
