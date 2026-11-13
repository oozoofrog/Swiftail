/// 사용자의 표시 정보. Go `tailcfg.UserProfile`. 맵 응답의 `UserProfiles`로 온다.
///
/// 증분에서는 ID별로 더하거나 바꾸기만 하고 지우지 않는다(노트 4.3의 7). WhoIs가 노드의 `user`로 찾는다.
/// `docs/protocol-notes/control-map.md` 3.7 (출처: tailscale.com `tailcfg/tailcfg.go` `UserProfile`).
public struct UserProfile: Decodable, Sendable, Equatable {
    /// 사용자 ID. `Node.user`·`Node.sharer`가 가리킨다.
    public internal(set) var id: Int64
    /// 로그인 이름(메일 형태). 표시용이다.
    public internal(set) var loginName: String
    /// 표시 이름.
    public internal(set) var displayName: String
    /// 프로필 사진 URL. 없으면 빈 문자열.
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
