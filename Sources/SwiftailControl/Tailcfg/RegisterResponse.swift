import Foundation

/// `POST /machine/register`의 응답. Go `tailcfg.RegisterResponse`.
///
/// HTTP 200이어도 `error`가 비어 있지 않으면 실패이고 다른 필드는 보지 않는다. 그다음
/// `nodeKeySignature` → `nodeKeyExpired` → `authURL` 순으로 분기한다(노트 4.1의 3~5).
/// `machineAuthorized`가 `false`인 것은 실패가 아니다. 기기 승인 상태는 맵의 self `Node`를 따른다.
/// `docs/protocol-notes/control-map.md` 3.2 (출처: tailscale.com `tailcfg/tailcfg.go` `RegisterResponse`).
public struct RegisterResponse: Decodable, Sendable, Equatable {
    /// 노드를 소유한 사용자.
    public internal(set) var user: User
    /// 로그인에 쓴 신원.
    public internal(set) var login: Login
    /// 노드 키가 만료되었다. 새 키로 다시 등록해야 한다.
    public internal(set) var nodeKeyExpired: Bool
    /// 기기가 승인되었는지. 등록 성공 여부가 아니다.
    public internal(set) var machineAuthorized: Bool
    /// 비어 있지 않으면 사용자가 이 URL에서 로그인을 마쳐야 한다.
    public internal(set) var authURL: String
    /// 비어 있지 않으면 tailnet lock 서명을 새 키로 다시 서명해야 한다.
    public internal(set) var nodeKeySignature: [UInt8]
    /// 비어 있지 않으면 등록이 거절된 이유.
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

/// 노드를 소유한 사용자. Go `tailcfg.User`. 등록 응답에서만 온다.
public struct User: Decodable, Sendable, Equatable {
    /// 사용자 ID. `Node.User`와 `UserProfile.ID`가 같은 값을 가리킨다.
    public internal(set) var id: Int64
    /// 표시 이름.
    public internal(set) var displayName: String
    /// 프로필 사진 URL. 없으면 빈 문자열.
    public internal(set) var profilePicURL: String
    /// 계정을 만든 시각. 모르면 `nil`.
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

/// 로그인에 쓴 신원 공급자 쪽 정보. Go `tailcfg.Login`. 등록 응답에서만 온다.
public struct Login: Decodable, Sendable, Equatable {
    /// 로그인 ID. 클라이언트는 쓰지 않는다.
    public internal(set) var id: Int64
    /// 신원 공급자(`"google"`, `"github"` 등).
    public internal(set) var provider: String
    /// 로그인 이름(메일 형태).
    public internal(set) var loginName: String
    /// 신원 공급자가 준 표시 이름.
    public internal(set) var displayName: String
    /// 프로필 사진 URL. 없으면 빈 문자열.
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
