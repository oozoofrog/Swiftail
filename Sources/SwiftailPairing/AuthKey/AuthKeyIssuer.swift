import Foundation

/// OAuth 클라이언트로 Tailscale 관리 API에서 1회용 인증 키를 만든다(계약 `docs/contracts/SwiftailPairing.md` 4절).
///
/// 페어링 제안에 실어 보낼 키를 만드는 데 쓴다. 받는 쪽은 로그인 없이 그 키로 tailnet에 들어온다. 호출마다 토큰을 새로
/// 받고 쥐고 있지 않는다(K2). 발급은 드문 일이라 토큰을 아껴 둘 까닭이 없고, 쥐지 않으면 새어 나갈 곳도 없다.
/// 자격을 싣는 방식(머리·본문)도 기억하지 않고 호출마다 머리부터 묻는다.
/// 만든 키는 지우지 않는다. 쓰지 않은 키는 `lifetime`이 지나면 스스로 죽는다(K8).
///
/// ```swift
/// let issuer = try AuthKeyIssuer(client: TailscaleOAuthClient(
///     id: clientID, secret: clientSecret, tags: ["tag:example"]))
/// let issued = try await issuer.issue(lifetime: .seconds(600))
/// ```
public struct AuthKeyIssuer: Sendable {
    /// Tailscale 관리 API.
    public static let defaultBaseURL: URL = {
        guard let url = URL(string: "https://api.tailscale.com") else {
            preconditionFailure("고정된 관리 API URL은 올바른 URL이다")
        }
        return url
    }()

    private let client: TailscaleOAuthClient
    private let baseURL: URL
    private let transport: any AuthKeyTransport

    /// 클라이언트와 API 주소를 검사하고 담는다(K4). 아직 아무것도 보내지 않는다.
    ///
    /// - Parameters:
    ///   - client: OAuth 클라이언트와 키에 붙일 태그.
    ///   - baseURL: 관리 API의 주소. `https`여야 한다. 시험 서버를 위해 루프백 호스트(`127.0.0.1`, `::1`,
    ///     `localhost`)의 평문 `http`만 받는다.
    /// - Throws: `.invalidClient`, `.invalidTags`, `.invalidBaseURL`.
    public init(client: TailscaleOAuthClient, baseURL: URL = AuthKeyIssuer.defaultBaseURL) throws(AuthKeyIssueError) {
        try self.init(client: client, baseURL: baseURL, transport: URLSessionAuthKeyTransport())
    }

    /// 시험이 가짜 전송을 넣는 길.
    init(client: TailscaleOAuthClient, baseURL: URL, transport: any AuthKeyTransport) throws(AuthKeyIssueError) {
        try client.validate()
        guard Self.isAllowed(baseURL) else { throw .invalidBaseURL }
        self.client = client
        self.baseURL = baseURL
        self.transport = transport
    }

    /// 한 번만 쓸 수 있는 키 하나를 만든다(K1). 토큰 요청(한두 번)과 키 요청을 보낸다.
    ///
    /// 만든 키는 한 번만 쓰이고, 들어온 노드는 승인 없이 들어와 tailnet에 남는다(K3). 페어링에 필요한 값으로 고정해
    /// 매개변수로 두지 않는다.
    ///
    /// - Parameter lifetime: 키의 수명. 초 단위로 버린다. 제안의 수명과 같게 짧게 준다. 너무 길면 서버가
    ///   거절한다(`.http(status:)`).
    /// - Throws: `AuthKeyIssueError`. 1초보다 짧으면 아무것도 보내지 않고 `.invalidLifetime`. 어느 오류에도
    ///   비밀·토큰·키가 실리지 않는다.
    public func issue(lifetime: Duration) async throws(AuthKeyIssueError) -> IssuedAuthKey {
        let expirySeconds = try AuthKeyExchange.expirySeconds(for: lifetime)
        let token = try await accessToken()
        let request = AuthKeyExchange.keyRequest(baseURL: baseURL, token: token, tags: client.tags, expirySeconds: expirySeconds)
        return try AuthKeyExchange.issuedKey(from: await transport.send(request))
    }

    /// 토큰을 받는다. `x/oauth2`의 자동 감지처럼 머리 방식이 어떤 까닭으로든 실패하면 본문 방식으로 한 번 더 묻고,
    /// 그 결과로 분류한다(`internal/token.go` `RetrieveToken`). 취소만은 다시 묻지 않는다.
    private func accessToken() async throws(AuthKeyIssueError) -> String {
        do throws(AuthKeyIssueError) {
            let request = AuthKeyExchange.tokenRequest(baseURL: baseURL, client: client, style: .header)
            return try AuthKeyExchange.accessToken(from: await transport.send(request))
        } catch .cancelled {
            throw .cancelled
        } catch {
            let request = AuthKeyExchange.tokenRequest(baseURL: baseURL, client: client, style: .parameters)
            return try AuthKeyExchange.accessToken(from: await transport.send(request))
        }
    }

    /// `https`는 늘, 평문 `http`는 루프백 호스트일 때만. 사용자 정보·쿼리·조각은 받지 않는다: 경로를 뒤에 이을 base다.
    private static func isAllowed(_ url: URL) -> Bool {
        guard let host = url.host(), !host.isEmpty, url.user() == nil, url.password() == nil,
              url.query() == nil, url.fragment() == nil
        else { return false }
        switch url.scheme?.lowercased() {
        case "https": return true
        case "http": return ["127.0.0.1", "::1", "localhost"].contains(host.lowercased())
        default: return false
        }
    }
}

extension AuthKeyIssuer: CustomStringConvertible, CustomReflectable {
    /// 클라이언트 비밀을 가린다.
    public var description: String {
        "AuthKeyIssuer(client: \(client), baseURL: \(baseURL))"
    }

    /// `dump`도 가린 클라이언트만 보인다.
    public var customMirror: Mirror {
        Mirror(self, children: ["client": client, "baseURL": baseURL])
    }
}
