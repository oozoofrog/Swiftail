/// 인증 키를 만들지 못한 까닭(계약 `docs/contracts/SwiftailPairing.md` 4절 K4·K6).
///
/// 연관 값에 비밀·토큰·키·서버 본문을 싣지 않는다. 오류를 그대로 로그에 찍어도 된다.
public enum AuthKeyIssueError: Error, Sendable, Equatable {
    /// OAuth 클라이언트의 `id`나 `secret`이 규칙에 맞지 않는다.
    case invalidClient
    /// 태그가 없거나 `tag:` 규칙에 맞지 않는 것이 있다.
    case invalidTags
    /// `lifetime`이 1초보다 짧다(초 단위로 버린 값이 0 이하).
    case invalidLifetime
    /// `baseURL`이 `https`가 아니거나(루프백의 `http`만 예외) 쿼리·조각·사용자 정보가 있다.
    case invalidBaseURL
    /// 토큰 요청이 거절됐다: 400·401이거나, 2xx인데 응답에 `error`가 있거나 `access_token`이 비었다. 클라이언트 ID나
    /// 비밀이 틀렸거나 지워진 클라이언트다.
    case clientRejected
    /// 키 요청이 401로 거절됐다. 받은 토큰이 받아들여지지 않았다.
    case unauthorized
    /// 키 요청이 403으로 거절됐다. 클라이언트에 `auth_keys` 쓰기 권한이 없거나 그 태그를 다룰 수 없다.
    case forbidden
    /// 그 밖의 HTTP 상태. 리다이렉트(3xx)는 따르지 않고 여기로 온다.
    case http(status: Int)
    /// 응답을 읽지 못했다. JSON이 아니거나, 필드가 없거나 모양이 틀렸거나, 본문이 64KiB를 넘었다.
    case invalidResponse
    /// 연결하지 못했거나 도중에 끊겼거나 요청 하나의 기한(15초)을 넘었다.
    case network
    /// 호출한 Task가 취소됐다.
    case cancelled
}
