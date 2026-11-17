import Foundation

/// 관리 API와의 HTTP 왕복 하나. 가장자리(`URLSessionAuthKeyTransport`)와 시험(가짜 전송)이 구현한다.
///
/// 리다이렉트는 따르지 않고 3xx 응답을 그대로 돌려준다(계약 `docs/contracts/SwiftailPairing.md` 4절 K5).
/// 실패는 `.network`·`.invalidResponse`(본문 한도 초과)·`.cancelled`로만 던진다.
protocol AuthKeyTransport: Sendable {
    func send(_ request: AuthKeyHTTPRequest) async throws(AuthKeyIssueError) -> AuthKeyHTTPResponse
}

/// 관리 API에 보낼 `POST` 요청 하나. 두 요청 모두 `POST`다.
///
/// `authorization`이나 `body`에 비밀(클라이언트 자격이나 토큰)이 있다. 로그에 찍지 않는다.
struct AuthKeyHTTPRequest: Sendable, Equatable {
    var url: URL
    /// `Authorization` 머리 값 전체(`Basic …`, `Bearer …`). nil이면 싣지 않는다(자격을 본문에 싣는 토큰 요청).
    var authorization: String?
    var contentType: String
    var body: [UInt8]
}

/// 관리 API가 돌려준 응답. 이 절차는 상태와 본문만 읽는다.
struct AuthKeyHTTPResponse: Sendable, Equatable {
    var status: Int
    /// 한도까지만. 넘으면 전송이 `.invalidResponse`를 던진다.
    var body: [UInt8]
}
