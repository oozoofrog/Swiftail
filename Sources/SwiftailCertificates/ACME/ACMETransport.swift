/// ACME 서버와의 HTTP 왕복 하나. 가장자리(`URLSession`)와 시험(가짜 서버)이 구현한다.
///
/// 주문 절차(`ACMEOrderFlow`)는 이 프로토콜을 모른다. 구동 함수(`issueCertificate`)가 절차가 낸 요청을 여기로
/// 보내고 받은 응답을 절차에 넘긴다. 리다이렉트는 따르지 않고 3xx 응답을 그대로 돌려준다(계약 동작 X1).
protocol ACMETransport: Sendable {
    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse
}

/// ACME 서버에 보낼 HTTP 요청 하나.
struct ACMEHTTPRequest: Sendable, Equatable {
    enum Method: Sendable, Equatable { case get, head, post }
    var method: Method
    /// 서버가 준 URL 문자열 그대로(RFC 8555 6.4). POST이면 JWS의 `url` 머리와 같은 값이다.
    var url: String
    /// POST일 때만. Content-Type은 `application/jose+json`이다(RFC 8555 6.2). GET·HEAD는 빈 배열이다.
    var body: [UInt8]
    /// `Accept` 머리. nil이면 보내지 않는다. 인증서 내려받기만 `application/pem-certificate-chain`을 싣는다
    /// (RFC 8555 7.4.2, 계약 동작 C7).
    var accept: String? = nil
}

/// ACME 서버가 돌려준 HTTP 응답 하나.
struct ACMEHTTPResponse: Sendable, Equatable {
    struct Header: Sendable, Equatable {
        var name: String
        var value: String
    }

    var status: Int
    /// 받은 순서대로. 이름의 대소문자는 견줄 때 무시한다. 같은 이름이 여럿일 수 있다(Link).
    var headers: [Header]
    /// 한도까지만. 넘으면 전송이 오류를 던진다.
    var body: [UInt8]

    /// 그 이름의 첫 머리 값. 이름은 대소문자를 가리지 않는다(RFC 7230 3.2).
    func firstHeader(named name: String) -> String? {
        headers.first { $0.name.lowercased() == name.lowercased() }?.value
    }
}

/// 전송이 응답을 받지 못한 까닭. 연관 값이 없다: URL·본문을 싣지 않는다(계약 동작 K2·K3).
enum ACMETransportError: Error, Sendable, Equatable {
    /// 연결하지 못했거나 도중에 끊겼다. TLS 서버 검증의 실패도 여기다.
    case network
    /// 요청 하나의 기한(30초, 계약 동작 C10)을 넘었다.
    case timedOut
    /// 응답 본문이 전송의 한도를 넘었다.
    case responseTooLarge
    /// URL을 해석하지 못했거나 전송이 허용하지 않는 스킴이다.
    case invalidURL
}
