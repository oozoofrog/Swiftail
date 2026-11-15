import Foundation

// ACME 자원 객체(RFC 8555 7.1)를 응답 본문에서 읽고, 요청 본문을 만든다.
//
// 읽기는 신뢰할 수 없는 입력의 경계다(계약 동작 X2): 본문이 64KiB를 넘거나, JSON이 아니거나, 필수 필드가 없거나,
// 모르는 `status`이거나, URL이 `isAcceptableURL`을 통과하지 못하거나, authorization이 8개를 넘으면 nil이다. 주문 절차는
// nil을 `unexpectedResponse`로 적는다. 모르는 필드는 무시한다. 읽기는 어떤 바이트로도 죽지 않는다.

/// 디렉터리(RFC 8555 7.1.1). 발급에 필요한 세 URL만 읽는다. `newAuthz`·`revokeCert`·`keyChange`·`renewalInfo`는
/// 쓰지 않는다(계약 1절 제외 표). Go도 `newOrder`가 없으면 실패한다(`tempfork/acme/acme.go:199-201`).
struct ACMEDirectory: Sendable, Equatable {
    let newNonce: String
    let newAccount: String
    let newOrder: String

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body),
              [wire.newNonce, wire.newAccount, wire.newOrder].allSatisfy(ACMEInputRules.isAcceptableURL)
        else { return nil }
        newNonce = wire.newNonce
        newAccount = wire.newAccount
        newOrder = wire.newOrder
    }

    private struct Wire: Decodable {
        let newNonce: String
        let newAccount: String
        let newOrder: String
    }
}

/// 계정 객체(RFC 8555 7.1.2)의 `status`. newAccount 응답의 본문이다.
enum ACMEAccountStatus: String, Sendable, Decodable {
    case valid, deactivated, revoked

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body) else { return nil }
        self = wire.status
    }

    private struct Wire: Decodable {
        let status: ACMEAccountStatus
    }
}

/// 식별자(RFC 8555 7.1.3·7.1.4). 이 구현이 요청하는 것은 `dns` 하나다.
struct ACMEIdentifier: Sendable, Hashable, Decodable {
    let type: String
    let value: String
}

/// 주문 객체(RFC 8555 7.1.3).
struct ACMEOrder: Sendable, Equatable {
    /// RFC 8555 7.1.6의 다섯 상태.
    enum Status: String, Sendable, Decodable {
        case pending, ready, processing, valid, invalid
    }

    let status: Status
    let identifiers: [ACMEIdentifier]
    /// authorization URL들. 식별자와 1:1이라는 보장도, 순서의 뜻도 없다(RFC 8555 7.1.3·7.4, 계약 동작 C5). 8개까지.
    let authorizations: [String]
    let finalize: String
    /// `valid`가 된 주문의 인증서 URL. 다른 상태에서는 없을 수 있다.
    let certificate: String?
    /// 주문이 실패했으면 그 문제 문서(RFC 8555 7.1.3).
    let error: ProblemDocument?

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body),
              wire.authorizations.count <= ACMEInputRules.maximumAuthorizationCount,
              wire.authorizations.allSatisfy(ACMEInputRules.isAcceptableURL),
              ACMEInputRules.isAcceptableURL(wire.finalize),
              wire.certificate.map(ACMEInputRules.isAcceptableURL) ?? true
        else { return nil }
        status = wire.status
        identifiers = wire.identifiers
        authorizations = wire.authorizations
        finalize = wire.finalize
        certificate = wire.certificate
        error = wire.error
    }

    private struct Wire: Decodable {
        let status: Status
        let identifiers: [ACMEIdentifier]
        let authorizations: [String]
        let finalize: String
        let certificate: String?
        let error: ProblemDocument?
    }
}

/// authorization 객체(RFC 8555 7.1.4).
struct ACMEAuthorization: Sendable, Equatable {
    /// RFC 8555 7.1.6의 여섯 상태.
    enum Status: String, Sendable, Decodable {
        case pending, valid, invalid, deactivated, expired, revoked
    }

    let identifier: ACMEIdentifier
    let status: Status
    /// 와일드카드 이름의 authorization이면 참(RFC 8555 7.1.4). 없으면 거짓.
    let wildcard: Bool
    let challenges: [ACMEChallenge]

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body) else { return nil }
        identifier = wire.identifier
        status = wire.status
        wildcard = wire.wildcard ?? false
        challenges = wire.challenges
    }

    /// `type`이 `dns-01`인 첫 challenge(RFC 8555 8.4). 고른 challenge만 URL·token·상태를 검사한다.
    var dns01Challenge: ACMEChallenge? {
        challenges.first { $0.type == "dns-01" }
    }

    private struct Wire: Decodable {
        let identifier: ACMEIdentifier
        let status: Status
        let wildcard: Bool?
        let challenges: [ACMEChallenge]
    }
}

/// challenge 객체(RFC 8555 7.1.5, 8절). 종류마다 구조가 달라 `type` 밖의 필드는 모두 선택으로 읽고, 쓰는 challenge만
/// `validated`로 검사한다. 쓰지 않는 종류(http-01 등)의 모양 때문에 authorization 전체를 버리지 않기 위해서다.
struct ACMEChallenge: Sendable, Equatable, Decodable {
    /// RFC 8555 7.1.6의 네 상태.
    enum Status: String, Sendable {
        case pending, processing, valid, invalid
    }

    let type: String
    let url: String?
    let status: String?
    let token: String?
    let error: ProblemDocument?

    /// 검사를 통과한 DNS-01 challenge: URL은 `https`·2,048바이트 이하, token은 base64url 1~512바이트, 상태는 넷 중 하나.
    var validated: (url: String, token: String, status: Status)? {
        guard let url, ACMEInputRules.isAcceptableURL(url), let token, ACMEInputRules.isAcceptableToken(token),
              let status = status.flatMap(Status.init(rawValue:))
        else { return nil }
        return (url, token, status)
    }
}

/// 요청 본문(JWS의 payload) JSON. 값은 모두 이 구현이 만든 것이라 이스케이프할 문자가 없다.
enum ACMERequestBody {
    /// 계정 찾기(RFC 8555 7.3.1).
    static let findAccount = Array(#"{"onlyReturnExisting":true}"#.utf8)
    /// 계정 만들기(RFC 8555 7.3). 연락처는 보내지 않는다(계약 1절 제외 표). Go는 디렉터리에 약관 URL이 있을 때만 이
    /// 필드를 보내지만(`tempfork/acme/rfc8555.go:49-61`), 이 구현은 늘 보낸다: 약관이 없는 서버에는 뜻이 없는 필드다.
    static let createAccount = Array(#"{"termsOfServiceAgreed":true}"#.utf8)
    /// challenge 응답(RFC 8555 7.5.1). DNS-01은 응답 필드가 없다.
    static let respondToChallenge = Array("{}".utf8)
    /// POST-as-GET(RFC 8555 6.3): 빈 payload.
    static let postAsGet: [UInt8] = []

    /// 주문(RFC 8555 7.4). 이름 검사를 통과한 이름은 소문자·숫자·`-`·`.`뿐이다.
    static func newOrder(_ domain: CertificateDomain) -> [UInt8] {
        Array(#"{"identifiers":[{"type":"dns","value":"\#(domain.name)"}]}"#.utf8)
    }

    /// finalize(RFC 8555 7.4): CSR DER의 base64url.
    static func finalize(_ csr: CertificateSigningRequest) -> [UInt8] {
        Array(#"{"csr":"\#(Base64URL.encode(csr.der))"}"#.utf8)
    }
}

/// 64KiB 이하의 JSON 본문을 읽는다. 넘거나 형식이 틀리면 nil.
private func decodeJSON<T: Decodable>(_ type: T.Type, from body: [UInt8]) -> T? {
    guard body.count <= ACMEInputRules.maximumJSONByteCount else { return nil }
    return try? JSONDecoder().decode(type, from: Data(body))
}
