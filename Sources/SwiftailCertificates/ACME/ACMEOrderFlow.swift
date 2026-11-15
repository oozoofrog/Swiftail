import CryptoKit
import Foundation

/// 주문 절차 한 번의 결과.
///
/// 계정 URL은 계정 키를 가진 사람을 가리키므로 로그에 남기지 않는다(계약 동작 K2).
enum ACMEIssuanceResult: Sendable, Equatable {
    /// 발급됐다. `certificateChainPEM`은 인증서 URL의 응답 본문 그대로다(`application/pem-certificate-chain`, 256KiB
    /// 이하). 사슬의 해석과 검증(계약 동작 X3)은 받는 쪽의 몫이다. `accountURL`은 다음 시도에서 계정 찾기를 건너뛰는 데
    /// 쓸 수 있다(메모리에만 둔다. 계약 동작 C4).
    case issued(certificateChainPEM: [UInt8], accountURL: String)
    /// 실패했다. `retryNotBefore`는 ACME 서버가 `Retry-After`로 알려 준 시각 가운데 시도가 끝난 때보다 늦은 것(7일로
    /// 묶었다)이다. 그 전에는 그 서버에 요청을 보내지 않는다(계약 동작 X5). `accountURL`은 그 시도에서 알게 된 계정 URL이다.
    case failed(CertificateFailure, retryNotBefore: Date?, accountURL: String?)
}

/// ACME(RFC 8555) DNS-01 주문 절차 한 번. 소켓·시계·난수를 갖지 않는 값 타입 상태 기계다(plan 5절 코드 기준).
///
/// 절차는 "지금 할 일 하나"(`Step`)를 내고, 그 결과(응답과 받은 시각, 기다림이 끝난 시각, TXT를 올렸다는 알림)를 받아
/// 나아간다. 단계는 노트 4.3의 열두 단계와 계약 동작 C4~C7·C12, X1·X2·X4·X5다:
///
/// ```
/// directory → newNonce → newAccount(onlyReturnExisting, 없으면 약관 동의로 만듦) → newOrder
///   → 주문 상태로 가름: pending → authorization마다(valid 건너뜀, pending이면 dns-01의 TXT → challenge 응답)
///                         → 주문을 다시 읽어 ready를 기다림
///                     ready → finalize(CSR) → valid → 인증서 내려받기
///                     valid·processing(CSR 전) → 새 주문으로 한 번만 다시(계약 H17)
/// ```
///
/// - 모든 응답의 유효한 `Replay-Nonce`를 쥐고 다음 POST에 한 번 쓴다. 쥔 것이 없으면 `HEAD newNonce`로 얻는다
///   (RFC 8555 6.5·7.2). `badNonce`면 그 응답의 nonce로 같은 요청을 다시 서명해 보낸다. 요청마다 3번까지다(계약 X4).
/// - `Retry-After`(RFC 7231 7.1.3)가 알려 준 시각 전에는 어떤 요청도 내지 않고 `.wait(until:)`을 낸다. 그 시각이 발급
///   한 번의 기한(5분)을 넘으면 기다리지 않고 `timedOut`으로 끝내며 그 시각을 결과에 싣는다(계약 X5).
/// - 주문을 다시 읽는 간격은 `Retry-After`, 없거나 더 짧으면 1초다(Go `WaitOrder`와 같은 값. RFC의 상수가 아니다).
/// - 계정 키와 인증서 키는 받은 것을 쓴다. 인증서 키는 계정 키와 달라야 하고(RFC 8555 11.1) CSR은 처음 finalize할 때
///   한 번 만들어 그 시도가 끝날 때까지 쓴다(계약 C7: `ready`·`pending`의 되풀이도 같은 키·CSR).
///
/// 서명(JWS·CSR)은 CryptoKit이 안에서 난수를 뽑으므로 같은 입력이어도 요청 본문의 서명 바이트는 실행마다 다르다.
/// 개인 키를 쥐므로 `dump`·`description`에는 아무것도 드러내지 않는다.
struct ACMEOrderFlow: Sendable {
    /// 절차가 지금 바라는 일.
    enum Step: Sendable, Equatable {
        /// 이 요청을 지금 보내고 응답을 `receive(_:at:)`로, 전송의 실패를 `transportFailed(_:at:)`로 넘긴다.
        case send(ACMEHTTPRequest)
        /// 이 시각 전에는 요청하지 않는다. 그 시각이 지나면 `resume(at:)`을 부른다.
        case wait(until: Date)
        /// `name`(`_acme-challenge.<이름>`)의 TXT 레코드에 `value`를 올린다(제어 서버의 `set-dns`, 계약 동작 D). 끝나면
        /// `txtPublished(at:)`, 실패하면 `txtPublishingFailed(_:at:)`를 부른다. 값은 키 인가에서 나오므로 로그에 남기지 않는다.
        case publishTXT(name: String, value: String)
        /// 끝났다. 이 뒤의 입력은 모두 같은 결과를 돌려준다.
        case finished(ACMEIssuanceResult)
    }

    /// 발급 한 번의 기한(계약 동작 C10).
    static let attemptDuration: TimeInterval = 5 * 60
    /// 주문을 다시 읽는 최소 간격(계약 동작 X5).
    static let minimumPollInterval: TimeInterval = 1
    /// 요청 하나의 `badNonce` 재시도 상한(계약 한도 표).
    static let maximumBadNonceRetries = 3

    private let directoryURL: String
    private let domain: CertificateDomain
    private let accountKey: P256.Signing.PrivateKey
    private let certificateKey: P256.Signing.PrivateKey

    /// 아는 계정 URL(`kid`). 처음부터 주어졌거나 newAccount 응답의 `Location`에서 얻었다.
    private(set) var accountURL: String?

    private var deadline = Date.distantFuture
    private var directory: ACMEDirectory?
    /// 마지막 응답이 준 nonce. 보내는 요청에 한 번 쓰면 버린다(RFC 8555 6.5).
    private var nonce: String?
    /// 서버가 `Retry-After`로 알려 준 시각 가운데 가장 늦은 것. 그 전에는 어떤 요청도 보내지 않는다.
    private var serverNotBefore: Date?
    /// 다음 주문 읽기의 최소 시각(1초 간격).
    private var pollNotBefore: Date?
    /// 보내고 응답을 기다리는 요청.
    private var inFlight: Request?
    /// 기다림이나 nonce 얻기가 끝나면 보낼 요청.
    private var queued: Request?
    /// TXT를 올린 뒤에 보낼 challenge 응답. 올리는 중이 아니면 `awaitingPublication`이 거짓이다.
    private var challengeAfterPublication: Request?
    private var awaitingPublication = false
    private var badNonceRetries = 0
    private var ordersCreated = 0
    private var order: OrderState?
    private var csr: CertificateSigningRequest?
    private var result: ACMEIssuanceResult?

    /// - Parameters:
    ///   - directoryURL: ACME 디렉터리의 URL. `https`가 아니면 첫 단계가 `unexpectedResponse`로 끝난다(계약 X1).
    ///   - domain: 인증서를 받을 이름. 식별자 하나로 주문한다(계약 C5).
    ///   - accountKey: 계정 키. P-256만 쓴다(계약 C4).
    ///   - accountURL: 이미 아는 계정 URL. 주면 계정 찾기를 건너뛴다.
    ///   - certificateKey: 이 시도의 인증서 키. 계정 키와 다른, 새로 만든 키여야 한다(RFC 8555 11.1).
    init(
        directoryURL: String,
        domain: CertificateDomain,
        accountKey: P256.Signing.PrivateKey,
        accountURL: String?,
        certificateKey: P256.Signing.PrivateKey
    ) {
        self.directoryURL = directoryURL
        self.domain = domain
        self.accountKey = accountKey
        self.accountURL = accountURL.flatMap { ACMEInputRules.isAcceptableURL($0) ? $0 : nil }
        self.certificateKey = certificateKey
    }

    // MARK: 입력

    /// 절차를 시작한다. 기한(5분)은 이 시각부터 센다.
    mutating func start(at now: Date) -> Step {
        guard result == nil, inFlight == nil else { return misuse(at: now) }
        deadline = now.addingTimeInterval(Self.attemptDuration)
        guard ACMEInputRules.isAcceptableURL(directoryURL) else { return fail(.unexpectedResponse, at: now) }
        return request(.directory, at: now)
    }

    /// `.send`의 응답을 받았다.
    mutating func receive(_ response: ACMEHTTPResponse, at now: Date) -> Step {
        if let result { return .finished(result) }
        guard let request = inFlight else { return misuse(at: now) }
        inFlight = nil

        // 성공이든 오류든 모든 응답의 nonce를 쓴다(RFC 8555 6.5). 형식이 틀린 값은 무시한다(6.5.1).
        if let value = response.firstHeader(named: "Replay-Nonce"), ACMEInputRules.isAcceptableNonce(value) {
            nonce = value
        }
        let retryAfter = response.firstHeader(named: "Retry-After").flatMap { RetryAfter.date(from: $0, receivedAt: now) }
        if let retryAfter {
            serverNotBefore = max(serverNotBefore ?? retryAfter, retryAfter)
        }
        guard now < deadline else { return fail(.timedOut, at: now) }

        guard (200..<300).contains(response.status) else {
            return handleError(response, retryAfter: retryAfter, for: request, at: now)
        }
        if request != .newNonce {
            badNonceRetries = 0
        }
        return handleSuccess(response, for: request, at: now)
    }

    /// `.send`의 요청이 응답을 받지 못했다.
    mutating func transportFailed(_ error: ACMETransportError, at now: Date) -> Step {
        if let result { return .finished(result) }
        guard inFlight != nil else { return misuse(at: now) }
        inFlight = nil
        switch error {
        case .network: return fail(.network("ACME server unreachable"), at: now)
        case .timedOut: return fail(.timedOut, at: now)
        case .responseTooLarge, .invalidURL: return fail(.unexpectedResponse, at: now)
        }
    }

    /// `.wait(until:)`의 시각이 지났다.
    mutating func resume(at now: Date) -> Step {
        if let result { return .finished(result) }
        guard inFlight == nil, let queued else { return misuse(at: now) }
        self.queued = nil
        return request(queued, at: now)
    }

    /// `.publishTXT`의 레코드를 올렸다.
    mutating func txtPublished(at now: Date) -> Step {
        if let result { return .finished(result) }
        guard awaitingPublication else { return misuse(at: now) }
        awaitingPublication = false
        guard now < deadline else { return fail(.timedOut, at: now) }
        if let challenge = challengeAfterPublication {
            challengeAfterPublication = nil
            return request(challenge, at: now)
        }
        return nextAuthorization(at: now)
    }

    /// `.publishTXT`의 레코드를 올리지 못했다. 그 실패로 시도를 끝낸다.
    mutating func txtPublishingFailed(_ failure: CertificateFailure, at now: Date) -> Step {
        if let result { return .finished(result) }
        guard awaitingPublication else { return misuse(at: now) }
        awaitingPublication = false
        return fail(failure, at: now)
    }

    // MARK: 요청

    /// 절차가 보내는 요청의 종류. POST는 모두 JWS로 서명한다.
    private enum Request: Sendable, Equatable {
        case directory
        case newNonce
        case findAccount
        case createAccount
        case newOrder
        case authorization(String)
        case challenge(String)
        case order(OrderRead)
        case finalize
        case certificate(String)
        /// `invalid`가 된 주문의 authorization을 다시 읽어 실패의 종류를 가린다(계약 C7).
        case diagnosis(String)
    }

    /// 주문을 다시 읽는 까닭. 같은 상태라도 까닭에 따라 갈래가 다르다(계약 C7).
    private enum OrderRead: Sendable, Equatable {
        /// authorization을 처리한 뒤 `ready`를 기다린다.
        case awaitingReady
        /// finalize가 받아들여진 뒤 `valid`를 기다린다.
        case awaitingIssuance
        /// finalize가 `orderNotReady`로 거절됐다.
        case afterOrderNotReady
    }

    /// 지금 이 주문에서 아는 것.
    private struct OrderState: Sendable {
        let url: String
        var finalizeURL: String
        var authorizations: [String]
        var certificateURL: String?
        var error: ProblemDocument?
        /// finalize가 200으로 받아들여졌다. 그 뒤의 `valid`는 이 시도의 키·CSR로 발급된 것이다.
        var finalizeAccepted = false
        /// finalize 뒤 `ready`·`pending`의 되풀이를 이미 했다(주문마다 한 번. 계약 H17).
        var repeated = false
        var remainingAuthorizations: [String] = []
        var remainingDiagnoses: [String] = []
    }

    /// 기한과 서버의 시각을 지키며 요청을 낸다. 서명할 요청인데 nonce가 없으면 먼저 `HEAD newNonce`를 낸다.
    private mutating func request(_ request: Request, at now: Date) -> Step {
        guard now < deadline else { return fail(.timedOut, at: now) }
        var notBefore = serverNotBefore
        if case .order = request, let pollNotBefore {
            notBefore = max(notBefore ?? pollNotBefore, pollNotBefore)
        }
        if let notBefore, notBefore > now {
            // 기한을 넘는 기다림은 하지 않는다. 서버가 알려 준 시각은 `fail`이 결과에 싣는다(계약 X5).
            guard notBefore < deadline else { return fail(.timedOut, at: now) }
            queued = request
            return .wait(until: notBefore)
        }
        if request != .directory, request != .newNonce, nonce == nil {
            queued = request
            return transmit(.newNonce, at: now)
        }
        return transmit(request, at: now)
    }

    private mutating func transmit(_ request: Request, at now: Date) -> Step {
        switch request {
        case .directory:
            inFlight = request
            return .send(ACMEHTTPRequest(method: .get, url: directoryURL, body: []))
        case .newNonce:
            guard let directory else { return fail(.unexpectedResponse, at: now) }
            inFlight = request
            return .send(ACMEHTTPRequest(method: .head, url: directory.newNonce, body: []))
        default:
            guard let nonce, let parts = signedParts(of: request) else { return fail(.unexpectedResponse, at: now) }
            let jws: JWS
            do {
                jws = try JWS(payload: parts.payload, url: parts.url, nonce: nonce, keyReference: parts.key, signedWith: accountKey)
            } catch {
                // shortcut: CryptoKit의 P-256 서명은 정상 키로 실패하지 않는다. `CertificateFailure`에 내부 오류의 종류가
                // 없어 `unexpectedResponse`로 적는다. 실제로 일어나면 종류를 더한다.
                return fail(.unexpectedResponse, at: now)
            }
            self.nonce = nil
            inFlight = request
            return .send(ACMEHTTPRequest(method: .post, url: parts.url, body: jws.flattenedJSON, accept: parts.accept))
        }
    }

    /// 서명할 요청의 URL, 본문, 키를 가리키는 방식, `Accept`.
    private mutating func signedParts(
        of request: Request
    ) -> (url: String, payload: [UInt8], key: JWS.KeyReference, accept: String?)? {
        guard let directory else { return nil }
        if request == .findAccount || request == .createAccount {
            // newAccount만 `jwk`로 서명한다(RFC 8555 6.2).
            let payload = request == .findAccount ? ACMERequestBody.findAccount : ACMERequestBody.createAccount
            return (directory.newAccount, payload, .publicKey, nil)
        }
        guard let accountURL else { return nil }
        let kid = JWS.KeyReference.accountURL(accountURL)
        switch request {
        case .newOrder:
            return (directory.newOrder, ACMERequestBody.newOrder(domain), kid, nil)
        case .authorization(let url), .diagnosis(let url):
            return (url, ACMERequestBody.postAsGet, kid, nil)
        case .challenge(let url):
            return (url, ACMERequestBody.respondToChallenge, kid, nil)
        case .order:
            guard let order else { return nil }
            return (order.url, ACMERequestBody.postAsGet, kid, nil)
        case .finalize:
            guard let order else { return nil }
            if csr == nil {
                csr = try? CertificateSigningRequest(domain: domain, signedWith: certificateKey)
            }
            guard let csr else { return nil }
            return (order.finalizeURL, ACMERequestBody.finalize(csr), kid, nil)
        case .certificate(let url):
            return (url, ACMERequestBody.postAsGet, kid, "application/pem-certificate-chain")
        case .directory, .newNonce, .findAccount, .createAccount:
            return nil
        }
    }

    // MARK: 응답

    /// 성공이 아닌 응답(RFC 8555 6.7, 계약 동작 C12).
    private mutating func handleError(
        _ response: ACMEHTTPResponse,
        retryAfter: Date?,
        for request: Request,
        at now: Date
    ) -> Step {
        let problem = ProblemDocument(responseBody: response.body)
        switch problem.kind {
        case .badNonce where badNonceRetries < Self.maximumBadNonceRetries:
            // 그 오류 응답의 nonce로 같은 요청을 다시 서명한다(RFC 8555 6.5 "MUST use the nonce provided in the error
            // response"). 응답에 유효한 nonce가 없으면 `request`가 newNonce부터 얻는다.
            badNonceRetries += 1
            return self.request(request, at: now)
        case .accountDoesNotExist where request == .findAccount:
            return self.request(.createAccount, at: now)
        case .orderNotReady where request == .finalize:
            // RFC 8555 7.4: 주문을 POST-as-GET으로 읽어 그 상태로 간다.
            return self.request(.order(.afterOrderNotReady), at: now)
        case .rateLimited:
            return fail(.rateLimited(retryAfter: retryAfter), at: now)
        default:
            return fail(.acme(status: response.status, type: problem.type), at: now)
        }
    }

    private mutating func handleSuccess(_ response: ACMEHTTPResponse, for request: Request, at now: Date) -> Step {
        switch request {
        case .directory:
            guard response.status == 200, let directory = ACMEDirectory(body: response.body) else { return unexpected(at: now) }
            self.directory = directory
            return self.request(accountURL == nil ? .findAccount : .newOrder, at: now)

        case .newNonce:
            // RFC 8555 7.2: HEAD는 200을 SHOULD로, GET은 204다. 응답의 nonce는 `receive`가 이미 쥐었다.
            guard response.status == 200 || response.status == 204, nonce != nil, let queued else { return unexpected(at: now) }
            self.queued = nil
            return self.request(queued, at: now)

        case .findAccount, .createAccount:
            // 계정 찾기는 200(RFC 8555 7.3.1), 만들기는 201 또는 이미 있으면 200(7.3). 둘 다 `Location`이 계정 URL이다.
            let accepted = request == .findAccount ? [200] : [200, 201]
            guard accepted.contains(response.status),
                  let location = response.firstHeader(named: "Location"), ACMEInputRules.isAcceptableURL(location),
                  let status = ACMEAccountStatus(body: response.body)
            else { return unexpected(at: now) }
            // shortcut: `valid`가 아닌 계정(`deactivated`·`revoked`)에 맞는 실패 종류가 계약에 없어 `unexpectedResponse`로
            // 적는다. 그런 계정은 서버가 보통 `unauthorized`로 거절하므로(RFC 8555 7.3.6) 이 갈래는 드물다.
            guard status == .valid else { return unexpected(at: now) }
            accountURL = location
            return self.request(.newOrder, at: now)

        case .newOrder:
            // RFC 8555 7.4: 201과 `Location`의 주문 URL.
            guard response.status == 201,
                  let location = response.firstHeader(named: "Location"), ACMEInputRules.isAcceptableURL(location),
                  let created = ACMEOrder(body: response.body)
            else { return unexpected(at: now) }
            ordersCreated += 1
            order = OrderState(url: location, finalizeURL: created.finalize, authorizations: created.authorizations)
            return handleOrder(created, context: .created, at: now)

        case .authorization:
            guard response.status == 200, let authorization = ACMEAuthorization(body: response.body) else {
                return unexpected(at: now)
            }
            return handleAuthorization(authorization, at: now)

        case .challenge:
            // RFC 8555 7.5.1은 200이고, Let's Encrypt는 202를 보낸 적이 있다(Go `tempfork/acme/acme.go:570-573`).
            guard response.status == 200 || response.status == 202 else { return unexpected(at: now) }
            return nextAuthorization(at: now)

        case .order(let reason):
            guard response.status == 200, let current = ACMEOrder(body: response.body) else { return unexpected(at: now) }
            let context: OrderContext = switch reason {
            case .awaitingReady: .awaitingReady
            case .awaitingIssuance: .awaitingIssuance
            case .afterOrderNotReady: .afterOrderNotReady
            }
            return handleOrder(current, context: context, at: now)

        case .finalize:
            // RFC 8555 7.4: 200과 갱신된 주문 객체.
            guard response.status == 200, let current = ACMEOrder(body: response.body) else { return unexpected(at: now) }
            order?.finalizeAccepted = true
            return handleOrder(current, context: .awaitingIssuance, at: now)

        case .certificate:
            guard response.status == 200, response.body.count <= ACMEInputRules.maximumCertificateChainByteCount,
                  let accountURL
            else { return unexpected(at: now) }
            let issued = ACMEIssuanceResult.issued(certificateChainPEM: response.body, accountURL: accountURL)
            result = issued
            return .finished(issued)

        case .diagnosis:
            guard response.status == 200, let authorization = ACMEAuthorization(body: response.body),
                  isRequestedIdentifier(authorization)
            else { return unexpected(at: now) }
            if authorization.status == .invalid {
                return fail(.validationFailed(type: Self.validationErrorType(authorization)), at: now)
            }
            return nextDiagnosis(at: now)
        }
    }

    // MARK: 주문

    /// 주문 객체를 받은 자리. 상태의 뜻이 자리마다 다르다(계약 C5·C7).
    private enum OrderContext {
        /// newOrder의 응답.
        case created
        /// authorization을 처리한 뒤 다시 읽었다.
        case awaitingReady
        /// finalize의 응답이거나 그 뒤에 다시 읽었다.
        case awaitingIssuance
        /// finalize가 `orderNotReady`로 거절된 뒤 다시 읽었다.
        case afterOrderNotReady
    }

    /// 주문의 상태로 다음 일을 고른다.
    ///
    /// | 상태 | created | awaitingReady | awaitingIssuance | afterOrderNotReady |
    /// | --- | --- | --- | --- | --- |
    /// | pending | authorization 처리 | 다시 읽기 | 되풀이 → authorization 처리 | 되풀이 → authorization 처리 |
    /// | ready | finalize | finalize | 되풀이 → 같은 CSR로 finalize | 되풀이 → 같은 CSR로 finalize |
    /// | processing | 새 주문 | finalize가 받아들여졌으면 다시 읽기, 아니면 새 주문 | 다시 읽기 | 새 주문 |
    /// | valid | 새 주문 | finalize가 받아들여졌으면 내려받기, 아니면 새 주문 | 내려받기 | 새 주문 |
    /// | invalid | `orderFailed` | 실패의 종류를 가림 | 실패의 종류를 가림 | 실패의 종류를 가림 |
    ///
    /// "새 주문"은 CSR을 보내기 전에 `valid`·`processing`이 된 주문이다: 대응하는 개인 키가 없으므로 그 인증서를 받지
    /// 않는다(한 시도에 한 번, 계약 H17). "되풀이"는 주문마다 한 번이고 두 번째는 `unexpectedResponse`다(H17).
    private mutating func handleOrder(_ current: ACMEOrder, context: OrderContext, at now: Date) -> Step {
        // 응답의 식별자가 요청한 집합과 같아야 한다(RFC 8555 7.4, 계약 C5).
        guard Set(current.identifiers) == [requestedIdentifier], var state = order else { return unexpected(at: now) }
        state.finalizeURL = current.finalize
        state.authorizations = current.authorizations
        state.certificateURL = current.certificate
        state.error = current.error
        order = state

        switch (current.status, context) {
        case (.invalid, .created):
            return fail(.orderFailed(type: current.error?.type ?? ""), at: now)
        case (.invalid, _):
            return diagnose(at: now)

        case (.pending, .created):
            return processAuthorizations(at: now)
        case (.pending, .awaitingReady):
            return poll(.awaitingReady, at: now)
        case (.pending, .awaitingIssuance), (.pending, .afterOrderNotReady):
            guard repeatOnce() else { return unexpected(at: now) }
            return processAuthorizations(at: now)

        case (.ready, .created), (.ready, .awaitingReady):
            return request(.finalize, at: now)
        case (.ready, .awaitingIssuance), (.ready, .afterOrderNotReady):
            guard repeatOnce() else { return unexpected(at: now) }
            return request(.finalize, at: now)

        case (.processing, .awaitingIssuance):
            return poll(.awaitingIssuance, at: now)
        case (.processing, .awaitingReady) where state.finalizeAccepted:
            return poll(.awaitingIssuance, at: now)
        case (.processing, _):
            return restart(at: now)

        case (.valid, .awaitingIssuance):
            return download(at: now)
        case (.valid, .awaitingReady) where state.finalizeAccepted:
            return download(at: now)
        case (.valid, _):
            return restart(at: now)
        }
    }

    private var requestedIdentifier: ACMEIdentifier {
        ACMEIdentifier(type: "dns", value: domain.name)
    }

    private mutating func repeatOnce() -> Bool {
        guard let state = order, !state.repeated else { return false }
        order?.repeated = true
        return true
    }

    /// 1초(또는 `Retry-After`) 뒤에 주문을 다시 읽는다.
    private mutating func poll(_ reason: OrderRead, at now: Date) -> Step {
        pollNotBefore = now.addingTimeInterval(Self.minimumPollInterval)
        return request(.order(reason), at: now)
    }

    /// CSR 전에 `valid`·`processing`이 된 주문을 버리고 새 주문을 한 번만 만든다(계약 H17).
    private mutating func restart(at now: Date) -> Step {
        guard ordersCreated < 2 else { return fail(.orderFailed(type: order?.error?.type ?? ""), at: now) }
        order = nil
        pollNotBefore = nil
        return request(.newOrder, at: now)
    }

    private mutating func download(at now: Date) -> Step {
        guard let url = order?.certificateURL else { return unexpected(at: now) }
        return request(.certificate(url), at: now)
    }

    // MARK: authorization

    /// 주문의 authorization을 모두, 차례 무관하게 처리한다(계약 C5).
    private mutating func processAuthorizations(at now: Date) -> Step {
        guard let authorizations = order?.authorizations, !authorizations.isEmpty else { return unexpected(at: now) }
        order?.remainingAuthorizations = authorizations
        return nextAuthorization(at: now)
    }

    /// 남은 authorization을 읽는다. 다 끝났으면 곧바로 주문을 다시 읽는다(Go와 같다. 노트 4.3 9).
    private mutating func nextAuthorization(at now: Date) -> Step {
        guard let url = order?.remainingAuthorizations.first else {
            pollNotBefore = nil
            return request(.order(.awaitingReady), at: now)
        }
        order?.remainingAuthorizations.removeFirst()
        return request(.authorization(url), at: now)
    }

    /// authorization 하나의 상태로 가른다(RFC 8555 7.1.4·7.1.6, 계약 C5).
    private mutating func handleAuthorization(_ authorization: ACMEAuthorization, at now: Date) -> Step {
        guard isRequestedIdentifier(authorization) else { return unexpected(at: now) }
        switch authorization.status {
        case .valid:
            return nextAuthorization(at: now)
        case .invalid:
            return fail(.validationFailed(type: Self.validationErrorType(authorization)), at: now)
        case .deactivated, .expired, .revoked:
            return fail(.orderFailed(type: order?.error?.type ?? ""), at: now)
        case .pending:
            guard let challenge = authorization.dns01Challenge?.validated else { return unexpected(at: now) }
            switch challenge.status {
            case .valid:
                return nextAuthorization(at: now)
            case .invalid:
                return fail(.validationFailed(type: authorization.dns01Challenge?.error?.type ?? ""), at: now)
            case .pending:
                // 레코드를 올린 뒤 challenge에 `{}`로 응답한다(RFC 8555 7.5.1).
                return publishTXT(token: challenge.token, thenRespondTo: .challenge(challenge.url))
            case .processing:
                // 서버가 이미 확인 중이다. 레코드만 올리고 응답은 다시 보내지 않는다(계약 C5).
                return publishTXT(token: challenge.token, thenRespondTo: nil)
            }
        }
    }

    /// `identifier.type`이 `dns`이고, 값이 요청한 이름이고, 와일드카드가 아니다(계약 C5).
    private func isRequestedIdentifier(_ authorization: ACMEAuthorization) -> Bool {
        authorization.identifier == requestedIdentifier && !authorization.wildcard
    }

    private mutating func publishTXT(token: String, thenRespondTo challenge: Request?) -> Step {
        awaitingPublication = true
        challengeAfterPublication = challenge
        let keyAuthorization = KeyAuthorization(token: token, accountKey: JWK(accountKey.publicKey))
        return .publishTXT(name: domain.challengeRecordName, value: keyAuthorization.dns01TXTValue)
    }

    /// `invalid`인 authorization의 실패 종류: dns-01 challenge의 `error`, 없으면 `error`가 있는 첫 challenge의 것.
    private static func validationErrorType(_ authorization: ACMEAuthorization) -> String {
        let failed = authorization.dns01Challenge?.error ?? authorization.challenges.lazy.compactMap(\.error).first
        return failed?.type ?? ""
    }

    // MARK: invalid 주문의 진단

    /// 주문의 `invalid`는 DNS 확인 실패만이 아니라 만료·CSR·발급의 거절일 수 있다. authorization을 한 번씩 다시 읽어
    /// `invalid`가 있으면 `validationFailed`, 없으면 `orderFailed`다(계약 C7).
    private mutating func diagnose(at now: Date) -> Step {
        let authorizations = order?.authorizations ?? []
        order?.remainingDiagnoses = authorizations
        return nextDiagnosis(at: now)
    }

    private mutating func nextDiagnosis(at now: Date) -> Step {
        guard let url = order?.remainingDiagnoses.first else {
            return fail(.orderFailed(type: order?.error?.type ?? ""), at: now)
        }
        order?.remainingDiagnoses.removeFirst()
        return request(.diagnosis(url), at: now)
    }

    // MARK: 끝

    private mutating func unexpected(at now: Date) -> Step {
        fail(.unexpectedResponse, at: now)
    }

    private mutating func fail(_ failure: CertificateFailure, at now: Date) -> Step {
        let retryNotBefore = serverNotBefore.flatMap { $0 > now ? $0 : nil }
        let failed = ACMEIssuanceResult.failed(failure, retryNotBefore: retryNotBefore, accountURL: accountURL)
        result = failed
        inFlight = nil
        queued = nil
        return .finished(failed)
    }

    /// 절차가 기다리지 않는 입력(보내지 않은 요청의 응답 등). 부르는 쪽의 잘못이지만 죽지 않고 시도를 끝낸다.
    private mutating func misuse(at now: Date) -> Step {
        if let result { return .finished(result) }
        return fail(.unexpectedResponse, at: now)
    }
}

extension ACMEOrderFlow: CustomReflectable {
    /// 계정 키·인증서 키, 계정 URL, nonce, 이름을 드러내지 않는다(계약 동작 K1·K2).
    var customMirror: Mirror {
        Mirror(self, children: [] as [Mirror.Child])
    }
}
