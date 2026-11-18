import CryptoKit
import Foundation

/// The result of one order flow.
///
/// The account URL identifies the person holding the account key, so it is kept out of logs (contract behavior K2).
enum ACMEIssuanceResult: Sendable, Equatable {
    /// Issuance succeeded. `certificateChainPEM` is the unmodified response body from the certificate URL (`application/pem-certificate-chain`,
    /// up to 256KiB). The recipient parses and verifies the chain (contract behavior X3). The caller can use `accountURL` to skip account lookup
    /// on the next attempt (keep it in memory only, contract behavior C4).
    case issued(certificateChainPEM: [UInt8], accountURL: String)
    /// Issuance failed. `retryNotBefore` is the time the ACME server announced via `Retry-After`, if later than the end of the attempt (capped
    /// at 7 days). No requests go to that server before then (contract behavior X5). `accountURL` is the account URL learned during the attempt.
    case failed(CertificateFailure, retryNotBefore: Date?, accountURL: String?)
}

/// A single ACME (RFC 8555) DNS-01 order flow. This value-type state machine owns no sockets, clock, or randomness (plan §5, Code Standards).
///
/// The flow emits one action to take now (`Step`) and advances when it receives the result (a response and its receipt time,
/// the end time of a wait, or confirmation that a TXT record was published). The stages follow the twelve steps in notes §4.3 and contract behaviors C4–C7, C12, X1, X2, X4, and X5.
///
/// ```
/// directory → newNonce → newAccount(onlyReturnExisting, or create with terms accepted if absent) → newOrder
///   → branch by order status: pending → for each authorization (skip valid, publish the dns-01 TXT and answer the challenge if pending)
///                         → poll the order until ready
///                     ready → finalize(CSR) → valid → download the certificate
///                     valid or processing (before CSR) → try again with a new order just once (contract H17)
/// ```
///
/// - Keep the valid `Replay-Nonce` from each response and use it once on the next POST. If none is available, fetch one with `HEAD newNonce`
///   (RFC 8555 6.5 and 7.2). On `badNonce`, re-sign the same request with the response nonce and send it again, up to 3 times per request (contract X4).
/// - Emit `.wait(until:)` and withhold all requests until the time given by `Retry-After` (RFC 7231 7.1.3). If the time exceeds the
///   deadline for one issuance attempt (5 minutes), finish immediately with `timedOut` and include that time in the result (contract X5).
/// - Poll the order at the `Retry-After` interval, with a 1-second minimum and a 1-second default (the same value as Go's `WaitOrder`, which the RFC does not specify).
/// - Use the supplied account and certificate keys. The certificate key must differ from the account key (RFC 8555 11.1). Create the CSR
///   on the first finalize and reuse it through the end of the attempt (contract C7, including the same key and CSR on repeated `ready` or `pending`).
///
/// CryptoKit draws randomness internally for JWS and CSR signatures, so signature bytes in request bodies vary across runs even with identical inputs.
/// Because the flow holds private keys, it exposes nothing through `dump` or `description`.
struct ACMEOrderFlow: Sendable {
    /// The action the flow needs now.
    enum Step: Sendable, Equatable {
        /// Send this request now and pass the response to `receive(_:at:)` or a transport failure to `transportFailed(_:at:)`.
        case send(ACMEHTTPRequest)
        /// Withhold requests until this time, then call `resume(at:)`.
        case wait(until: Date)
        /// Publish `value` in the TXT record at `name` (`_acme-challenge.<name>`) using the control server's `set-dns` (contract behavior D).
        /// Call `txtPublished(at:)` on completion or `txtPublishingFailed(_:at:)` on failure. Keep the value out of logs because it comes from the key authorization.
        case publishTXT(name: String, value: String)
        /// The flow has finished. All subsequent inputs return the same result.
        case finished(ACMEIssuanceResult)
    }

    /// The deadline for one issuance attempt (contract behavior C10).
    static let attemptDuration: TimeInterval = 5 * 60
    /// The minimum interval between order polls (contract behavior X5).
    static let minimumPollInterval: TimeInterval = 1
    /// The maximum number of `badNonce` retries per request (contract limits table).
    static let maximumBadNonceRetries = 3

    private let directoryURL: String
    private let domain: CertificateDomain
    private let accountKey: P256.Signing.PrivateKey
    private let certificateKey: P256.Signing.PrivateKey

    /// The known account URL (`kid`), supplied at the start or obtained from the newAccount response's `Location`.
    private(set) var accountURL: String?

    private var deadline = Date.distantFuture
    private var directory: ACMEDirectory?
    /// The nonce from the last response. Discard it after using it in one outgoing request (RFC 8555 6.5).
    private var nonce: String?
    /// The latest time the server announced via `Retry-After`. No requests go out before this time.
    private var serverNotBefore: Date?
    /// The earliest time to poll the order again (1-second interval).
    private var pollNotBefore: Date?
    /// The request that was sent and is awaiting a response.
    private var inFlight: Request?
    /// The request to send after waiting or obtaining a nonce.
    private var queued: Request?
    /// The challenge response to send after publishing the TXT record. `awaitingPublication` is false when no publication is in progress.
    private var challengeAfterPublication: Request?
    private var awaitingPublication = false
    private var badNonceRetries = 0
    private var ordersCreated = 0
    private var order: OrderState?
    private var csr: CertificateSigningRequest?
    private var result: ACMEIssuanceResult?

    /// - Parameters:
    ///   - directoryURL: The ACME directory URL. A scheme other than `https` ends the first step with `unexpectedResponse` (contract X1).
    ///   - domain: The name to obtain a certificate for. The order uses one identifier (contract C5).
    ///   - accountKey: The account key. Only P-256 is used (contract C4).
    ///   - accountURL: An already known account URL. Supplying it skips account lookup.
    ///   - certificateKey: The certificate key for this attempt. It must be freshly generated and differ from the account key (RFC 8555 11.1).
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

    // MARK: Input

    /// Starts the flow. The deadline (5 minutes) starts at this time.
    mutating func start(at now: Date) -> Step {
        guard result == nil, inFlight == nil, deadline == .distantFuture else { return misuse(at: now) }
        deadline = now.addingTimeInterval(Self.attemptDuration)
        guard ACMEInputRules.isAcceptableURL(directoryURL) else { return fail(.unexpectedResponse, at: now) }
        return request(.directory, at: now)
    }

    /// Processes the response to `.send`.
    mutating func receive(_ response: ACMEHTTPResponse, at now: Date) -> Step {
        if let result { return .finished(result) }
        guard let request = inFlight else { return misuse(at: now) }
        inFlight = nil

        // Use the nonce from every response, whether success or error (RFC 8555 6.5). Ignore malformed values (6.5.1).
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

    /// Handles a `.send` request that received no response.
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

    /// Resumes after the time in `.wait(until:)` has passed.
    mutating func resume(at now: Date) -> Step {
        if let result { return .finished(result) }
        guard inFlight == nil, let queued else { return misuse(at: now) }
        self.queued = nil
        return request(queued, at: now)
    }

    /// Records successful publication of the `.publishTXT` record.
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

    /// Handles failure to publish the `.publishTXT` record. Ends the attempt with that failure.
    mutating func txtPublishingFailed(_ failure: CertificateFailure, at now: Date) -> Step {
        if let result { return .finished(result) }
        guard awaitingPublication else { return misuse(at: now) }
        awaitingPublication = false
        return fail(failure, at: now)
    }

    // MARK: Requests

    /// The kinds of requests the flow sends. All POST requests are signed with JWS.
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
        /// Rereads the authorizations for an order that became `invalid` to classify the failure (contract C7).
        case diagnosis(String)
    }

    /// The reason for rereading the order. The branch depends on the reason even for identical statuses (contract C7).
    private enum OrderRead: Sendable, Equatable {
        /// Waits for `ready` after processing the authorizations.
        case awaitingReady
        /// Waits for `valid` after finalize was accepted.
        case awaitingIssuance
        /// Finalize was rejected with `orderNotReady`.
        case afterOrderNotReady
    }

    /// The information currently known about this order.
    private struct OrderState: Sendable {
        let url: String
        var finalizeURL: String
        var authorizations: [String]
        var certificateURL: String?
        var error: ProblemDocument?
        /// Finalize was accepted with 200. A subsequent `valid` means issuance used this attempt's key and CSR.
        var finalizeAccepted = false
        /// Already repeated the `ready` or `pending` step after finalize (once per order, contract H17).
        var repeated = false
        var remainingAuthorizations: [String] = []
        var remainingDiagnoses: [String] = []
    }

    /// Emits a request while honoring the deadline and the server's time. Emits `HEAD newNonce` first if a request needs signing and no nonce is available.
    private mutating func request(_ request: Request, at now: Date) -> Step {
        guard now < deadline else { return fail(.timedOut, at: now) }
        var notBefore = serverNotBefore
        if case .order = request, let pollNotBefore {
            notBefore = max(notBefore ?? pollNotBefore, pollNotBefore)
        }
        if let notBefore, notBefore > now {
            // Do not wait beyond the deadline. `fail` includes the server's time in the result (contract X5).
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
            guard let directory, ACMEInputRules.hasSameOrigin(directory.newNonce, as: directoryURL) else {
                return fail(.unexpectedResponse, at: now)
            }
            inFlight = request
            return .send(ACMEHTTPRequest(method: .head, url: directory.newNonce, body: []))
        default:
            guard let nonce, let parts = signedParts(of: request),
                  ACMEInputRules.hasSameOrigin(parts.url, as: directoryURL)
            else { return fail(.unexpectedResponse, at: now) }
            let jws: JWS
            do {
                jws = try JWS(payload: parts.payload, url: parts.url, nonce: nonce, keyReference: parts.key, signedWith: accountKey)
            } catch {
                // shortcut: CryptoKit's P-256 signing does not fail with a valid key. `CertificateFailure` has no internal error kind,
                // so report `unexpectedResponse`. Add a kind if this ever happens.
                return fail(.unexpectedResponse, at: now)
            }
            self.nonce = nil
            inFlight = request
            return .send(ACMEHTTPRequest(method: .post, url: parts.url, body: jws.flattenedJSON, accept: parts.accept))
        }
    }

    /// The URL, body, key reference method, and `Accept` for the request to sign.
    private mutating func signedParts(
        of request: Request
    ) -> (url: String, payload: [UInt8], key: JWS.KeyReference, accept: String?)? {
        guard let directory else { return nil }
        if request == .findAccount || request == .createAccount {
            // Only newAccount is signed with `jwk` (RFC 8555 6.2).
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

    // MARK: Responses

    /// Handles an unsuccessful response (RFC 8555 6.7, contract behavior C12).
    private mutating func handleError(
        _ response: ACMEHTTPResponse,
        retryAfter: Date?,
        for request: Request,
        at now: Date
    ) -> Step {
        let problem = ProblemDocument(responseBody: response.body)
        switch problem.kind {
        case .badNonce where badNonceRetries < Self.maximumBadNonceRetries:
            // Re-sign the same request with the nonce from the error response (RFC 8555 6.5 "MUST use the nonce provided in the error
            // response"). If the response lacks a valid nonce, `request` obtains one from newNonce first.
            badNonceRetries += 1
            return self.request(request, at: now)
        case .accountDoesNotExist where request == .findAccount:
            return self.request(.createAccount, at: now)
        case .orderNotReady where request == .finalize:
            // RFC 8555 7.4: Read the order with POST-as-GET and proceed according to its status.
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
            // RFC 8555 7.2: HEAD SHOULD return 200, and GET returns 204. `receive` already retained the response nonce.
            guard response.status == 200 || response.status == 204, nonce != nil, let queued else { return unexpected(at: now) }
            self.queued = nil
            return self.request(queued, at: now)

        case .findAccount, .createAccount:
            // Account lookup returns 200 (RFC 8555 7.3.1). Creation returns 201, or 200 if it already exists (7.3). In both cases `Location` is the account URL.
            let accepted = request == .findAccount ? [200] : [200, 201]
            guard accepted.contains(response.status),
                  let location = response.firstHeader(named: "Location"), ACMEInputRules.isAcceptableURL(location),
                  let status = ACMEAccountStatus(body: response.body)
            else { return unexpected(at: now) }
            // shortcut: The contract has no failure kind for a non-`valid` account (`deactivated` or `revoked`), so report
            // `unexpectedResponse`. This branch is rare because servers usually reject such accounts with `unauthorized` (RFC 8555 7.3.6).
            guard status == .valid else { return unexpected(at: now) }
            accountURL = location
            return self.request(.newOrder, at: now)

        case .newOrder:
            // RFC 8555 7.4: 201 with the order URL in `Location`.
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
            // RFC 8555 7.5.1 specifies 200. Let's Encrypt has also returned 202 (Go `tempfork/acme/acme.go:570-573`).
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
            // RFC 8555 7.4: 200 with the updated order object.
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

    // MARK: Order

    /// The context in which the order object was received. Each context interprets the status differently (contract C5 and C7).
    private enum OrderContext {
        /// The response to newOrder.
        case created
        /// Reread after processing the authorizations.
        case awaitingReady
        /// The response to finalize or a subsequent read.
        case awaitingIssuance
        /// Reread after finalize was rejected with `orderNotReady`.
        case afterOrderNotReady
    }

    /// Selects the next action based on the order status.
    ///
    /// | Status | created | awaitingReady | awaitingIssuance | afterOrderNotReady |
    /// | --- | --- | --- | --- | --- |
    /// | pending | Process authorizations | Reread | Repeat → process authorizations | Repeat → process authorizations |
    /// | ready | finalize | finalize | Repeat → finalize with the same CSR | Repeat → finalize with the same CSR |
    /// | processing | New order | Reread if finalize was accepted, otherwise new order | Reread | New order |
    /// | valid | New order | Download if finalize was accepted, otherwise new order | Download | New order |
    /// | invalid | `orderFailed` | Classify failure | Classify failure | Classify failure |
    ///
    /// "New order" applies to an order that became `valid` or `processing` before the CSR was sent. The corresponding private key is unavailable,
    /// so discard that order and create a new one at most once per attempt (contract H17). Allow one "repeat" per order and report `unexpectedResponse` on the second (H17).
    private mutating func handleOrder(_ current: ACMEOrder, context: OrderContext, at now: Date) -> Step {
        // The response identifiers must match the requested set (RFC 8555 7.4, contract C5).
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

    /// Rereads the order after 1 second (or `Retry-After`).
    private mutating func poll(_ reason: OrderRead, at now: Date) -> Step {
        pollNotBefore = now.addingTimeInterval(Self.minimumPollInterval)
        return request(.order(reason), at: now)
    }

    /// Discards an order that became `valid` or `processing` before the CSR and creates a new order just once (contract H17).
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

    /// Processes all authorizations for the order regardless of their sequence (contract C5).
    private mutating func processAuthorizations(at now: Date) -> Step {
        guard let authorizations = order?.authorizations, !authorizations.isEmpty else { return unexpected(at: now) }
        order?.remainingAuthorizations = authorizations
        return nextAuthorization(at: now)
    }

    /// Reads the remaining authorizations. Rereads the order immediately once they are done (same as Go, notes §4.3 step 9).
    private mutating func nextAuthorization(at now: Date) -> Step {
        guard let url = order?.remainingAuthorizations.first else {
            pollNotBefore = nil
            return request(.order(.awaitingReady), at: now)
        }
        order?.remainingAuthorizations.removeFirst()
        return request(.authorization(url), at: now)
    }

    /// Branches on the status of one authorization (RFC 8555 7.1.4 and 7.1.6, contract C5).
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
                // Respond to the challenge with `{}` after publishing the record (RFC 8555 7.5.1).
                return publishTXT(token: challenge.token, thenRespondTo: .challenge(challenge.url))
            case .processing:
                // The server is already validating. Publish the record and skip resending the response (contract C5).
                return publishTXT(token: challenge.token, thenRespondTo: nil)
            }
        }
    }

    /// Checks that `identifier.type` is `dns`, the value is the requested name, and the identifier is not a wildcard (contract C5).
    private func isRequestedIdentifier(_ authorization: ACMEAuthorization) -> Bool {
        authorization.identifier == requestedIdentifier && !authorization.wildcard
    }

    private mutating func publishTXT(token: String, thenRespondTo challenge: Request?) -> Step {
        awaitingPublication = true
        challengeAfterPublication = challenge
        let keyAuthorization = KeyAuthorization(token: token, accountKey: JWK(accountKey.publicKey))
        return .publishTXT(name: domain.challengeRecordName, value: keyAuthorization.dns01TXTValue)
    }

    /// The failure kind for an `invalid` authorization is the dns-01 challenge's `error` or, if absent, the `error` from the first challenge that has one.
    private static func validationErrorType(_ authorization: ACMEAuthorization) -> String {
        let failed = authorization.dns01Challenge?.error ?? authorization.challenges.lazy.compactMap(\.error).first
        return failed?.type ?? ""
    }

    // MARK: Diagnosing an invalid order

    /// An `invalid` order can mean failed DNS validation, expiration, or rejection of the CSR or issuance. Reread each authorization once.
    /// If any is `invalid`, report `validationFailed`. Otherwise, report `orderFailed` (contract C7).
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

    // MARK: Completion

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

    /// Handles input the flow is not waiting for (such as a response to a request it never sent). Ends the attempt without crashing on the caller's mistake.
    private mutating func misuse(at now: Date) -> Step {
        if let result { return .finished(result) }
        return fail(.unexpectedResponse, at: now)
    }
}

extension ACMEOrderFlow: CustomReflectable {
    /// Keeps account and certificate keys, the account URL, nonces, and names private (contract behaviors K1 and K2).
    var customMirror: Mirror {
        Mirror(self, children: [] as [Mirror.Child])
    }
}
