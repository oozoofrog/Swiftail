import CryptoKit
import Foundation

/// 등록: `POST /machine/register`로 node 키를 제어 서버에 올린다.
///
/// 1. 저장된 node 키가 있으면 그것으로, 없거나 바꿔야 하면(대화형 로그인, 만료) 새 후보 키로 요청한다.
///    키를 바꿀 때는 이전 키를 `OldNodeKey`에 넣는다. 인증 키가 있으면 등록 요청마다 `--TL` 앞부분만 보낸다
///    (Go와 같다. 키가 만료되어 새 키를 등록할 때도 재사용 인증 키로 스스로 인증된다).
/// 2. 응답은 `Error` → `NodeKeySignature` → `NodeKeyExpired` → `AuthURL` 순으로 본다.
/// 3. `AuthURL`이 오면 `loginRequired`를 내고, 같은 후보 키로 `Followup` 요청(긴 폴링)을 되풀이한다.
///    후보 키는 인증이 끝난 뒤에만 확정하고 저장한다. 그 전에 연결이 끊기면 다시 이은 뒤 같은 후보 키와 Followup
///    URL로 이어서 기다린다. 사용자가 보고 있는 URL은 그 후보 키에 묶여 있기 때문이다.
/// 4. 등록하는 동안 `startInteractiveLogin()`이 불리면, 이 등록이 끝나도 그 요청은 남는다(Go `authRoutine`의
///    `loginGoal == goal` 확인). 받은 키는 확정하지만 다음 연결에서 새 키로 다시 등록한다. 로그인을 기다리는
///    Followup 긴 폴링은 그 자리에서 그만두고 새 키로 다시 시작한다(사용자가 새 URL을 곧바로 받는다).
///
/// `docs/protocol-notes/control-map.md` 3.2, 4.1 (출처: tailscale.com `control/controlclient/direct.go`
/// `doLogin`, `auto.go` `authRoutine`, BSD-3-Clause).
extension ControlClient {
    /// 등록 응답 본문의 한도(1MiB). Go와 같다.
    static let maximumRegisterResponseSize = 1 << 20
    /// `registrationRejected`에 담는 서버 메시지의 한도(문자 수). Go가 HTTP 오류 본문을 자르는 길이와 같다.
    static let maximumRejectionLength = 200

    func register(over connection: ControlConnection) async throws {
        let loginRequest = loginRequests
        var attempt: PendingRegistration
        if let pendingRegistration {
            attempt = pendingRegistration
        } else if !rotateNodeKey, let nodeKey = identity.nodeKey {
            attempt = PendingRegistration(nodeKey: nodeKey, oldNodeKey: .zero, followup: "")
        } else {
            attempt = PendingRegistration(nodeKey: .init(), oldNodeKey: identity.nodePublicKey ?? .zero, followup: "")
        }
        var regenerated = false
        var repeatedURLs = 0

        while true {
            let publicKey = NodePublicKey(attempt.nodeKey.publicKey)
            let request = RegisterRequest(
                nodeKey: publicKey,
                oldNodeKey: attempt.oldNodeKey,
                auth: configuration.authKey.map { RegisterResponseAuth(authKey: AuthKey.controlValue(of: $0)) },
                followup: attempt.followup,
                hostinfo: hostinfo,
                ephemeral: configuration.ephemeral
            )
            let httpRequest = connection.jsonRequest("POST", path: "/machine/register", nodeKey: publicKey)
            let body = try Self.encode(request)
            let response: ControlConnection.Response
            if attempt.followup.isEmpty {
                response = try await withTimeout(timeouts.request) {
                    try await connection.response(to: httpRequest, body: body, limit: Self.maximumRegisterResponseSize)
                }
            } else {
                response = try await untilLoginRequested(timeout: timeouts.followup) {
                    try await connection.response(to: httpRequest, body: body, limit: Self.maximumRegisterResponseSize)
                }
            }
            try Self.check(status: response.status, retryAfter: response.headers.first { $0.name == "retry-after" }?.value)
            guard let decoded = try? JSONDecoder().decode(RegisterResponse.self, from: Data(response.body)) else {
                throw ControlError.connection("등록 응답을 해석하지 못했다")
            }

            if !decoded.error.isEmpty {
                throw ControlError.registrationRejected(Self.rejectionMessage(decoded.error, authKey: configuration.authKey))
            }
            if !decoded.nodeKeySignature.isEmpty {
                // 서버가 새 키에 tailnet lock 서명을 다시 해 달라고 한다. lock은 지원하지 않는다.
                throw ControlError.tailnetLockEnabled
            }
            if decoded.nodeKeyExpired {
                guard !regenerated else { throw ControlError.nodeKeyExpired }
                regenerated = true
                attempt = PendingRegistration(nodeKey: .init(), oldNodeKey: identity.nodePublicKey ?? .zero, followup: "")
                pendingRegistration = nil
                continue
            }
            if !decoded.authURL.isEmpty {
                guard let url = URL(string: decoded.authURL), ["http", "https"].contains(url.scheme?.lowercased()) else {
                    throw ControlError.connection("서버가 잘못된 AuthURL을 보냈다")
                }
                // 기다리는 동안 새 로그인을 요청받았으면 이 URL은 버리고 새 키로 다시 시작한다.
                guard loginRequests == loginRequest else { throw SessionInterruption.loginRequested }
                if decoded.authURL == attempt.followup {
                    // 같은 URL이 곧바로 되돌아오면 서버를 몰아붙이지 않게 물러난다.
                    repeatedURLs += 1
                    try await Task.sleep(for: RetryPolicy.backoff(failures: repeatedURLs, jitter: .random(in: 0..<1)), clock: .continuous)
                    // 잠든 사이에 새 로그인을 요청받았으면 지워진 이전 등록을 되살리지 않는다.
                    guard loginRequests == loginRequest else { throw SessionInterruption.loginRequested }
                } else {
                    repeatedURLs = 0
                    eventContinuation.yield(.loginRequired(url))
                }
                attempt.followup = decoded.authURL
                pendingRegistration = attempt
                continue
            }

            identity.nodeKey = attempt.nodeKey
            try identityStore.save(identity)
            pendingRegistration = nil
            if loginRequests == loginRequest {
                rotateNodeKey = false
                needsRegistration = false
            }
            eventContinuation.yield(.registered(publicKey))
            return
        }
    }

    /// 로그인을 기다리는 긴 폴링을 돌리되, 그동안 `startInteractiveLogin()`이 불리면 그만두고
    /// `SessionInterruption.loginRequested`를 던진다. 사용자가 로그인을 다시 요청했는데 이전 URL의 응답을
    /// 기한(10분)까지 기다리지 않게 한다.
    private func untilLoginRequested(
        timeout: Duration,
        _ operation: @escaping @Sendable () async throws -> ControlConnection.Response
    ) async throws -> ControlConnection.Response {
        let (requests, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        followupInterrupt = continuation
        defer {
            followupInterrupt = nil
            continuation.finish()
        }
        return try await withThrowingTaskGroup(of: ControlConnection.Response?.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await withTimeout(timeout, operation) }
            group.addTask {
                for await _ in requests { break }
                return nil
            }
            guard let first = try await group.next(), let response = first else {
                throw SessionInterruption.loginRequested
            }
            return response
        }
    }

    /// 서버의 거절 메시지를 오류에 담을 형태로 만든다. 서버가 인증 키를 되풀이해도 비밀이 오류·로그에 남지 않게
    /// 설정의 인증 키(원문과 `--TL` 앞부분)와 같은 부분을 가리고, 길이를 `maximumRejectionLength`로 자른다.
    static func rejectionMessage(_ message: String, authKey: String?) -> String {
        var message = message
        if let authKey {
            // 긴 것부터 가린다. 앞부분을 먼저 가리면 원문의 나머지(`--TL…`)가 남는다.
            for secret in [authKey, AuthKey.controlValue(of: authKey)] where !secret.isEmpty {
                message = message.replacingOccurrences(of: secret, with: "<가림>")
            }
        }
        guard message.count > maximumRejectionLength else { return message }
        return String(message.prefix(maximumRejectionLength)) + "…"
    }

    /// 200이 아닌 상태를 오류로 바꾼다. 429와 `Retry-After`가 붙은 503은 기다릴 시간을 담는다.
    static func check(status: Int, retryAfter: String?) throws {
        switch status {
        case 200:
            return
        case 429:
            throw SessionInterruption.rateLimited(RetryPolicy.retryAfter(retryAfter, now: Date(), jitter: .random(in: 0..<1)))
        case 503 where retryAfter != nil:
            throw SessionInterruption.rateLimited(RetryPolicy.retryAfter(retryAfter, now: Date(), jitter: .random(in: 0..<1)))
        default:
            throw ControlError.http(status: status)
        }
    }

    static func encode(_ value: some Encodable) throws -> [UInt8] {
        do {
            return Array(try JSONEncoder().encode(value))
        } catch {
            throw ControlError.connection("요청을 JSON으로 만들지 못했다")
        }
    }
}
