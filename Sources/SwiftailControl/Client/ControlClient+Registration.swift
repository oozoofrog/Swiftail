import CryptoKit
import Foundation
import os
import SwiftailBase
import SwiftailIO
import SwiftailTKA

/// tailnet lock의 로그(계약 `docs/contracts/SwiftailTailnetLock.md` 동작 K5). 키·서명 바이트·인증 키는 남기지 않는다.
private let tailnetLockLog = Logger(subsystem: "Swiftail", category: "tailnet-lock")

/// 등록: `POST /machine/register`로 node 키를 제어 서버에 올린다.
///
/// 1. 저장된 node 키가 있으면 그것으로, 없거나 바꿔야 하면(대화형 로그인, 만료) 새 후보 키로 요청한다.
///    키를 바꿀 때는 이전 키를 `OldNodeKey`에 넣는다. 인증 키는 새 node 키를 등록할 때만 `--TL` 앞부분을 보낸다:
///    처음 등록할 때와, 키가 만료되거나 로그인을 새로 해서 키를 바꿀 때다(재사용 인증 키면 스스로 다시 인증된다).
///    이미 등록된 저장 키로 다시 붙을 때(재시작)는 보내지 않는다. 일회용 키는 이미 쓰였고, Go tsnet도 로그인이
///    필요한 상태에서만 인증 키를 넘긴다.
///    요청마다 NL 공개 키(`NLKey`)를 싣고, node 키 서명(`NodeKeySignature`)은 Go의 순서로 고른다(`nodeKeySignature`).
/// 2. 응답은 `Error` → `NodeKeySignature` → `NodeKeyExpired` → `AuthURL` 순으로 본다. `NodeKeySignature`가 오면 서버가
///    재서명을 요청한 것이다: 새 node 키를 만들어, 받은 서명을 NL 키로 이어 서명해 다시 등록한다. 한 번의 등록에서 한 번만
///    따르고, 거듭 오면 연결 오류로 보고 물러났다가 다시 잇는다(Go는 두 번째 요청을 버린다).
/// 3. `AuthURL`이 오면 `loginRequired`를 내고, 같은 후보 키로 `Followup` 요청(긴 폴링)을 되풀이한다.
///    후보 키는 인증이 끝난 뒤에만 확정하고 저장한다. 그 전에 연결이 끊기면 다시 이은 뒤 같은 후보 키와 Followup
///    URL로 이어서 기다린다. 사용자가 보고 있는 URL은 그 후보 키에 묶여 있기 때문이다.
/// 4. 등록하는 동안 `startInteractiveLogin()`이 불리면, 이 등록이 끝나도 그 요청은 남는다(Go `authRoutine`의
///    `loginGoal == goal` 확인). 받은 키는 확정하지만 다음 연결에서 새 키로 다시 등록한다. 로그인을 기다리는
///    Followup 긴 폴링은 그 자리에서 그만두고 새 키로 다시 시작한다(사용자가 새 URL을 곧바로 받는다).
///
/// `docs/protocol-notes/control-map.md` 3.2, 4.1, `docs/protocol-notes/tailnet-lock.md` 4.6, 계약
/// `docs/contracts/SwiftailTailnetLock.md` 동작 R (출처: tailscale.com `control/controlclient/direct.go`
/// `doLoginOrRegen`·`doLogin`, `auto.go` `authRoutine`, BSD-3-Clause).
extension ControlClient {
    /// 등록 응답 본문의 한도(1MiB). Go와 같다.
    static let maximumRegisterResponseSize = 1 << 20
    /// `registrationRejected`에 담는 서버 메시지의 한도(문자 수). Go가 HTTP 오류 본문을 자르는 길이와 같다.
    static let maximumRejectionLength = 200

    /// `run()`이 첫 연결 전에 한 번 부른다. 인증 키의 `--TL` 뒤를 해석하고(어긋나면 서버에 아무것도 보내지 않고 끝난다),
    /// 신원을 읽거나 만든다. NL 키가 없던 옛 신원이면 새 NL 키를 저장한 뒤 돌아온다(동작 R1·R3).
    func prepareRegistration() throws(ControlError) {
        wrappedAuthKey = try AuthKey.wrapped(in: configuration.authKey)
        identity = try identityStore.loadOrCreate()
    }

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
        var resignRequested = false
        /// 서버가 방금 준 옛 서명. 그 응답 다음의 요청 하나에만 쓴다(Go `loginOpt.OldNodeKeySignature`).
        var previousSignature: [UInt8]?
        var repeatedURLs = 0

        while true {
            let publicKey = NodePublicKey(attempt.nodeKey.publicKey)
            let auth = publicKey == identity.nodePublicKey
                ? nil
                : configuration.authKey.map { RegisterResponseAuth(authKey: AuthKey.controlValue(of: $0)) }
            let signature = try nodeKeySignature(
                for: publicKey, oldNodeKey: attempt.oldNodeKey, resigning: previousSignature, sendsAuthKey: auth != nil
            )
            previousSignature = nil
            let request = RegisterRequest(
                nodeKey: publicKey,
                oldNodeKey: attempt.oldNodeKey,
                nlKey: identity.lockPublicKey,
                auth: auth,
                followup: attempt.followup,
                hostinfo: hostinfo,
                ephemeral: configuration.ephemeral,
                nodeKeySignature: signature
            )
            let httpRequest = connection.jsonRequest("POST", path: "/machine/register", nodeKey: publicKey)
            let body = try Self.encode(request)
            let response: ControlConnection.Response
            if attempt.followup.isEmpty {
                response = try await withControlTimeout(timeouts.request) {
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
                let message = Self.rejectionMessage(decoded.error, authKey: configuration.authKey)
                // 앱이 사용자에게 다르게 안내해야 하는 두 경우를 가른다: 실어 보낸 인증 키가 거절된 것과 그 밖의 거절.
                throw request.auth == nil ? ControlError.registrationRejected(message) : ControlError.authKeyRejected(message)
            }
            if !decoded.nodeKeySignature.isEmpty {
                // 재서명 요청(동작 R6). 옛 node 키는 저장된 지금의 키이고, 재서명의 입력은 방금 받은 바이트다.
                guard !resignRequested else { throw ControlError.connection("서버가 재서명을 거듭 요청했다") }
                resignRequested = true
                previousSignature = decoded.nodeKeySignature
                attempt = PendingRegistration(nodeKey: .init(), oldNodeKey: identity.nodePublicKey ?? .zero, followup: "")
                pendingRegistration = nil
                continue
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
                    try await Task.sleep(for: Backoff.delay(failures: repeatedURLs, maximum: RetryPolicy.maximumBackoff, jitter: .random(in: 0..<1)), clock: .continuous)
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

    /// 등록 요청에 실을 node 키 서명(동작 R5). Go `doLogin`의 순서 그대로다.
    ///
    /// 1. 옛 node 키가 있고 서버가 방금 옛 서명을 줬으면 그것을 NL 키로 이어 서명한다(`ResignNKS`). 실패하면 로그만 남기고
    ///    서명 없이 등록한다.
    /// 2. 아니고 서명된 인증 키를 실어 보내는 요청이면 감싼 키로 새 node 키에 서명한다(`SignByCredential`). 실패하면 이 등록을
    ///    오류로 끝낸다(Go와 같이 물러났다가 다시 시도한다).
    /// 3. 그 밖에는 서명이 없다(JSON `null`). 서명은 서명 기기가 뒤에 올린다.
    private func nodeKeySignature(
        for nodeKey: NodePublicKey, oldNodeKey: NodePublicKey, resigning previous: [UInt8]?, sendsAuthKey: Bool
    ) throws(ControlError) -> [UInt8] {
        if !oldNodeKey.isZero, let previous {
            let signature: [UInt8]
            do {
                signature = try NodeKeySignature.resigned(previous, for: nodeKey, with: identity.lockKey)
            } catch {
                tailnetLockLog.error("재서명하지 못해 서명 없이 등록한다(\(String(describing: error), privacy: .public))")
                return []
            }
            if !Self.rotates(previous, by: identity.lockPublicKey) {
                // Go와 같이 그대로 보낸다(결정 L9). 노드는 서명 기기가 다시 서명할 때까지 잠기고, 다음 netmap이 그것을 드러낸다.
                tailnetLockLog.notice("재서명: 옛 서명의 회전 키가 이 노드의 NL 키가 아니어서 새 서명은 검증되지 않는다")
            }
            return signature
        }
        guard sendsAuthKey, let wrappedAuthKey else { return [] }
        do {
            return try wrappedAuthKey.keySignature(for: nodeKey)
        } catch {
            throw .connection("서명된 인증 키로 node 키에 서명하지 못했다")
        }
    }

    /// 옛 서명을 감쌀 rotation을 검증할 키(Go `wrappingPublic`: 가장 바깥의 비지 않은 `WrappingPubkey`)가 `lockKey`인가.
    /// 아니면 재서명은 검증되지 않는다. 로그에만 쓴다. Go는 rotation이 아닌 서명의 `Nested`를 따라가지 않지만, 그런 서명은
    /// 검증을 통과하지 못하므로 판정에 영향이 없다.
    private static func rotates(_ previous: [UInt8], by lockKey: NLPublicKey) -> Bool {
        var current = try? NodeKeySignature(decoding: previous)
        while let signature = current {
            if !signature.wrappingPublicKey.isEmpty { return signature.wrappingPublicKey == lockKey.rawValue }
            current = signature.nested
        }
        return false
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
            group.addTask { try await withControlTimeout(timeout, operation) }
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
