import CryptoKit
import Foundation

/// 등록: `POST /machine/register`로 node 키를 제어 서버에 올린다.
///
/// 1. 저장된 node 키가 있으면 그것으로, 없거나 바꿔야 하면(대화형 로그인, 만료) 새 후보 키로 요청한다.
///    키를 바꿀 때는 이전 키를 `OldNodeKey`에 넣는다. 인증 키는 처음 등록할 때만, `--TL` 앞부분만 보낸다.
/// 2. 응답은 `Error` → `NodeKeySignature` → `NodeKeyExpired` → `AuthURL` 순으로 본다.
/// 3. `AuthURL`이 오면 `loginRequired`를 내고, 같은 후보 키로 `Followup` 요청(긴 폴링)을 되풀이한다.
///    후보 키는 인증이 끝난 뒤에만 확정하고 저장한다.
///
/// `docs/protocol-notes/control-map.md` 3.2, 4.1 (출처: tailscale.com `control/controlclient/direct.go`
/// `doLogin`, BSD-3-Clause).
extension ControlClient {
    /// 등록 응답 본문의 한도(1MiB). Go와 같다.
    static let maximumRegisterResponseSize = 1 << 20

    func register(over connection: ControlConnection) async throws {
        let isFirstRegistration = identity.nodeKey == nil
        let reusedKey = rotateNodeKey ? nil : identity.nodeKey
        var key = reusedKey ?? Curve25519.KeyAgreement.PrivateKey()
        var oldNodeKey = reusedKey == nil ? identity.nodePublicKey ?? .zero : .zero
        var regenerated = false
        var followup = ""
        var repeatedURLs = 0

        while true {
            let publicKey = NodePublicKey(key.publicKey)
            let request = RegisterRequest(
                nodeKey: publicKey,
                oldNodeKey: oldNodeKey,
                auth: isFirstRegistration ? configuration.authKey.map { RegisterResponseAuth(authKey: AuthKey.controlValue(of: $0)) } : nil,
                followup: followup,
                hostinfo: hostinfo,
                ephemeral: configuration.ephemeral
            )
            let response = try await connection.response(
                to: connection.jsonRequest("POST", path: "/machine/register", nodeKey: publicKey),
                body: Self.encode(request),
                limit: Self.maximumRegisterResponseSize
            )
            try Self.check(status: response.status, retryAfter: response.headers.first { $0.name == "retry-after" }?.value)
            guard let decoded = try? JSONDecoder().decode(RegisterResponse.self, from: Data(response.body)) else {
                throw ControlError.connection("등록 응답을 해석하지 못했다")
            }

            if !decoded.error.isEmpty {
                throw ControlError.registrationRejected(decoded.error)
            }
            if !decoded.nodeKeySignature.isEmpty {
                // 서버가 새 키에 tailnet lock 서명을 다시 해 달라고 한다. lock은 지원하지 않는다.
                throw ControlError.tailnetLockEnabled
            }
            if decoded.nodeKeyExpired {
                guard !regenerated else { throw ControlError.nodeKeyExpired }
                regenerated = true
                oldNodeKey = identity.nodePublicKey ?? .zero
                key = Curve25519.KeyAgreement.PrivateKey()
                followup = ""
                continue
            }
            if !decoded.authURL.isEmpty {
                guard let url = URL(string: decoded.authURL), ["http", "https"].contains(url.scheme?.lowercased()) else {
                    throw ControlError.connection("서버가 잘못된 AuthURL을 보냈다")
                }
                if decoded.authURL == followup {
                    // 같은 URL이 곧바로 되돌아오면 서버를 몰아붙이지 않게 물러난다.
                    repeatedURLs += 1
                    try await Task.sleep(for: RetryPolicy.backoff(failures: repeatedURLs, jitter: .random(in: 0..<1)), clock: .continuous)
                } else {
                    repeatedURLs = 0
                    eventContinuation.yield(.loginRequired(url))
                }
                followup = decoded.authURL
                continue
            }

            identity.nodeKey = key
            try identityStore.save(identity)
            rotateNodeKey = false
            needsRegistration = false
            eventContinuation.yield(.registered(publicKey))
            return
        }
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
