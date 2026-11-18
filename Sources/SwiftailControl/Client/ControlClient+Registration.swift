import CryptoKit
import Foundation
import os
import SwiftailBase
import SwiftailIO
import SwiftailTKA

/// Tailnet lock logging (contract `docs/contracts/SwiftailTailnetLock.md` behavior K5). Omits keys, signature bytes, and auth keys.
private let tailnetLockLog = Logger(subsystem: "Swiftail", category: "tailnet-lock")

/// Registers a node key with the control server using `POST /machine/register`.
///
/// 1. Requests with the stored node key when available, or a fresh candidate key if none exists or rotation is required (interactive login or expiration).
///    During rotation, includes the previous key in `OldNodeKey`. Sends the part of the auth key before `--TL` only when registering a fresh node key.
///    This covers initial registration and rotation after expiration or a new login (a reusable auth key authenticates again automatically).
///    Omits it when reconnecting with an already registered stored key (restart). A single-use key has already been used, and Go tsnet also
///    passes an auth key only when login is required.
///    Includes the NL public key (`NLKey`) in each request and chooses the node key signature (`NodeKeySignature`) in Go's order (`nodeKeySignature`).
/// 2. Checks `Error` → `NodeKeySignature` → `NodeKeyExpired` → `AuthURL` in order. If `NodeKeySignature` arrives, the server
///    requested re-signing. Creates a fresh node key, uses the NL key to extend the received signature chain, and registers again. Honors this only once
///    per registration. A repeated request is a connection error followed by backoff and reconnection (Go discards the second request).
/// 3. If `AuthURL` arrives, emits `loginRequired` and repeats `Followup` requests (long polls) with the same candidate key.
///    Commits and stores the candidate key only after authentication. If the connection drops before then, resumes waiting after reconnecting using the same candidate
///    key and Followup URL, because the URL the user sees is tied to that candidate key.
/// 4. If `startInteractiveLogin()` is called during registration, the request remains pending after registration completes (Go `authRoutine`'s
///    `loginGoal == goal` check). Commits the candidate key after successful registration and registers again with a fresh key on the next connection. If a Followup long poll
///    is waiting for login, stops it immediately and starts over with a fresh key (the user gets a fresh URL immediately).
///
/// `docs/protocol-notes/control-map.md` §3.2, §4.1, `docs/protocol-notes/tailnet-lock.md` §4.6, contract
/// `docs/contracts/SwiftailTailnetLock.md` behavior R (origin: tailscale.com `control/controlclient/direct.go`
/// `doLoginOrRegen`·`doLogin`, `auto.go` `authRoutine`, BSD-3-Clause).
extension ControlClient {
    /// The registration response body limit (1MiB), matching Go.
    static let maximumRegisterResponseSize = 1 << 20
    /// The server message length limit (in characters) in `registrationRejected`. Matches the length at which Go truncates the HTTP error body.
    static let maximumRejectionLength = 200

    /// Called once by `run()` before the first connection. Parses the part of the auth key after `--TL` (stops without sending anything to the server if invalid)
    /// and loads or creates the identity. For a legacy identity without an NL key, stores a fresh NL key before returning (behaviors R1 and R3).
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
        /// The old signature the server just supplied. Used only for the request immediately after that response (Go `loginOpt.OldNodeKeySignature`).
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
                throw ControlError.connection("Could not parse the registration response")
            }

            if !decoded.error.isEmpty {
                let message = Self.rejectionMessage(decoded.error, authKey: configuration.authKey)
                // Distinguish the cases the app must explain differently to the user: rejection of the included auth key and other rejections.
                throw request.auth == nil ? ControlError.registrationRejected(message) : ControlError.authKeyRejected(message)
            }
            if !decoded.nodeKeySignature.isEmpty {
                // A re-signing request (behavior R6). The old node key is the currently stored key. Re-signing uses the bytes just received.
                guard !resignRequested else { throw ControlError.connection("Server requested re-signing again") }
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
                    throw ControlError.connection("Server returned an invalid AuthURL")
                }
                // If a new login was requested while waiting, discard this URL and restart with a fresh key.
                guard loginRequests == loginRequest else { throw SessionInterruption.loginRequested }
                if decoded.authURL == attempt.followup {
                    // If the same URL comes back immediately, back off to avoid hammering the server.
                    repeatedURLs += 1
                    try await Task.sleep(for: Backoff.delay(failures: repeatedURLs, maximum: RetryPolicy.maximumBackoff, jitter: .random(in: 0..<1)), clock: .continuous)
                    // If a new login was requested while sleeping, avoid reviving the discarded prior registration.
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

    /// The node key signature for the registration request (behavior R5). Follows the exact order of Go `doLogin`.
    ///
    /// 1. If an old node key exists and the server just supplied the old signature, extend that signature chain using the NL key (`ResignNKS`). If the old signature
    ///    does not belong to a chain this node already signed with its NL key, re-signing throws (contract §5 TL-11b item 1 prohibits signing a server-selected node key).
    ///    On error, logs only its kind and registers without a signature. The node is locked out, which the next netmap's `signingRequest` reveals.
    /// 2. Otherwise, if the request includes a signed auth key, signs the new node key using the wrapped key (`SignByCredential`). Failure
    ///    ends registration with an error (backs off and retries, as Go does).
    /// 3. Otherwise, there is no signature (JSON `null`). The signing device uploads the signature later.
    private func nodeKeySignature(
        for nodeKey: NodePublicKey, oldNodeKey: NodePublicKey, resigning previous: [UInt8]?, sendsAuthKey: Bool
    ) throws(ControlError) -> [UInt8] {
        if !oldNodeKey.isZero, let previous {
            do {
                return try NodeKeySignature.resigned(previous, for: nodeKey, with: identity.lockKey)
            } catch {
                // `TKAError` holds only the kind, without keys or bytes.
                tailnetLockLog.error("Could not re-sign, so registering without a signature (\(String(describing: error), privacy: .public))")
                return []
            }
        }
        guard sendsAuthKey, let wrappedAuthKey else { return [] }
        do {
            return try wrappedAuthKey.keySignature(for: nodeKey)
        } catch {
            throw .connection("Could not sign the node key with the signed auth key")
        }
    }

    /// Runs a long poll waiting for login. If `startInteractiveLogin()` is called in the meantime, stops
    /// and throws `SessionInterruption.loginRequested`. When the user asks to log in again, this avoids waiting for the previous URL's response
    /// until the deadline (10 minutes).
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

    /// Prepares the server rejection message for an error. To keep secrets out of errors and logs even if the server echoes the auth key,
    /// redacts occurrences of the configured auth key (the original and the portion before `--TL`). After `maximumRejectionLength` characters, truncates the message and appends an ellipsis.
    static func rejectionMessage(_ message: String, authKey: String?) -> String {
        var message = message
        if let authKey {
            // Redact longer matches first. Redacting the prefix first would leave the rest of the original text (`--TL…`).
            for secret in [authKey, AuthKey.controlValue(of: authKey)] where !secret.isEmpty {
                message = message.replacingOccurrences(of: secret, with: "<redacted>")
            }
        }
        guard message.count > maximumRejectionLength else { return message }
        return String(message.prefix(maximumRejectionLength)) + "…"
    }

    /// Converts a status other than 200 into an error. Includes a wait time for 429, or for 503 when `Retry-After` is present.
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
            throw ControlError.connection("Could not encode the request as JSON")
        }
    }
}
