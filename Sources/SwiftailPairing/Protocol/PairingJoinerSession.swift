import SwiftailCrypto

/// The joiner's pairing protocol for a single connection (contract behaviors J3–J5).
///
/// Performs no I/O. Accepts received bytes and times and emits actions (`Action`). Dialing and redialing (J1), range checks (J2),
/// and cancellation (J7) are handled at the edge (`PairingJoiner`).
///
/// ```
/// hello ─▶ challenge(continue) ─▶ proof ─▶ accepted ─▶ SAS ─▶ decision ─▶ end
///            └ status 1: rejected           └ invalid: hostNotVerified  └ invalid HMAC: hostNotVerified
/// ```
///
/// `hello` carries a commitment to the nonce. The joiner reveals the nonce in `proof` after receiving the host's commitment in `challenge`. The host's
/// nonce arrives in `accepted` and must match the `challenge` commitment (`PairingTranscript`).
///
/// The joiner establishes trust in the host at `accepted`. Its HMAC uses the offer secret and T, which includes both endpoints as seen by the joiner.
/// Computing the SAS requires the host nonce revealed in `accepted`. The joiner computes and emits it only after `accepted` verifies. The `decision` contents are read only after its HMAC verifies.
struct PairingJoinerSession: Sendable {
    typealias Instant = ContinuousClock.Instant

    /// The deadline from sending `proof` to receiving `decision` (J4). It exceeds the host's 120-second approval deadline.
    static let decisionTimeout = Duration.seconds(130)

    /// An action for the edge.
    enum Action: Sendable, Equatable {
        /// Sends these bytes.
        case send([UInt8])
        /// The host has been verified and approval is pending. Reports the SAS to the app.
        case awaitingApproval(confirmationCode: String)
        /// The protocol ended. Closes the connection. This is the final action.
        case finish(Result<Approval, PairingError>)
    }

    /// An approved result containing the host's identity from `decision`.
    struct Approval: Sendable, Equatable {
        var stableID: String
        var name: String
    }

    private enum Phase: Sendable {
        case challenge
        case accepted(PairingProofTranscript)
        case decision(PairingTranscript)
        case finished
    }

    /// The `hello` to send upon connection.
    let hello: [UInt8]
    /// The next deadline, or nil after completion.
    private(set) var deadline: Instant?

    private let offer: PairingOffer
    /// This connection's nonceJ. Withheld until `challenge` arrives.
    private let nonce: [UInt8]
    private let deviceName: DeviceName
    private let endpoints: PairingEndpoints
    private var phase = Phase.challenge
    private var buffer: [UInt8] = []

    /// - Parameters:
    ///   - nonce: 32 random bytes for this connection.
    ///   - endpoints: The connected endpoints as seen locally.
    ///   - challengeDeadline: The deadline for the first `challenge` (J1's 60 seconds, which continue to elapse across redials).
    init(
        offer: PairingOffer, deviceName: DeviceName, nonce: [UInt8], endpoints: PairingEndpoints,
        challengeDeadline: Instant
    ) {
        self.offer = offer
        self.nonce = nonce
        self.deviceName = deviceName
        self.endpoints = endpoints
        hello = PairingMessage.Hello(
            commitment: PairingTranscript.commitment(toJoinerNonce: nonce), deviceName: deviceName
        ).encoded
        deadline = challengeDeadline
    }

    /// Processes bytes received on the connection. Advances after each complete message.
    mutating func receive(_ bytes: [UInt8], at now: Instant) -> [Action] {
        buffer += bytes
        var actions: [Action] = []
        while true {
            switch phase {
            case .challenge:
                switch PairingMessage.Challenge.parse(buffer) {
                case .incomplete:
                    return actions
                case .invalid:
                    return actions + finish(.failure(.protocolViolation))
                case .complete(let challenge, let length):
                    // Any subsequent bytes received before sending proof are out of turn.
                    guard length == buffer.count else { return actions + finish(.failure(.protocolViolation)) }
                    guard challenge.status == .proceed else { return actions + finish(.failure(.rejected)) }
                    buffer = []
                    let proofTranscript = PairingProofTranscript(
                        joinerNonce: nonce, hostCommitment: challenge.commitment, offerHost: offer.host,
                        offerPort: offer.port, deviceName: deviceName.bytes, endpoints: endpoints)
                    phase = .accepted(proofTranscript)
                    deadline = now + Self.decisionTimeout
                    let proof = PairingMessage.Proof(nonce: nonce, code: proofTranscript.proof(secret: offer.secret))
                    return actions + [.send(proof.encoded)]
                }

            case .accepted(let proofTranscript):
                guard buffer.count >= PairingMessage.Accepted.length else { return actions }
                // J4: The revealed nonceH must match the `challenge` commitment (the host also cannot choose a nonce after seeing nonceJ),
                // and the HMAC of T containing that nonce must verify.
                guard let accepted = PairingMessage.Accepted(Array(buffer.prefix(PairingMessage.Accepted.length))),
                      let transcript = proofTranscript.opened(with: accepted.nonce),
                      constantTimeEqual(accepted.code, transcript.accepted(secret: offer.secret))
                else { return actions + finish(.failure(.hostNotVerified)) }
                buffer.removeFirst(PairingMessage.Accepted.length)
                phase = .decision(transcript)
                actions.append(.awaitingApproval(confirmationCode: transcript.confirmationCode(secret: offer.secret)))

            case .decision(let transcript):
                switch PairingMessage.Decision.frame(buffer) {
                case .incomplete:
                    return actions
                case .invalid:
                    return actions + finish(.failure(.protocolViolation))
                case .complete(let frame, let length):
                    guard length == buffer.count else { return actions + finish(.failure(.protocolViolation)) }
                    guard constantTimeEqual(
                        frame.code, transcript.decisionCode(for: frame.body, secret: offer.secret))
                    else { return actions + finish(.failure(.hostNotVerified)) }
                    switch PairingMessage.Decision(body: frame.body) {
                    case .approved(let stableID, let name):
                        return actions + finish(.success(Approval(stableID: stableID, name: name)))
                    case .denied:
                        return actions + finish(.failure(.denied))
                    case .timedOut:
                        return actions + finish(.failure(.timedOut))
                    case nil:
                        return actions + finish(.failure(.protocolViolation))
                    }
                }

            case .finished:
                return actions
            }
        }
    }

    /// Handles EOF or a read error.
    ///
    /// Before `challenge` this means unreachable (if the host does not yet know this node, it closes without reading, and the edge redials).
    /// A closure after `proof` without `accepted` means rejected (J3). While waiting for a decision, it means the connection ended without the
    /// expected message.
    mutating func connectionEnded() -> [Action] {
        switch phase {
        case .challenge: finish(.failure(.unreachable))
        case .accepted: finish(.failure(.rejected))
        case .decision: finish(.failure(.protocolViolation))
        case .finished: []
        }
    }

    /// Handles elapsed time. If the deadline passed, finishes with `unreachable` before `challenge` or `timedOut` afterward.
    mutating func advance(to now: Instant) -> [Action] {
        guard let deadline, now >= deadline else { return [] }
        if case .challenge = phase { return finish(.failure(.unreachable)) }
        return finish(.failure(.timedOut))
    }

    private mutating func finish(_ result: Result<Approval, PairingError>) -> [Action] {
        phase = .finished
        deadline = nil
        buffer = []
        return [.finish(result)]
    }
}
