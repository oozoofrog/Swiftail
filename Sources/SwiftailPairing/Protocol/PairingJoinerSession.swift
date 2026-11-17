import SwiftailCrypto

/// 들어오는 쪽의 짝 맺기 절차, 연결 하나(계약 동작 J3~J5).
///
/// 입출력이 없다. 받은 바이트·시각이 들어가고, 할 일(`Action`)이 나온다. 연결을 걸고 다시 거는 일(J1), 대역 검사(J2),
/// 취소(J7)는 가장자리(`PairingJoiner`)가 맡는다.
///
/// ```
/// hello ─▶ challenge(계속) ─▶ proof ─▶ accepted ─▶ 확인 숫자 ─▶ decision ─▶ 끝
///            └ 상태 1: rejected         └ 틀림: hostNotVerified   └ HMAC 틀림: hostNotVerified
/// ```
///
/// `hello`에는 nonce가 아니라 그 약속을 싣고, nonce는 여는 쪽의 nonce를 받은 뒤 `proof`에서 연다
/// (`PairingTranscript.commitment(to:)`).
///
/// 여는 쪽을 믿게 되는 곳은 `accepted`다. 그 HMAC은 제안의 비밀과, 이쪽이 본 연결의 두 끝을 넣은 T로 만든다. 그래서
/// `accepted`가 맞기 전에는 확인 숫자를 내지 않고, `decision`은 HMAC이 맞은 뒤에만 내용을 읽는다.
struct PairingJoinerSession: Sendable {
    typealias Instant = ContinuousClock.Instant

    /// `proof`를 보낸 뒤 `decision`까지의 기한(J4). 여는 쪽의 승인 기한 120초보다 길다.
    static let decisionTimeout = Duration.seconds(130)

    /// 가장자리가 할 일.
    enum Action: Sendable, Equatable {
        /// 이 바이트를 보낸다.
        case send([UInt8])
        /// 여는 쪽이 확인됐고 승인을 기다린다. 확인 숫자를 앱에 알린다.
        case awaitingApproval(confirmationCode: String)
        /// 절차가 끝났다. 연결을 닫는다. 마지막 할 일이다.
        case finish(Result<Approval, PairingError>)
    }

    /// 승인된 결과: 여는 쪽이 `decision`에 실은 자기 신원.
    struct Approval: Sendable, Equatable {
        var stableID: String
        var name: String
    }

    private enum Phase: Sendable {
        case challenge
        case accepted(PairingTranscript)
        case decision(PairingTranscript)
        case finished
    }

    /// 연결하자마자 보낼 `hello`.
    let hello: [UInt8]
    /// 다음 기한. 끝났으면 nil.
    private(set) var deadline: Instant?

    private let offer: PairingOffer
    /// 이 연결의 nonceJ. `challenge`를 받을 때까지 내보내지 않는다.
    private let nonce: [UInt8]
    private let deviceName: DeviceName
    private let endpoints: PairingEndpoints
    private var phase = Phase.challenge
    private var buffer: [UInt8] = []

    /// - Parameters:
    ///   - nonce: 이 연결에 쓸 난수 32바이트.
    ///   - endpoints: 이쪽이 본 연결의 두 끝.
    ///   - challengeDeadline: 첫 `challenge`를 받아야 하는 때(J1의 60초. 다시 거는 동안 함께 흐른다).
    init(
        offer: PairingOffer, deviceName: DeviceName, nonce: [UInt8], endpoints: PairingEndpoints,
        challengeDeadline: Instant
    ) {
        self.offer = offer
        self.nonce = nonce
        self.deviceName = deviceName
        self.endpoints = endpoints
        hello = PairingMessage.Hello(commitment: PairingTranscript.commitment(to: nonce), deviceName: deviceName).encoded
        deadline = challengeDeadline
    }

    /// 연결에서 받은 바이트. 메시지 하나가 다 올 때마다 다음 단계로 간다.
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
                    // 이쪽이 proof를 보내기 전에 온 그 뒤의 바이트는 차례 밖이다.
                    guard length == buffer.count else { return actions + finish(.failure(.protocolViolation)) }
                    guard challenge.status == .proceed else { return actions + finish(.failure(.rejected)) }
                    buffer = []
                    let transcript = PairingTranscript(
                        joinerNonce: nonce, hostNonce: challenge.nonce, offerHost: offer.host,
                        offerPort: offer.port, deviceName: deviceName.bytes, endpoints: endpoints)
                    phase = .accepted(transcript)
                    deadline = now + Self.decisionTimeout
                    let proof = PairingMessage.Proof(nonce: nonce, code: transcript.proof(secret: offer.secret))
                    return actions + [.send(proof.encoded)]
                }

            case .accepted(let transcript):
                guard buffer.count >= PairingMessage.codeLength else { return actions }
                let code = Array(buffer.prefix(PairingMessage.codeLength))
                guard constantTimeEqual(code, transcript.accepted(secret: offer.secret)) else {
                    return actions + finish(.failure(.hostNotVerified))
                }
                buffer.removeFirst(PairingMessage.codeLength)
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

    /// 연결이 끝났다(EOF, 오류).
    ///
    /// `challenge` 전이면 닿지 못한 것이다(여는 쪽이 이 노드를 아직 모르면 읽지 않고 닫는다. 가장자리가 다시 건다).
    /// `proof`를 보낸 뒤 `accepted` 없이 닫혔으면 받아 주지 않은 것이다(J3). 결정을 기다리던 중이면 약속된 메시지 없이
    /// 끝난 것이다.
    mutating func connectionEnded() -> [Action] {
        switch phase {
        case .challenge: finish(.failure(.unreachable))
        case .accepted: finish(.failure(.rejected))
        case .decision: finish(.failure(.protocolViolation))
        case .finished: []
        }
    }

    /// 시각이 흘렀다. 기한이 지났으면 `challenge` 전에는 `unreachable`, 그 뒤에는 `timedOut`으로 끝난다.
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
