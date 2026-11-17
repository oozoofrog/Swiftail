import Foundation
import Swiftail
import SwiftailCrypto

/// 여는 쪽의 짝 맺기 절차: 열린 제안 하나와, 절차 중인 연결들(계약 동작 P1~P9).
///
/// 입출력이 없다. 받은 바이트·시각·앱의 결정·저장 결과가 들어가고, 할 일(`Action`)이 나온다. 소켓·시계·난수·파일은
/// 가장자리(`PairingHost`)가 맡는다. 연결 하나의 흐름:
///
/// ```
/// accept ─ hello ─▶ challenge(계속) ─ proof ─▶ accepted + 결정 요청 ─ 결정 ─▶ 저장 ─▶ decision ─▶ 끝
///            │                         │                              └ 끊김·120초
///            └ 제안 없음: challenge(1)  └ 약속과 다른 nonce·틀림·제안이 바뀜: 말없이 닫음
/// ```
///
/// 제안은 한 번에 하나이고 한 번만 쓰인다. 맞는 `proof`가 온 그 자리에서 지운다(P4). 틀린 `proof`는 제안을 건드리지
/// 않는다(P3): 비밀이 256비트라 시도로 맞힐 수 없고, 틀린 시도로 태우면 tailnet의 아무 피어나 제안을 못 쓰게 만들 수 있다.
///
/// 이 연결의 nonce는 `challenge`에 약속으로만 나가고, `proof`가 맞아 제안을 지운 뒤에야 `accepted`로 나간다. 확인 숫자는
/// 그 nonce 없이는 계산할 수 없으므로, 제안의 비밀을 아는 쪽도 숫자를 보려면 제안을 써야 한다(숫자를 고르려고 다시 걸 수
/// 없다).
struct PairingHostMachine: Sendable {
    typealias SessionID = UInt64
    typealias Instant = ContinuousClock.Instant

    /// 절차 중인 연결의 한도(P8).
    static let sessionLimit = 8
    /// 그 가운데 같은 노드(`StableID`)의 것의 한도(P8). 피어 하나가 연결을 거듭 열어 자리를 모두 쥐고 있지 못한다.
    static let sessionLimitPerPeer = 2
    /// 연결을 받은 때부터 `proof`까지의 기한(P8). 말없는 연결이 자리를 쥐고 있지 못하게 받은 때부터 잰다.
    static let proofTimeout = Duration.seconds(10)
    /// 앱의 결정을 기다리는 기한(P5).
    static let decisionTimeout = Duration.seconds(120)

    /// 가장자리가 할 일.
    enum Action: Sendable {
        /// 이 바이트를 보낸다.
        case send([UInt8])
        /// 앱에게 승인을 묻는다. 답은 `decided`로 넣는다.
        case requestDecision(PairingRequest)
        /// 짝 목록에 넣고 저장한다. 결과는 `saved`로 넣는다.
        case save(PairedPeer)
        /// 보낼 것을 다 보낸 뒤 연결을 닫고, 이 연결의 결정 Task를 취소한다. 그 연결의 마지막 할 일이다.
        case finish(Ending)
    }

    /// 연결이 끝난 까닭. 로그에 남기는 요약이다(P10).
    enum Ending: String, Sendable {
        case limitReached = "절차 중인 연결이 한도에 닿음"
        case peerLimitReached = "같은 노드의 절차 중인 연결이 한도에 닿음"
        case unknownPeer = "상대의 신원을 모름"
        case noOffer = "열린 제안이 없음"
        case malformed = "절차와 다른 바이트"
        case wrongProof = "증명이 틀림"
        case proofTimedOut = "증명이 기한 안에 오지 않음"
        case disconnected = "상대가 끊음"
        case denied = "앱이 거절함"
        case decisionTimedOut = "승인 시간 초과"
        case identityChanged = "승인할 때 상대의 신원이 달라짐"
        case hostIdentityUnknown = "자기 신원을 모름"
        case storeFailed = "짝 목록에 저장하지 못함"
        case paired = "짝이 됨"
    }

    /// 열린 제안. 번호는 연결이 `hello` 때 본 제안과 `proof` 때의 제안이 같은 것인지 가리는 데 쓴다.
    private struct OpenOffer: Sendable {
        let serial: UInt64
        let offer: PairingOffer
    }

    /// `proof`가 맞은 뒤에 연결이 쥐는 것. 제안이 닫히거나 바뀌어도 이 결정은 계속된다(P6).
    private struct Approval: Sendable {
        let transcript: PairingTranscript
        let secret: [UInt8]
        let deviceName: String

        /// `decision` 메시지: 본문과 그 HMAC.
        func message(_ decision: PairingMessage.Decision) -> [UInt8] {
            decision.body + transcript.decisionCode(for: decision.body, secret: secret)
        }
    }

    private enum Phase: Sendable {
        /// `hello`를 모으는 중.
        case hello(buffer: [UInt8])
        /// `challenge`를 보냈고 `proof`를 모으는 중.
        case proof(buffer: [UInt8], hello: PairingMessage.Hello, offerSerial: UInt64)
        /// `accepted`를 보냈고 앱의 결정을 기다리는 중.
        case decision(Approval, deadline: Instant)
        /// 앱이 승인했고 저장 결과를 기다리는 중.
        case saving(Approval, approved: PairingMessage.Decision)
    }

    private struct Session: Sendable {
        /// 연결을 받았을 때의 상대 신원(P1).
        let peer: PeerIdentity
        let endpoints: PairingEndpoints
        /// 이 연결에 쓸 여는 쪽의 nonce. `challenge`에는 그 약속만 싣고, `proof`가 맞은 뒤 `accepted`에서 연다.
        let nonce: [UInt8]

        /// `challenge`에 싣는 약속 commitH.
        var commitment: [UInt8] { PairingTranscript.commitment(toHostNonce: nonce) }
        let acceptedAt: Instant
        var phase: Phase
    }

    private var offer: OpenOffer?
    private var nextOfferSerial: UInt64 = 0
    private var sessions: [SessionID: Session] = [:]

    /// 쓸 수 있는 제안이 열려 있는가(만료는 보지 않는다).
    var hasOpenOffer: Bool { offer != nil }
    /// 열린 제안의 만료 시각. 열린 제안이 없으면 nil.
    var openOfferExpiry: Date? { offer?.offer.expires }
    /// 절차 중인 연결 수.
    var sessionCount: Int { sessions.count }

    // MARK: 제안 (P9)

    /// 제안을 연다. 앞의 것은 그 자리에서 못 쓴다.
    mutating func open(_ offer: PairingOffer) {
        nextOfferSerial += 1
        self.offer = OpenOffer(serial: nextOfferSerial, offer: offer)
    }

    /// 제안을 닫는다. 이미 `proof`가 맞아 결정을 기다리는 연결은 그대로다(P6).
    mutating func closeOffer() {
        offer = nil
    }

    /// 만료된 제안을 지운다. 만료된 제안은 이미 쓰이지 않으므로(`usableOffer`) 지워도 절차는 그대로다. 가장자리가 만료를
    /// 알리려고 부른다.
    ///
    /// - Returns: 지운 제안이 있으면 true.
    mutating func expireOffer(at wallClock: Date) -> Bool {
        guard let offer, wallClock >= offer.offer.expires else { return false }
        self.offer = nil
        return true
    }

    // MARK: 연결

    /// 받은 연결 하나를 올린다(P1, P8). 한도(전체 8, 같은 노드 2)를 넘으면 받자마자 닫는다.
    ///
    /// - Parameters:
    ///   - peer: 원격 주소의 `whoIs`. 모르면 읽지 않고 닫는다.
    ///   - nonce: 이 연결에 쓸 난수 32바이트. 맞는 `proof`가 올 때까지 밖으로 내지 않는다.
    ///   - now: 연결을 받은 때. `proof`의 기한을 여기서부터 잰다.
    mutating func accept(
        _ id: SessionID, from peer: PeerIdentity?, endpoints: PairingEndpoints, nonce: [UInt8], at now: Instant
    ) -> [Action] {
        guard sessions.count < Self.sessionLimit else { return [.finish(.limitReached)] }
        guard let peer else { return [.finish(.unknownPeer)] }
        guard sessions.values.filter({ $0.peer.stableID == peer.stableID }).count < Self.sessionLimitPerPeer else {
            return [.finish(.peerLimitReached)]
        }
        sessions[id] = Session(
            peer: peer, endpoints: endpoints, nonce: nonce, acceptedAt: now, phase: .hello(buffer: []))
        return []
    }

    /// 연결에서 받은 바이트. 메시지는 정해진 길이 그대로여야 하고, 자기 차례가 아닐 때 온 바이트는 위반이다(P8).
    ///
    /// - Parameters:
    ///   - wallClock: 제안의 만료를 보는 시각.
    ///   - now: 결정의 기한을 재기 시작하는 때.
    mutating func receive(_ bytes: [UInt8], on id: SessionID, wallClock: Date, now: Instant) -> [Action] {
        guard var session = sessions[id] else { return [] }
        switch session.phase {
        case .hello(let buffer):
            let buffer = buffer + bytes
            switch PairingMessage.Hello.parse(buffer) {
            case .incomplete:
                session.phase = .hello(buffer: buffer)
                sessions[id] = session
                return []
            case .complete(let hello, let length) where length == buffer.count:
                // P2: 제안이 없거나 만료됐으면 hello를 다 읽은 뒤에 알리고 닫는다.
                guard let offer = usableOffer(at: wallClock) else {
                    let challenge = PairingMessage.Challenge(status: .noOffer, commitment: session.commitment)
                    return [.send(challenge.encoded)] + finish(id, .noOffer)
                }
                session.phase = .proof(buffer: [], hello: hello, offerSerial: offer.serial)
                sessions[id] = session
                return [.send(PairingMessage.Challenge(status: .proceed, commitment: session.commitment).encoded)]
            case .complete, .invalid:
                return finish(id, .malformed)
            }

        case .proof(let buffer, let hello, let offerSerial):
            let buffer = buffer + bytes
            guard buffer.count >= PairingMessage.Proof.length else {
                session.phase = .proof(buffer: buffer, hello: hello, offerSerial: offerSerial)
                sessions[id] = session
                return []
            }
            // P3: 연 nonceJ가 `hello`의 약속과 맞아야 한다. `challenge`를 본 뒤에 고른 nonce는 여기서 걸린다.
            // 약속은 공개된 값이라 상수 시간으로 견줄 까닭이 없다.
            guard let proof = PairingMessage.Proof(buffer),
                  PairingTranscript.commitment(toJoinerNonce: proof.nonce) == hello.commitment
            else { return finish(id, .malformed) }
            // 그 사이 제안이 닫혔거나, 바뀌었거나, 다른 연결이 썼거나, 만료됐으면 아무것도 보내지 않고 닫는다.
            guard let offer = usableOffer(at: wallClock), offer.serial == offerSerial else {
                return finish(id, .noOffer)
            }
            let secret = offer.offer.secret
            let proofTranscript = PairingProofTranscript(
                joinerNonce: proof.nonce, hostCommitment: session.commitment, offerHost: offer.offer.host,
                offerPort: offer.offer.port, deviceName: hello.deviceName.bytes, endpoints: session.endpoints)
            // P3: 상수 시간으로 견주고, 틀리면 제안을 그대로 둔다. nonceH도 내지 않는다.
            guard constantTimeEqual(proof.code, proofTranscript.proof(secret: secret)),
                  let transcript = proofTranscript.opened(with: session.nonce)
            else { return finish(id, .wrongProof) }
            // P4: 제안은 한 번만 쓴다. nonceH를 여는 것은 그 뒤다.
            self.offer = nil
            let approval = Approval(transcript: transcript, secret: secret, deviceName: hello.deviceName.text)
            session.phase = .decision(approval, deadline: now + Self.decisionTimeout)
            sessions[id] = session
            let request = PairingRequest(
                peer: session.peer, deviceName: approval.deviceName,
                confirmationCode: transcript.confirmationCode(secret: secret))
            let accepted = PairingMessage.Accepted(nonce: session.nonce, code: transcript.accepted(secret: secret))
            return [.send(accepted.encoded), .requestDecision(request)]

        case .decision, .saving:
            // P6: 결정을 기다리는 동안 온 바이트는 끊긴 것으로 본다.
            return finish(id, .disconnected)
        }
    }

    /// 연결이 끝났다(EOF, 오류). 결정을 기다리던 중이면 가장자리가 결정 Task를 취소한다(P6).
    mutating func connectionEnded(_ id: SessionID) -> [Action] {
        finish(id, .disconnected)
    }

    /// 이 연결의 다음 기한. 없으면 nil.
    func deadline(of id: SessionID) -> Instant? {
        guard let session = sessions[id] else { return nil }
        switch session.phase {
        case .hello, .proof: return session.acceptedAt + Self.proofTimeout
        case .decision(_, let deadline): return deadline
        case .saving: return nil
        }
    }

    /// 시각이 흘렀다. 기한이 지났으면 `proof` 전에는 말없이 닫고, 결정을 기다리던 중이면 상태 3을 보내고 닫는다.
    mutating func advance(_ id: SessionID, to now: Instant) -> [Action] {
        guard let session = sessions[id], let deadline = deadline(of: id), now >= deadline else { return [] }
        if case .decision(let approval, _) = session.phase {
            return [.send(approval.message(.timedOut))] + finish(id, .decisionTimedOut)
        }
        return finish(id, .proofTimedOut)
    }

    /// 앱의 결정(P5·P7).
    ///
    /// 승인이어도 짝이 되려면: 상대의 지금 신원(`currentPeer`)이 처음과 같은 `StableID`여야 하고, 알려 줄 자기 신원
    /// (`host`)이 있어야 한다. 아니면 거절(상태 2)이다.
    ///
    /// - Parameters:
    ///   - currentPeer: 지금의 `whoIs(원격 주소)`.
    ///   - host: 이 노드의 신원(`whoIs(자기 주소)`). `decision`에 `StableID`와 표시 이름을 싣는다.
    ///   - wallClock: 짝이 된 때로 적을 시각.
    mutating func decided(
        _ id: SessionID, approved: Bool, currentPeer: PeerIdentity?, host: PeerIdentity?, at wallClock: Date
    ) -> [Action] {
        guard var session = sessions[id], case .decision(let approval, _) = session.phase else { return [] }
        guard approved else { return [.send(approval.message(.denied))] + finish(id, .denied) }
        guard let currentPeer, currentPeer.stableID == session.peer.stableID else {
            return [.send(approval.message(.denied))] + finish(id, .identityChanged)
        }
        guard let host,
              let decision = PairingMessage.Decision.approval(stableID: host.stableID, name: host.computedName)
        else { return [.send(approval.message(.denied))] + finish(id, .hostIdentityUnknown) }
        session.phase = .saving(approval, approved: decision)
        sessions[id] = session
        return [.save(PairedPeer(peer: currentPeer, deviceName: approval.deviceName, pairedAt: wallClock))]
    }

    /// 저장 결과(P7). 저장했으면 상태 1을, 못 했으면(쓰기 실패, 목록이 가득 참) 상태 2를 보내고 닫는다.
    mutating func saved(_ id: SessionID, succeeded: Bool) -> [Action] {
        guard let session = sessions[id], case .saving(let approval, let approved) = session.phase else { return [] }
        return succeeded
            ? [.send(approval.message(approved))] + finish(id, .paired)
            : [.send(approval.message(.denied))] + finish(id, .storeFailed)
    }

    // MARK: 도우미

    private func usableOffer(at wallClock: Date) -> OpenOffer? {
        offer.flatMap { wallClock < $0.offer.expires ? $0 : nil }
    }

    private mutating func finish(_ id: SessionID, _ ending: Ending) -> [Action] {
        guard sessions.removeValue(forKey: id) != nil else { return [] }
        return [.finish(ending)]
    }
}
