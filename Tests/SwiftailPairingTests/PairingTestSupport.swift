// 페어링 단위 시험의 공용 값과 도우미. 값은 모두 가짜다(가짜 tailnet `tail0001`, 가짜 주소 `100.64.0.x`).

import Foundation
import Swiftail
import SwiftailBase
import Synchronization
import Testing
@testable import SwiftailPairing

enum Sample {
    static let host = "rd-mac-1a2b3c4d.tail0001.ts.net"
    static let port: UInt16 = 4747
    static let secret = [UInt8](repeating: 0x5A, count: 32)
    static let authKey = "tskey-auth-EXAMPLE-0000"
    /// 제안이 살아 있는 시각과 만료 시각.
    static let wallClock = Date(timeIntervalSince1970: 1_900_000_000)
    static let expires = Date(timeIntervalSince1970: 1_900_000_300)
    static let joinerNonce = [UInt8](repeating: 0x11, count: 32)
    static let hostNonce = [UInt8](repeating: 0x22, count: 32)

    static let joinerIdentity = PeerIdentity(
        stableID: "nEXAMPLEJOINER", name: "rd-phone-5e6f7a8b.tail0001.ts.net", computedName: "rd-phone-5e6f7a8b",
        loginName: "alice@example.com")
    static let hostIdentity = PeerIdentity(
        stableID: "nEXAMPLEHOST", name: host, computedName: "rd-mac-1a2b3c4d", loginName: "alice@example.com")

    static func offer(
        secret: [UInt8] = secret, expires: Date = expires, authKey: String? = nil, host: String = host,
        port: UInt16 = port
    ) -> PairingOffer {
        PairingOffer(host: host, port: port, expires: expires, authKey: authKey, secret: secret)
    }

    static func endpoints(
        joiner: String = "100.64.0.2:49152", host: String = "100.64.0.1:4747"
    ) throws -> PairingEndpoints {
        PairingEndpoints(joiner: try #require(IPEndpoint(joiner)), host: try #require(IPEndpoint(host)))
    }

    static func deviceName(_ text: String = "rd-phone-5e6f7a8b") throws -> DeviceName {
        try #require(DeviceName(text))
    }

    /// 여는 쪽이 `challenge`에 싣는 약속 commitH.
    static let hostCommitment = PairingTranscript.commitment(toHostNonce: hostNonce)

    /// `Sample`의 값으로 만든 P. 들어오는 쪽의 nonce, 제안, 연결의 두 끝은 바꿀 수 있다.
    static func proofTranscript(
        joinerNonce: [UInt8] = joinerNonce, offer: PairingOffer = offer(), endpoints: PairingEndpoints? = nil
    ) throws -> PairingProofTranscript {
        PairingProofTranscript(
            joinerNonce: joinerNonce, hostCommitment: hostCommitment, offerHost: offer.host, offerPort: offer.port,
            deviceName: Array("rd-phone-5e6f7a8b".utf8), endpoints: try endpoints ?? Sample.endpoints())
    }

    /// 같은 값으로 만든 T(여는 쪽의 nonce까지 열린 뒤).
    static func transcript(
        joinerNonce: [UInt8] = joinerNonce, offer: PairingOffer = offer(), endpoints: PairingEndpoints? = nil
    ) throws -> PairingTranscript {
        try #require(
            try proofTranscript(joinerNonce: joinerNonce, offer: offer, endpoints: endpoints).opened(with: hostNonce))
    }

    /// 여는 쪽이 `Sample`의 값으로 보낼 `accepted`: 열어 보인 nonceH와 T의 HMAC.
    static func accepted() throws -> [UInt8] {
        hostNonce + (try transcript()).accepted(secret: secret)
    }

    /// 시험이 만들고 지우는 빈 임시 디렉터리의 자리(만들지는 않는다).
    static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "swiftail-pairing-\(UUID().uuidString)")
    }
}

/// 여는 쪽 상태 기계가 낸 할 일을 견줄 수 있는 모양으로 줄인 것(`PairingRequest`는 `Equatable`이 아니다).
enum HostStep: Equatable {
    case send([UInt8])
    case requestDecision(stableID: String, deviceName: String, confirmationCode: String)
    case save(PairedPeer)
    case finish(PairingHostMachine.Ending)

    static func steps(_ actions: [PairingHostMachine.Action]) -> [HostStep] {
        actions.map { action in
            switch action {
            case .send(let bytes): .send(bytes)
            case .requestDecision(let request):
                .requestDecision(
                    stableID: request.peer.stableID, deviceName: request.deviceName,
                    confirmationCode: request.confirmationCode)
            case .save(let peer): .save(peer)
            case .finish(let ending): .finish(ending)
            }
        }
    }
}

extension [PairingHostMachine.Action] {
    /// 보낼 바이트를 차례대로 이어 붙인 것.
    var sentBytes: [UInt8] {
        flatMap { action -> [UInt8] in if case .send(let bytes) = action { bytes } else { [] } }
    }
}

extension [PairingJoinerSession.Action] {
    var sentBytes: [UInt8] {
        flatMap { action -> [UInt8] in if case .send(let bytes) = action { bytes } else { [] } }
    }

    /// 절차가 끝났으면 그 결과.
    var result: Result<PairingJoinerSession.Approval, PairingError>? {
        compactMap { action in if case .finish(let result) = action { result } else { nil } }.first
    }

    var confirmationCode: String? {
        compactMap { action in if case .awaitingApproval(let code) = action { code } else { nil } }.first
    }
}

/// 여는 쪽 상태 기계 하나와 들어오는 쪽 연결 하나를 메모리에서 맞물린 것. 단계마다 멈춰 끼어들 수 있다.
struct PairingRehearsal {
    static let sessionID: PairingHostMachine.SessionID = 1

    var machine = PairingHostMachine()
    var joiner: PairingJoinerSession
    let start = ContinuousClock.now
    let offer: PairingOffer

    /// 제안을 열고, 연결 하나를 받고, 들어오는 쪽 연결을 만든다.
    init(
        offer: PairingOffer = Sample.offer(), hostSees: PairingEndpoints? = nil, joinerSees: PairingEndpoints? = nil,
        deviceName: String = "rd-phone-5e6f7a8b"
    ) throws {
        self.offer = offer
        machine.open(offer)
        let accepted = machine.accept(
            Self.sessionID, from: Sample.joinerIdentity, endpoints: try hostSees ?? Sample.endpoints(),
            nonce: Sample.hostNonce, at: start)
        #expect(accepted.isEmpty)
        joiner = PairingJoinerSession(
            offer: offer, deviceName: try Sample.deviceName(deviceName), nonce: Sample.joinerNonce,
            endpoints: try joinerSees ?? Sample.endpoints(), challengeDeadline: start + .seconds(60))
    }

    /// 들어오는 쪽의 바이트를 여는 쪽에 넣는다.
    mutating func toHost(_ bytes: [UInt8], wallClock: Date = Sample.wallClock) -> [PairingHostMachine.Action] {
        machine.receive(bytes, on: Self.sessionID, wallClock: wallClock, now: start)
    }

    /// 여는 쪽의 바이트를 들어오는 쪽에 넣는다.
    mutating func toJoiner(_ bytes: [UInt8]) -> [PairingJoinerSession.Action] {
        joiner.receive(bytes, at: start)
    }

    /// `hello`와 `challenge`, `proof`와 `accepted`를 주고받아 결정을 기다리는 데까지 간다. 여는 쪽이 낸 요청의 확인
    /// 숫자와 들어오는 쪽이 받은 확인 숫자를 돌려준다.
    mutating func reachDecision() throws -> (hostCode: String, joinerCode: String) {
        let challenge = toHost(joiner.hello)
        let proof = toJoiner(challenge.sentBytes)
        let accepted = toHost(proof.sentBytes)
        guard case .requestDecision(let request)? = accepted.last else {
            throw RehearsalFailure(description: "결정 요청이 나오지 않았다: \(HostStep.steps(accepted))")
        }
        let waiting = toJoiner(accepted.sentBytes)
        return (request.confirmationCode, try #require(waiting.confirmationCode))
    }

    /// 앱이 승인했고 저장도 됐을 때 여는 쪽이 낸 할 일.
    mutating func approve(saving succeeded: Bool = true) -> [PairingHostMachine.Action] {
        let decided = machine.decided(
            Self.sessionID, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity,
            at: Sample.wallClock)
        guard case .save? = decided.last else { return decided }
        return machine.saved(Self.sessionID, succeeded: succeeded)
    }
}

struct RehearsalFailure: Error, CustomStringConvertible {
    let description: String
}

/// `body`가 던진 `PairingError`. 던지지 않으면 nil. 다른 오류는 시험 실패다.
func pairingError<T>(_ body: () async throws -> T) async -> PairingError? {
    do {
        _ = try await body()
        return nil
    } catch let error as PairingError {
        return error
    } catch {
        Issue.record("PairingError가 아닌 오류: \(error)")
        return nil
    }
}
