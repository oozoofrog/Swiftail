import Foundation
import Swiftail
import SwiftailBase
import Testing
@testable import SwiftailPairing

/// 절차 전체의 고정 벡터(계약 7절 시험 2).
///
/// 기대값은 다른 구현이 냈다: Go `crypto/hmac`·`crypto/sha256`으로 쓴 `Tools/interop/cmd/pairingvectors`의 출력을
/// `Fixtures/pairing-vectors.json`에 넣었다. 여기서는 코덱과 계산을 하나씩 견주고, 두 상태 기계를 맞물려 선 위로 나가는
/// 바이트가 벡터와 같은지 본다.
@Suite("절차의 고정 벡터(Go 구현과 일치)")
struct ProtocolVectorTests {
    struct Vector: Decodable, Sendable, CustomTestStringConvertible {
        struct Decision: Decodable, Sendable {
            var stableID: String?
            var name: String?
            var bytes: String
        }

        var label: String
        var secret: String
        var offerHost: String
        var offerPort: UInt16
        var deviceName: String
        var joinerNonce: String
        var hostNonce: String
        var joinerAddress: String
        var joinerPort: UInt16
        var hostAddress: String
        var hostPort: UInt16
        var joinerCommitment: String
        var hostCommitment: String
        var hello: String
        var challenge: String
        var challengeNoOffer: String
        var proofTranscript: String
        var transcript: String
        var proof: String
        var accepted: String
        var confirmationCode: String
        var approved: Decision
        var denied: Decision
        var timedOut: Decision

        var testDescription: String { label }

        var endpoints: PairingEndpoints {
            get throws {
                PairingEndpoints(
                    joiner: IPEndpoint(address: try #require(IPAddress(joinerAddress)), port: joinerPort),
                    host: IPEndpoint(address: try #require(IPAddress(hostAddress)), port: hostPort))
            }
        }

        var offer: PairingOffer {
            get throws {
                PairingOffer(
                    host: offerHost, port: offerPort, expires: Sample.expires, authKey: nil,
                    secret: try #require([UInt8](hex: secret)))
            }
        }

        var hostIdentity: PeerIdentity {
            get throws {
                PeerIdentity(
                    stableID: try #require(approved.stableID), name: offerHost, computedName: approved.name ?? "",
                    loginName: "alice@example.com")
            }
        }
    }

    private struct File: Decodable {
        var vectors: [Vector]
    }

    static let vectors: [Vector] = {
        guard let url = Bundle.module.url(forResource: "pairing-vectors", withExtension: "json", subdirectory: "Fixtures"),
              let data = try? Data(contentsOf: url), let file = try? JSONDecoder().decode(File.self, from: data)
        else { return [] }
        return file.vectors
    }()

    @Test("벡터 파일에 네 경우가 있다")
    func loadsVectors() {
        #expect(Self.vectors.count == 4)
    }

    @Test("두 nonce의 약속, hello와 challenge의 바이트", arguments: vectors)
    func messages(vector: Vector) throws {
        let commitment = PairingTranscript.commitment(toJoinerNonce: try #require([UInt8](hex: vector.joinerNonce)))
        #expect(commitment.hex == vector.joinerCommitment)
        let hello = PairingMessage.Hello(commitment: commitment, deviceName: try Sample.deviceName(vector.deviceName))
        #expect(hello.encoded.hex == vector.hello)
        guard case .complete(let parsed, let length) = PairingMessage.Hello.parse(hello.encoded) else {
            Issue.record("hello를 읽지 못했다")
            return
        }
        #expect(parsed == hello && length == hello.encoded.count)

        let hostCommitment = PairingTranscript.commitment(toHostNonce: try #require([UInt8](hex: vector.hostNonce)))
        #expect(hostCommitment.hex == vector.hostCommitment)
        #expect(PairingMessage.Challenge(status: .proceed, commitment: hostCommitment).encoded.hex == vector.challenge)
        #expect(
            PairingMessage.Challenge(status: .noOffer, commitment: hostCommitment).encoded.hex == vector.challengeNoOffer)
    }

    @Test("P, T, proof, accepted, 확인 숫자, decision", arguments: vectors)
    func transcript(vector: Vector) throws {
        let secret = try #require([UInt8](hex: vector.secret))
        let joinerNonce = try #require([UInt8](hex: vector.joinerNonce))
        let hostNonce = try #require([UInt8](hex: vector.hostNonce))
        let proofTranscript = PairingProofTranscript(
            joinerNonce: joinerNonce, hostCommitment: try #require([UInt8](hex: vector.hostCommitment)),
            offerHost: vector.offerHost, offerPort: vector.offerPort, deviceName: Array(vector.deviceName.utf8),
            endpoints: try vector.endpoints)
        #expect(proofTranscript.bytes.count == PairingProofTranscript.length)
        #expect(proofTranscript.bytes.hex == vector.proofTranscript)
        #expect(
            PairingMessage.Proof(nonce: joinerNonce, code: proofTranscript.proof(secret: secret)).encoded.hex
                == vector.proof)

        let transcript = try #require(proofTranscript.opened(with: hostNonce))
        #expect(transcript.bytes.count == PairingTranscript.length)
        #expect(transcript.bytes.hex == vector.transcript)
        #expect(
            PairingMessage.Accepted(nonce: hostNonce, code: transcript.accepted(secret: secret)).encoded.hex
                == vector.accepted)
        #expect(transcript.confirmationCode(secret: secret) == vector.confirmationCode)

        let stableID = try #require(vector.approved.stableID)
        let approval = try #require(
            PairingMessage.Decision.approval(stableID: stableID, name: vector.approved.name ?? ""))
        for (decision, expected) in [(approval, vector.approved), (.denied, vector.denied), (.timedOut, vector.timedOut)] {
            let message = decision.body + transcript.decisionCode(for: decision.body, secret: secret)
            #expect(message.hex == expected.bytes)
        }
    }

    @Test("두 상태 기계를 맞물리면 선 위의 바이트가 벡터와 같다", arguments: vectors)
    func wholeProcedure(vector: Vector) throws {
        let offer = try vector.offer
        var machine = PairingHostMachine()
        machine.open(offer)
        let now = ContinuousClock.now
        _ = machine.accept(
            1, from: Sample.joinerIdentity, endpoints: try vector.endpoints,
            nonce: try #require([UInt8](hex: vector.hostNonce)), at: now)
        var joiner = PairingJoinerSession(
            offer: offer, deviceName: try Sample.deviceName(vector.deviceName),
            nonce: try #require([UInt8](hex: vector.joinerNonce)), endpoints: try vector.endpoints,
            challengeDeadline: now + .seconds(60))

        #expect(joiner.hello.hex == vector.hello)
        let challenge = machine.receive(joiner.hello, on: 1, wallClock: Sample.wallClock, now: now)
        #expect(challenge.sentBytes.hex == vector.challenge)
        let proof = joiner.receive(challenge.sentBytes, at: now)
        #expect(proof.sentBytes.hex == vector.proof)
        let accepted = machine.receive(proof.sentBytes, on: 1, wallClock: Sample.wallClock, now: now)
        #expect(accepted.sentBytes.hex == vector.accepted)
        guard case .requestDecision(let request)? = accepted.last else {
            Issue.record("결정 요청이 나오지 않았다")
            return
        }
        #expect(request.confirmationCode == vector.confirmationCode)
        #expect(request.deviceName == vector.deviceName)
        #expect(joiner.receive(accepted.sentBytes, at: now).confirmationCode == vector.confirmationCode)

        _ = machine.decided(
            1, approved: true, currentPeer: Sample.joinerIdentity, host: try vector.hostIdentity, at: Sample.wallClock)
        let decision = machine.saved(1, succeeded: true)
        #expect(decision.sentBytes.hex == vector.approved.bytes)
        let approval = PairingJoinerSession.Approval(
            stableID: try #require(vector.approved.stableID), name: vector.approved.name ?? "")
        #expect(joiner.receive(decision.sentBytes, at: now).result == .success(approval))
    }
}
