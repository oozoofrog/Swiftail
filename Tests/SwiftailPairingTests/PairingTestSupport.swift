// Shared values and helpers for pairing unit tests. All values are fake (fake tailnet `tail0001`, fake addresses `100.64.0.x`).

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
    /// A time when the offer is valid and the expiration time.
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

    /// The commitment commitH that the host puts in `challenge`.
    static let hostCommitment = PairingTranscript.commitment(toHostNonce: hostNonce)

    /// Builds P from `Sample` values, with optional overrides for the joiner nonce, offer, and connection endpoints.
    static func proofTranscript(
        joinerNonce: [UInt8] = joinerNonce, offer: PairingOffer = offer(), endpoints: PairingEndpoints? = nil
    ) throws -> PairingProofTranscript {
        PairingProofTranscript(
            joinerNonce: joinerNonce, hostCommitment: hostCommitment, offerHost: offer.host, offerPort: offer.port,
            deviceName: Array("rd-phone-5e6f7a8b".utf8), endpoints: try endpoints ?? Sample.endpoints())
    }

    /// Builds T from the same values after the host nonce is also opened.
    static func transcript(
        joinerNonce: [UInt8] = joinerNonce, offer: PairingOffer = offer(), endpoints: PairingEndpoints? = nil
    ) throws -> PairingTranscript {
        try #require(
            try proofTranscript(joinerNonce: joinerNonce, offer: offer, endpoints: endpoints).opened(with: hostNonce))
    }

    /// The `accepted` that the host sends using `Sample` values, with the revealed nonceH and the HMAC of T.
    static func accepted() throws -> [UInt8] {
        hostNonce + (try transcript()).accepted(secret: secret)
    }

    /// Returns the path to an empty temporary directory for the test to create and remove. The directory is not created here.
    static func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "swiftail-pairing-\(UUID().uuidString)")
    }
}

/// Reduces host state machine actions to a comparable form because `PairingRequest` is not `Equatable`.
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
    /// The bytes to send, concatenated in order.
    var sentBytes: [UInt8] {
        flatMap { action -> [UInt8] in if case .send(let bytes) = action { bytes } else { [] } }
    }
}

extension [PairingJoinerSession.Action] {
    var sentBytes: [UInt8] {
        flatMap { action -> [UInt8] in if case .send(let bytes) = action { bytes } else { [] } }
    }

    /// The outcome if the flow has finished.
    var result: Result<PairingJoinerSession.Approval, PairingError>? {
        compactMap { action in if case .finish(let result) = action { result } else { nil } }.first
    }

    var confirmationCode: String? {
        compactMap { action in if case .awaitingApproval(let code) = action { code } else { nil } }.first
    }
}

/// Wires a host state machine and joiner connection together in memory. Tests can stop and intervene after each step.
struct PairingRehearsal {
    static let sessionID: PairingHostMachine.SessionID = 1

    var machine = PairingHostMachine()
    var joiner: PairingJoinerSession
    let start = ContinuousClock.now
    let offer: PairingOffer

    /// Opens an offer, accepts one connection, and creates the joiner connection.
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

    /// Feeds bytes from the joiner into the host.
    mutating func toHost(_ bytes: [UInt8], wallClock: Date = Sample.wallClock) -> [PairingHostMachine.Action] {
        machine.receive(bytes, on: Self.sessionID, wallClock: wallClock, now: start)
    }

    /// Feeds bytes from the host into the joiner.
    mutating func toJoiner(_ bytes: [UInt8]) -> [PairingJoinerSession.Action] {
        joiner.receive(bytes, at: start)
    }

    /// Exchanges `hello` and `challenge`, then `proof` and `accepted`, leaving the decision pending. Returns the SAS from the host request
    /// and the SAS received by the joiner.
    mutating func reachDecision() throws -> (hostCode: String, joinerCode: String) {
        let challenge = toHost(joiner.hello)
        let proof = toJoiner(challenge.sentBytes)
        let accepted = toHost(proof.sentBytes)
        guard case .requestDecision(let request)? = accepted.last else {
            throw RehearsalFailure(description: "No decision request was issued: \(HostStep.steps(accepted))")
        }
        let waiting = toJoiner(accepted.sentBytes)
        return (request.confirmationCode, try #require(waiting.confirmationCode))
    }

    /// The actions issued by the host after app approval and successful storage.
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

/// Returns the `PairingError` thrown by `body`, or nil if it does not throw. Any other error fails the test.
func pairingError<T>(_ body: () async throws -> T) async -> PairingError? {
    do {
        _ = try await body()
        return nil
    } catch let error as PairingError {
        return error
    } catch {
        Issue.record("Unexpected error type instead of PairingError: \(error)")
        return nil
    }
}
