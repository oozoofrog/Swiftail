import CryptoKit
import Foundation
import SwiftailBase
import Testing
@testable import SwiftailPairing

/// Tests the joiner state machine (contract behaviors J2–J5, §7 test 4).
@Suite("Joiner state machine")
struct JoinerSessionTests {
    private typealias Rehearsal = PairingRehearsal
    private typealias Approval = PairingJoinerSession.Approval

    /// The T that the host builds using `Sample` values.
    private static func transcript() throws -> PairingTranscript {
        try Sample.transcript()
    }

    /// The `challenge` that the host sends to continue.
    private static let challenge = [0] + Sample.hostCommitment

    /// A `decision` with an HMAC matching its body.
    private static func signed(_ body: [UInt8]) throws -> [UInt8] {
        body + (try transcript()).decisionCode(for: body, secret: Sample.secret)
    }

    private static func approvedBody(stableID: [UInt8], name: [UInt8]) -> [UInt8] {
        [1, UInt8(truncatingIfNeeded: stableID.count)] + stableID + [UInt8(truncatingIfNeeded: name.count)] + name
    }

    /// A connection waiting for a decision after a valid `accepted`.
    private static func waitingJoiner(at now: ContinuousClock.Instant = .now) throws -> PairingJoinerSession {
        var joiner = PairingJoinerSession(
            offer: Sample.offer(), deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: now + .seconds(60))
        let proof = joiner.receive(challenge, at: now)
        #expect(proof.sentBytes == Sample.joinerNonce + (try Sample.proofTranscript()).proof(secret: Sample.secret))
        let waiting = joiner.receive(try Sample.accepted(), at: now)
        #expect(waiting.confirmationCode == (try transcript()).confirmationCode(secret: Sample.secret))
        return joiner
    }

    // MARK: challenge (J3)

    @Test("Status 1 in challenge returns rejected. An unknown status or extra bytes is a violation")
    func readsChallenge() throws {
        var refused = try Rehearsal().joiner
        #expect(refused.receive([1] + Sample.hostCommitment, at: .now) == [.finish(.failure(.rejected))])

        var unknown = try Rehearsal().joiner
        #expect(unknown.receive([2], at: .now) == [.finish(.failure(.protocolViolation))])

        var overlong = try Rehearsal().joiner
        #expect(overlong.receive(Self.challenge + [0], at: .now) == [.finish(.failure(.protocolViolation))])

        var partial = try Rehearsal().joiner
        #expect(partial.receive(Array(Self.challenge.dropLast()), at: .now).isEmpty, "Waits until all bytes arrive")
        #expect(partial.receive([Self.challenge[32]], at: .now).sentBytes.count == 64)
    }

    @Test("hello carries the nonce commitment. The nonce is opened in proof after receiving challenge")
    func commitsToNonceBeforeChallenge() throws {
        var joiner = try Rehearsal().joiner
        let commitment = PairingTranscript.commitment(toJoinerNonce: Sample.joinerNonce)
        #expect(joiner.hello == Array("SWPR".utf8) + [3] + commitment + [17] + Array("rd-phone-5e6f7a8b".utf8))
        #expect(commitment != Sample.joinerNonce)
        // The commitments have different labels, so each party commits differently even with the same nonce. A party cannot reflect the peer's commitment back.
        #expect(commitment != PairingTranscript.commitment(toHostNonce: Sample.joinerNonce))

        let proof = joiner.receive(Self.challenge, at: .now).sentBytes
        #expect(Array(proof.prefix(32)) == Sample.joinerNonce)
    }

    @Test("The result depends on when the connection ends: unreachable before challenge, rejected after proof, and a violation while awaiting a decision")
    func classifiesConnectionEnd() throws {
        var early = try Rehearsal().joiner
        #expect(early.connectionEnded() == [.finish(.failure(.unreachable))])
        #expect(early.connectionEnded().isEmpty && early.deadline == nil, "Discards events after completion")

        var proved = try Rehearsal().joiner
        _ = proved.receive(Self.challenge, at: .now)
        #expect(proved.connectionEnded() == [.finish(.failure(.rejected))])

        var waiting = try Self.waitingJoiner()
        #expect(waiting.connectionEnded() == [.finish(.failure(.protocolViolation))])
    }

    // MARK: accepted (J4)

    @Test("An invalid accepted returns hostNotVerified and produces no SAS")
    func rejectsWrongAccepted() throws {
        var accepted = try Sample.accepted()
        accepted[63] ^= 1
        var joiner = try Rehearsal().joiner
        _ = joiner.receive(Self.challenge, at: .now)
        #expect(joiner.receive(accepted, at: .now) == [.finish(.failure(.hostNotVerified))])

        // Sending back a value with a different label (proof) also fails.
        var echoed = try Rehearsal().joiner
        let proof = echoed.receive(Self.challenge, at: .now).sentBytes
        #expect(echoed.receive(Sample.hostNonce + proof.suffix(32), at: .now) == [.finish(.failure(.hostNotVerified))])
    }

    @Test("A nonceH in accepted that differs from the challenge commitment returns hostNotVerified even with a valid HMAC for that nonce")
    func rejectsHostNonceThatBreaksCommitment() throws {
        // The host knows the secret and tries changing the nonce after seeing nonceJ to choose the SAS. It computes a valid HMAC using that nonce.
        var other = Sample.hostNonce
        other[0] ^= 1
        let forged = try Sample.proofTranscript().bytes + other
        let code = HMAC<SHA256>.authenticationCode(
            for: Array("swiftail-pairing-3 host".utf8) + forged, using: SymmetricKey(data: Sample.secret))
        var joiner = try Rehearsal().joiner
        _ = joiner.receive(Self.challenge, at: .now)
        #expect(joiner.receive(other + Array(code), at: .now) == [.finish(.failure(.hostNotVerified))])

        // The same construction is accepted with the committed nonce. The earlier rejection was due to the commitment.
        let honest = try Sample.proofTranscript().bytes + Sample.hostNonce
        let honestCode = HMAC<SHA256>.authenticationCode(
            for: Array("swiftail-pairing-3 host".utf8) + honest, using: SymmetricKey(data: Sample.secret))
        var second = try Rehearsal().joiner
        _ = second.receive(Self.challenge, at: .now)
        #expect(second.receive(Sample.hostNonce + Array(honestCode), at: .now).confirmationCode != nil)
    }

    @Test("The SAS is produced only after validating accepted, even if accepted arrives one byte at a time")
    func confirmationCodeFollowsAccepted() throws {
        var joiner = try Rehearsal().joiner
        _ = joiner.receive(Self.challenge, at: .now)
        let accepted = try Sample.accepted()
        for byte in accepted.dropLast() {
            #expect(joiner.receive([byte], at: .now).isEmpty)
        }
        let code = try Self.transcript().confirmationCode(secret: Sample.secret)
        #expect(joiner.receive([accepted[63]], at: .now) == [.awaitingApproval(confirmationCode: code)])
    }

    @Test("Reads accepted and decision in order even if they arrive together")
    func readsCoalescedMessages() throws {
        var joiner = try Rehearsal().joiner
        _ = joiner.receive(Self.challenge, at: .now)
        let transcript = try Self.transcript()
        let actions = joiner.receive(try Sample.accepted() + (try Self.signed([2])), at: .now)
        #expect(
            actions == [
                .awaitingApproval(confirmationCode: transcript.confirmationCode(secret: Sample.secret)),
                .finish(.failure(.denied)),
            ])
    }

    // MARK: decision (J5)

    @Test("Approval, rejection, and timeout")
    func readsDecisions() throws {
        var approved = try Self.waitingJoiner()
        let body = Self.approvedBody(stableID: Array("nEXAMPLEHOST".utf8), name: Array("거실 Mac".utf8))
        #expect(
            approved.receive(try Self.signed(body), at: .now)
                == [.finish(.success(Approval(stableID: "nEXAMPLEHOST", name: "거실 Mac")))])

        var unnamed = try Self.waitingJoiner()
        let bare = Self.approvedBody(stableID: Array("n".utf8), name: [])
        #expect(unnamed.receive(try Self.signed(bare), at: .now) == [.finish(.success(Approval(stableID: "n", name: "")))])

        var denied = try Self.waitingJoiner()
        #expect(denied.receive(try Self.signed([2]), at: .now) == [.finish(.failure(.denied))])
        var timedOut = try Self.waitingJoiner()
        #expect(timedOut.receive(try Self.signed([3]), at: .now) == [.finish(.failure(.timedOut))])
    }

    @Test("An invalid decision HMAC returns hostNotVerified, even when only the body changes")
    func rejectsWrongDecisionCode() throws {
        var flipped = try Self.signed([2])
        flipped[32] ^= 0x80
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive(flipped, at: .now) == [.finish(.failure(.hostNotVerified))])

        // Attach the HMAC for rejection (2) to timeout (3).
        var swapped = try Self.signed([2])
        swapped[0] = 3
        var second = try Self.waitingJoiner()
        #expect(second.receive(swapped, at: .now) == [.finish(.failure(.hostNotVerified))])

        // Change one character in the approval StableID.
        var renamed = try Self.signed(Self.approvedBody(stableID: Array("nEXAMPLEHOST".utf8), name: Array("mac".utf8)))
        renamed[2] = UInt8(ascii: "m")
        var third = try Self.waitingJoiner()
        #expect(third.receive(renamed, at: .now) == [.finish(.failure(.hostNotVerified))])

        // An HMAC generated with a different secret.
        let foreign = [2] + (try Self.transcript()).decisionCode(for: [2], secret: [UInt8](repeating: 0x5B, count: 32))
        var fourth = try Self.waitingJoiner()
        #expect(fourth.receive(foreign, at: .now) == [.finish(.failure(.hostNotVerified))])
    }

    @Test("An unknown status is a violation", arguments: [UInt8(0), 4, 0xFF])
    func rejectsUnknownStatus(status: UInt8) throws {
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive([status], at: .now) == [.finish(.failure(.protocolViolation))])
    }

    @Test(
        "Nonconforming content is a violation even with a valid HMAC",
        arguments: [
            JoinerSessionTests.approvedBody(stableID: [], name: Array("mac".utf8)),                         // StableID length 0
            JoinerSessionTests.approvedBody(stableID: Array("n\u{7F}".utf8), name: []),                     // Nonprintable ASCII
            JoinerSessionTests.approvedBody(stableID: Array("n\n".utf8), name: []),
            JoinerSessionTests.approvedBody(stableID: Array("né".utf8), name: []),                          // Non-ASCII
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: [UInt8](repeating: 0x61, count: 65)),   // 65-byte name
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: [0xFF]),                       // Invalid UTF-8
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: [0xED, 0xA0, 0x80]),           // Surrogate code point
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: Array("a\u{202E}b".utf8)),     // Cf
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: Array("a\u{1B}[2J".utf8)),     // Cc
        ])
    func rejectsInvalidApproval(body: [UInt8]) throws {
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive(try Self.signed(body), at: .now) == [.finish(.failure(.protocolViolation))])
    }

    @Test("Extra bytes after decision are a violation")
    func rejectsTrailingBytes() throws {
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive(try Self.signed([2]) + [0], at: .now) == [.finish(.failure(.protocolViolation))])
    }

    @Test("StableID boundary: 255 bytes")
    func acceptsLongestStableID() throws {
        let stableID = [UInt8](repeating: UInt8(ascii: "n"), count: 255)
        let name = Array(String(repeating: "a", count: 64).utf8)
        var joiner = try Self.waitingJoiner()
        let message = try Self.signed(Self.approvedBody(stableID: stableID, name: name))
        var result: Result<Approval, PairingError>?
        for byte in message {
            #expect(result == nil)
            result = joiner.receive([byte], at: .now).result
        }
        #expect(result == .success(Approval(stableID: String(repeating: "n", count: 255), name: String(repeating: "a", count: 64))))
    }

    // MARK: Deadlines (J1, J4)

    @Test("The deadline before challenge is used as supplied, and passing it returns unreachable")
    func timesOutBeforeChallenge() throws {
        var rehearsal = try Rehearsal()
        #expect(rehearsal.joiner.deadline == rehearsal.start + .seconds(60))
        #expect(rehearsal.joiner.advance(to: rehearsal.start + .seconds(59)).isEmpty)
        #expect(rehearsal.joiner.advance(to: rehearsal.start + .seconds(60)) == [.finish(.failure(.unreachable))])
    }

    @Test("If no decision arrives within 130 seconds of sending proof, returns timedOut")
    func timesOutWaitingForDecision() throws {
        let start = ContinuousClock.now
        var joiner = try Self.waitingJoiner(at: start + .seconds(5))
        #expect(joiner.deadline == start + .seconds(135))
        #expect(joiner.advance(to: start + .seconds(60)).isEmpty, "The challenge deadline no longer applies")
        #expect(joiner.advance(to: start + .milliseconds(134_999)).isEmpty)
        #expect(joiner.advance(to: start + .seconds(135)) == [.finish(.failure(.timedOut))])
        #expect(joiner.receive(try Self.signed([2]), at: start + .seconds(136)).isEmpty, "Discards bytes after completion")
    }

    // MARK: Connection endpoints (§5, J2)

    @Test("If an intermediary forwards the bytes, the parties see different endpoints and the proof fails")
    func relayedProofDoesNotVerify() throws {
        // The joiner sees the relay node (100.64.0.9) as the host, and the host sees the relay node as the joiner.
        var rehearsal = try Rehearsal(
            hostSees: try Sample.endpoints(joiner: "100.64.0.9:50000", host: "100.64.0.1:4747"),
            joinerSees: try Sample.endpoints(joiner: "100.64.0.2:49152", host: "100.64.0.9:4747"))
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes)
        #expect(HostStep.steps(rehearsal.toHost(proof.sentBytes)) == [.finish(.wrongProof)])
        #expect(rehearsal.machine.hasOpenOffer)
    }

    @Test("Changing just one endpoint changes P, T, and all four values", arguments: [
        ("100.64.0.3:49152", "100.64.0.1:4747"), ("100.64.0.2:49153", "100.64.0.1:4747"),
        ("100.64.0.2:49152", "100.64.0.4:4747"), ("100.64.0.2:49152", "100.64.0.1:4748"),
        ("[fd7a:115c:a1e0::2]:49152", "100.64.0.1:4747"),
    ])
    func transcriptBindsEndpoints(joiner: String, host: String) throws {
        let endpoints = try Sample.endpoints(joiner: joiner, host: host)
        let base = try Self.transcript()
        let other = try Sample.transcript(endpoints: endpoints)
        #expect(other.bytes.count == 230 && other.bytes != base.bytes)
        #expect(
            try Sample.proofTranscript(endpoints: endpoints).proof(secret: Sample.secret)
                != (try Sample.proofTranscript()).proof(secret: Sample.secret))
        #expect(other.accepted(secret: Sample.secret) != base.accepted(secret: Sample.secret))
        #expect(other.decisionCode(for: [2], secret: Sample.secret) != base.decisionCode(for: [2], secret: Sample.secret))
        #expect(other.confirmationCode(secret: Sample.secret) != base.confirmationCode(secret: Sample.secret))

        // If the joiner sees a different endpoint, it also rejects the host's accepted.
        var session = PairingJoinerSession(
            offer: Sample.offer(), deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: endpoints, challengeDeadline: .now + .seconds(60))
        _ = session.receive(Self.challenge, at: .now)
        #expect(session.receive(try Sample.accepted(), at: .now) == [.finish(.failure(.hostNotVerified))])
    }

    @Test("IPv4 and its IPv4-mapped IPv6 form use the same 16 bytes in T")
    func mapsIPv4() throws {
        let mapped = try Sample.transcript(
            endpoints: try Sample.endpoints(joiner: "[::ffff:100.64.0.2]:49152", host: "[::ffff:100.64.0.1]:4747"))
        #expect(mapped == (try Self.transcript()))
    }

    @Test(
        "Is this a tailnet address? (J2)",
        arguments: [
            ("100.64.0.1", true), ("100.127.255.255", true), ("100.100.100.100", true), ("::ffff:100.64.0.1", true),
            ("fd7a:115c:a1e0::1", true), ("fd7a:115c:a1e0:ab12:4843:cd96:6264:1", true),
            ("100.63.255.255", false), ("100.128.0.0", false), ("101.64.0.1", false), ("127.0.0.1", false),
            ("192.168.0.1", false), ("10.0.0.1", false), ("::ffff:127.0.0.1", false), ("::1", false),
            ("fd7a:115c:a1e1::1", false), ("fe80::1", false), ("2001:db8::1", false),
        ])
    func recognizesTailnetAddresses(address: String, expected: Bool) throws {
        #expect(PairingEndpoints.isTailnetAddress(try #require(IPAddress(address))) == expected)
    }

    @Test("A connection counts as using the tunnel only if the local endpoint is this device's tailnet address and the remote endpoint is in the tailnet range (J2)")
    func requiresLocalAddressAndTailnetPeer() throws {
        let local = try #require(IPAddress("100.64.0.2"))
        let local6 = try #require(IPAddress("fd7a:115c:a1e0::2"))
        #expect(try Sample.endpoints().isOnTailnet(localAddress: local))
        #expect(try Sample.endpoints(joiner: "[::ffff:100.64.0.2]:49152").isOnTailnet(localAddress: local))
        #expect(
            try Sample.endpoints(joiner: "[fd7a:115c:a1e0::2]:49152", host: "[fd7a:115c:a1e0::1]:4747")
                .isOnTailnet(localAddress: local6))

        // A local network uses the same range with the tunnel off. Both endpoints are in 100.64.0.0/10, but the local endpoint is not this device's address.
        #expect(try !Sample.endpoints(joiner: "100.64.0.77:49152").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(joiner: "[fd7a:115c:a1e0::2]:49152").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(joiner: "192.168.0.7:49152").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(host: "203.0.113.5:4747").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(host: "192.168.0.1:4747").isOnTailnet(localAddress: local))
    }

    @Test("A localAddress outside the tailnet range prevents dialing and returns invalidConfiguration", arguments: ["192.168.0.7", "127.0.0.1", "100.128.0.1", "fe80::1"])
    func rejectsLocalAddressOutsideTailnet(address: String) async throws {
        let localAddress = try #require(IPAddress(address))
        let error = await pairingError {
            try await PairingJoiner.pair(with: Sample.offer(), deviceName: "rd-phone-5e6f7a8b", localAddress: localAddress)
        }
        guard case .invalidConfiguration = error else {
            Issue.record("Expected invalidConfiguration: \(String(describing: error))")
            return
        }
    }
}
