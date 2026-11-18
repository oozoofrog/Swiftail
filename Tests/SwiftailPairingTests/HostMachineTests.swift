import Foundation
import Swiftail
import Testing
@testable import SwiftailPairing

/// Tests the host state machine (contract behaviors P1–P9, §7 test 3). Passes time and random values directly for deterministic execution.
@Suite("Host state machine")
struct HostMachineTests {
    private typealias Rehearsal = PairingRehearsal
    private static let id = PairingRehearsal.sessionID

    /// Builds a `hello` with the bytes of `name` copied directly into the name field, bypassing validation.
    private static func rawHello(name: [UInt8], prefix: [UInt8] = Array("SWPR".utf8) + [3]) -> [UInt8] {
        prefix + PairingTranscript.commitment(toJoinerNonce: Sample.joinerNonce)
            + [UInt8(truncatingIfNeeded: name.count)] + name
    }

    /// A joining node that differs only in `stableID`.
    private static func joiner(_ stableID: String) -> PeerIdentity {
        var identity = Sample.joinerIdentity
        identity.stableID = stableID
        return identity
    }

    /// Builds a `proof` that opens the `nonce` for a party that knows the offer secret. The HMAC of P built with that nonce is valid.
    private static func proof(opening nonce: [UInt8], offer: PairingOffer = Sample.offer()) throws -> [UInt8] {
        let transcript = try Sample.proofTranscript(joinerNonce: nonce, offer: offer)
        return PairingMessage.Proof(nonce: nonce, code: transcript.proof(secret: offer.secret)).encoded
    }

    /// Accepts connection `id` on a machine with an open offer and completes the exchange through a valid `proof`. Returns the decision request action.
    private static func prove(
        _ machine: inout PairingHostMachine, id: PairingHostMachine.SessionID, offer: PairingOffer,
        at now: ContinuousClock.Instant
    ) throws -> [PairingHostMachine.Action] {
        _ = machine.accept(
            id, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce, at: now)
        var joiner = PairingJoinerSession(
            offer: offer, deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: now + .seconds(60))
        let challenge = machine.receive(joiner.hello, on: id, wallClock: Sample.wallClock, now: now)
        let proof = joiner.receive(challenge.sentBytes, at: now)
        return machine.receive(proof.sentBytes, on: id, wallClock: Sample.wallClock, now: now)
    }

    // MARK: Successful path

    @Test("Successful path: hello → challenge → proof → accepted and decision request → storage → approval")
    func pairs() throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        #expect(HostStep.steps(challenge) == [.send([0] + Sample.hostCommitment)])
        #expect(rehearsal.machine.hasOpenOffer, "The offer stays unchanged until proof arrives")

        let proof = rehearsal.toJoiner(challenge.sentBytes)
        let accepted = HostStep.steps(rehearsal.toHost(proof.sentBytes))
        #expect(accepted.count == 2)
        guard case .send(let acceptedBytes) = accepted[0],
              case .requestDecision("nEXAMPLEJOINER", "rd-phone-5e6f7a8b", let hostCode) = accepted[1]
        else {
            Issue.record("Expected accepted and a decision request: \(accepted)")
            return
        }
        #expect(acceptedBytes.count == 64 && Array(acceptedBytes.prefix(32)) == Sample.hostNonce)
        #expect(hostCode.count == 6 && hostCode.allSatisfy(\.isNumber))
        #expect(!rehearsal.machine.hasOpenOffer, "A valid proof consumes the offer immediately (P4)")
        #expect(rehearsal.toJoiner(acceptedBytes).confirmationCode == hostCode, "Both sides have the same SAS")

        let decided = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        let peer = PairedPeer(peer: Sample.joinerIdentity, deviceName: "rd-phone-5e6f7a8b", pairedAt: Sample.wallClock)
        #expect(HostStep.steps(decided) == [.save(peer)], "Approval is sent only after storage (P7)")
        #expect(rehearsal.machine.deadline(of: Self.id) == nil)

        let saved = rehearsal.machine.saved(Self.id, succeeded: true)
        #expect(HostStep.steps(saved).last == .finish(.paired))
        #expect(rehearsal.machine.sessionCount == 0)
        let approval = PairingJoinerSession.Approval(stableID: "nEXAMPLEHOST", name: "rd-mac-1a2b3c4d")
        #expect(rehearsal.toJoiner(saved.sentBytes).result == .success(approval))
    }

    @Test("The result is the same when bytes arrive one at a time")
    func acceptsFragmentedMessages() throws {
        var rehearsal = try Rehearsal()
        var challenge: [PairingHostMachine.Action] = []
        for byte in rehearsal.joiner.hello {
            #expect(challenge.isEmpty)
            challenge = rehearsal.toHost([byte])
        }
        let proof = rehearsal.toJoiner(challenge.sentBytes).sentBytes
        var accepted: [PairingHostMachine.Action] = []
        for byte in proof {
            #expect(accepted.isEmpty)
            accepted = rehearsal.toHost([byte])
        }
        #expect(accepted.count == 2)
    }

    @Test("Records the identity at approval as the paired peer, with a snapshot of the name")
    func savesCurrentIdentity() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        var renamed = Sample.joinerIdentity
        renamed.computedName = "rd-phone-renamed"
        let decided = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: renamed, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(
            HostStep.steps(decided)
                == [.save(PairedPeer(peer: renamed, deviceName: "rd-phone-5e6f7a8b", pairedAt: Sample.wallClock))])
    }

    @Test("A display name over 64 bytes is truncated at a character boundary before sending")
    func truncatesHostName() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        var host = Sample.hostIdentity
        host.computedName = String(repeating: "표", count: 30)   // 90 bytes
        _ = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: host, at: Sample.wallClock)
        let saved = rehearsal.machine.saved(Self.id, succeeded: true)
        let approval = PairingJoinerSession.Approval(stableID: "nEXAMPLEHOST", name: String(repeating: "표", count: 21))
        #expect(rehearsal.toJoiner(saved.sentBytes).result == .success(approval))
    }

    // MARK: Admission (P1, P8)

    @Test("Peers with unknown identities are not admitted (P1)")
    func refusesUnknownPeer() throws {
        var machine = PairingHostMachine()
        machine.open(Sample.offer())
        let actions = machine.accept(
            1, from: nil, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce, at: .now)
        #expect(HostStep.steps(actions) == [.finish(.unknownPeer)])
        #expect(machine.sessionCount == 0)
        #expect(machine.receive([1], on: 1, wallClock: Sample.wallClock, now: .now).isEmpty)
    }

    @Test("Up to 8 connections may be in progress. Excess connections close immediately, and new connections are accepted when a slot opens")
    func limitsSessions() throws {
        var machine = PairingHostMachine()
        let endpoints = try Sample.endpoints()
        for id in UInt64(0)..<8 {
            #expect(machine.accept(id, from: Self.joiner("n\(id)"), endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
        }
        let ninth = machine.accept(8, from: Self.joiner("n8"), endpoints: endpoints, nonce: Sample.hostNonce, at: .now)
        #expect(HostStep.steps(ninth) == [.finish(.limitReached)])
        #expect(machine.sessionCount == 8)

        #expect(HostStep.steps(machine.connectionEnded(3)) == [.finish(.disconnected)])
        #expect(machine.accept(9, from: Self.joiner("n9"), endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
        #expect(machine.sessionCount == 8)
    }

    @Test("One node can have up to 2 connections in progress. Other nodes still have slots, and the node can connect again when one ends (P8)")
    func limitsSessionsPerPeer() throws {
        var machine = PairingHostMachine()
        machine.open(Sample.offer())
        let endpoints = try Sample.endpoints()
        let greedy = Self.joiner("nGREEDY")
        #expect(machine.accept(0, from: greedy, endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
        #expect(machine.accept(1, from: greedy, endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
        for id in UInt64(2)..<6 {
            let refused = machine.accept(id, from: greedy, endpoints: endpoints, nonce: Sample.hostNonce, at: .now)
            #expect(HostStep.steps(refused) == [.finish(.peerLimitReached)])
        }
        #expect(machine.sessionCount == 2)
        #expect(machine.receive([1], on: 2, wallClock: Sample.wallClock, now: .now).isEmpty, "The rejected connection was not admitted")

        // The other node still connects and completes pairing.
        #expect(try Self.prove(&machine, id: 6, offer: Sample.offer(), at: .now).count == 2)

        #expect(HostStep.steps(machine.connectionEnded(0)) == [.finish(.disconnected)])
        #expect(machine.accept(7, from: greedy, endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
    }

    // MARK: Offer (P2–P4, P9)

    @Test("With no open offer, the host reads hello, sends status 1, and closes (P2)")
    func reportsNoOffer() throws {
        var rehearsal = try Rehearsal()
        rehearsal.machine.closeOffer()
        #expect(rehearsal.toHost(Array(rehearsal.joiner.hello.dropLast())).isEmpty, "The host stays silent until the entire hello arrives")
        let actions = rehearsal.toHost([rehearsal.joiner.hello.last ?? 0])
        #expect(HostStep.steps(actions) == [.send([1] + Sample.hostCommitment), .finish(.noOffer)])
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.rejected))
    }

    @Test("An expired offer also produces status 1. It can be used until just before expiration")
    func reportsExpiredOffer() throws {
        var live = try Rehearsal()
        let before = live.toHost(live.joiner.hello, wallClock: Sample.expires.addingTimeInterval(-0.001))
        #expect(HostStep.steps(before) == [.send([0] + Sample.hostCommitment)])

        var expired = try Rehearsal()
        let after = expired.toHost(expired.joiner.hello, wallClock: Sample.expires)
        #expect(HostStep.steps(after) == [.send([1] + Sample.hostCommitment), .finish(.noOffer)])
        #expect(expired.machine.hasOpenOffer, "Observing expiration does not remove the offer")
    }

    @Test("An invalid proof closes the connection silently. The offer remains available to the next connection (P3)")
    func keepsOfferAfterWrongProof() throws {
        let wrong = Sample.offer(secret: [UInt8](repeating: 0x5B, count: 32))
        var rehearsal = try Rehearsal()
        var stranger = PairingJoinerSession(
            offer: wrong, deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: rehearsal.start + .seconds(60))
        let challenge = rehearsal.toHost(stranger.hello)
        let proof = stranger.receive(challenge.sentBytes, at: rehearsal.start)
        #expect(HostStep.steps(rehearsal.toHost(proof.sentBytes)) == [.finish(.wrongProof)])
        #expect(rehearsal.machine.hasOpenOffer)
        #expect(stranger.connectionEnded().result == .failure(.rejected))

        let accepted = try Self.prove(&rehearsal.machine, id: 2, offer: Sample.offer(), at: rehearsal.start)
        #expect(accepted.count == 2, "A connection that presents a valid proof for the same offer is accepted")
    }

    @Test("A proof that opens a different nonce than committed closes the connection even with a valid HMAC. The offer remains available to the next connection (P3)")
    func rejectsNonceThatBreaksCommitment() throws {
        var rehearsal = try Rehearsal()
        _ = rehearsal.toHost(rehearsal.joiner.hello)   // The committed value is Sample.joinerNonce
        var other = Sample.joinerNonce
        other[31] ^= 1
        #expect(HostStep.steps(rehearsal.toHost(try Self.proof(opening: other))) == [.finish(.malformed)])
        #expect(rehearsal.machine.hasOpenOffer && rehearsal.machine.sessionCount == 0)

        let accepted = try Self.prove(&rehearsal.machine, id: 2, offer: Sample.offer(), at: rehearsal.start)
        #expect(accepted.count == 2)
    }

    @Test("nonceJ is fixed after hello and challenge. Every attempt to open another nonce to choose the SAS closes the connection")
    func commitmentFixesConfirmationCode() throws {
        // The joiner knows the secret and tries different nonces after seeing `challenge` to choose the SAS.
        // All candidates differ from the committed nonce (filled with 0x11).
        let candidates = (UInt8(0x80)...0xBF).map { [UInt8](repeating: $0, count: 32) }
        let codes = try candidates.map { nonce in
            try Sample.transcript(joinerNonce: nonce).confirmationCode(secret: Sample.secret)
        }
        #expect(Set(codes).count > 32, "Choosing the nonce would allow choosing the SAS")

        for nonce in candidates {
            // On each connection, `hello` commits to Sample.joinerNonce. The host committed to its own nonce without knowing that value.
            var rehearsal = try Rehearsal()
            let challenge = rehearsal.toHost(rehearsal.joiner.hello)
            #expect(challenge.sentBytes == [0] + Sample.hostCommitment)
            let actions = rehearsal.toHost(try Self.proof(opening: nonce))
            #expect(HostStep.steps(actions) == [.finish(.malformed)], "A nonce that differs from the commitment never reaches the app")
            #expect(rehearsal.machine.hasOpenOffer)
        }

        // The host accepts the committed nonce when opened, and the SAS uses the nonce already fixed by the commitment.
        var honest = try Rehearsal()
        _ = honest.toHost(honest.joiner.hello)
        let accepted = HostStep.steps(honest.toHost(try Self.proof(opening: Sample.joinerNonce)))
        guard case .requestDecision(_, _, let code)? = accepted.last else {
            Issue.record("Expected a decision request: \(accepted)")
            return
        }
        #expect(code == (try Sample.transcript()).confirmationCode(secret: Sample.secret))
    }

    @Test("The host sends its nonce only after a valid proof. Even with the secret, disconnecting after challenge cannot reveal the SAS")
    func confirmationCodeCostsTheOffer() throws {
        var machine = PairingHostMachine()
        machine.open(Sample.offer())
        let now = ContinuousClock.now
        let hello = try Rehearsal().joiner.hello

        // The party that knows the secret repeatedly connects, receives only `challenge`, and disconnects. The host's nonce differs on each connection.
        var codes: Set<String> = []
        for attempt in UInt8(0)..<16 {
            let hostNonce = [UInt8](repeating: 0xA0 + attempt, count: 32)
            let id = PairingHostMachine.SessionID(attempt)
            _ = machine.accept(
                id, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: hostNonce, at: now)
            let challenge = machine.receive(hello, on: id, wallClock: Sample.wallClock, now: now).sentBytes
            // The response contains only the status and commitment. It never contains the nonce.
            #expect(challenge == [0] + PairingTranscript.commitment(toHostNonce: hostNonce))
            #expect(challenge.firstRange(of: hostNonce) == nil)
            #expect(HostStep.steps(machine.connectionEnded(id)) == [.finish(.disconnected)], "Nothing is sent on disconnect")
            #expect(machine.hasOpenOffer, "The disconnected attempt leaves the offer unused")

            // The SAS depends on that nonce. Even with the same commitment in P, a different nonce leaves no T, and each connection has a different SAS.
            let proofTranscript = PairingProofTranscript(
                joinerNonce: Sample.joinerNonce, hostCommitment: Array(challenge.dropFirst()), offerHost: Sample.host,
                offerPort: Sample.port, deviceName: Array("rd-phone-5e6f7a8b".utf8), endpoints: try Sample.endpoints())
            #expect(proofTranscript.opened(with: Sample.hostNonce) == nil)
            codes.insert(try #require(proofTranscript.opened(with: hostNonce)).confirmationCode(secret: Sample.secret))
        }
        #expect(codes.count > 8, "The SAS cannot be known in advance without the nonce")

        // Seeing the SAS requires sending `proof`, which consumes the offer immediately. Disconnecting because the SAS is undesirable prevents another attempt.
        let accepted = try Self.prove(&machine, id: 100, offer: Sample.offer(), at: now)
        #expect(Array(accepted.sentBytes.prefix(32)) == Sample.hostNonce)
        #expect(!machine.hasOpenOffer)
        _ = machine.connectionEnded(100)
        #expect(HostStep.steps(try Self.prove(&machine, id: 101, offer: Sample.offer(), at: now)).isEmpty)
        #expect(!machine.hasOpenOffer)
    }

    @Test("An invalid HMAC or a nonceJ that differs from the commitment leaves the offer open and keeps the host nonce undisclosed (P3)")
    func keepsHostNonceAfterFailedProof() throws {
        var wrongCode = try Self.proof(opening: Sample.joinerNonce)
        wrongCode[63] ^= 1
        var otherNonce = Sample.joinerNonce
        otherNonce[0] ^= 1
        for proof in [wrongCode, try Self.proof(opening: otherNonce)] {
            var rehearsal = try Rehearsal()
            _ = rehearsal.toHost(rehearsal.joiner.hello)
            let actions = rehearsal.toHost(proof)
            #expect(actions.sentBytes.isEmpty, "Neither accepted nor the nonce it contains is sent")
            #expect(HostStep.steps(actions).count == 1)
            #expect(rehearsal.machine.hasOpenOffer && rehearsal.machine.sessionCount == 0)
        }
    }

    @Test("An offer can be used once. Other connections with the same secret are rejected afterward (P4)")
    func consumesOfferOnce() throws {
        var rehearsal = try Rehearsal()
        // The second connection also received a challenge while the offer was open.
        _ = rehearsal.machine.accept(
            2, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce,
            at: rehearsal.start)
        var second = PairingJoinerSession(
            offer: Sample.offer(), deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: rehearsal.start + .seconds(60))
        let challenge = rehearsal.machine.receive(second.hello, on: 2, wallClock: Sample.wallClock, now: rehearsal.start)
        let secondProof = second.receive(challenge.sentBytes, at: rehearsal.start)

        _ = try rehearsal.reachDecision()
        let late = rehearsal.machine.receive(
            secondProof.sentBytes, on: 2, wallClock: Sample.wallClock, now: rehearsal.start)
        #expect(HostStep.steps(late) == [.finish(.noOffer)], "Even with a valid proof, the offer has already been used")

        _ = rehearsal.machine.accept(
            3, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce,
            at: rehearsal.start)
        let third = rehearsal.machine.receive(second.hello, on: 3, wallClock: Sample.wallClock, now: rehearsal.start)
        #expect(HostStep.steps(third) == [.send([1] + Sample.hostCommitment), .finish(.noOffer)])
    }

    @Test("If the offer changes, closes, or expires between hello and proof, the connection closes silently", arguments: ["changed", "closed", "expired"])
    func rejectsProofForStaleOffer(change: String) throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes)
        var wallClock = Sample.wallClock
        switch change {
        case "changed": rehearsal.machine.open(Sample.offer(secret: [UInt8](repeating: 0x77, count: 32)))
        case "closed": rehearsal.machine.closeOffer()
        default: wallClock = Sample.expires
        }
        #expect(HostStep.steps(rehearsal.toHost(proof.sentBytes, wallClock: wallClock)) == [.finish(.noOffer)])
        #expect(rehearsal.machine.hasOpenOffer == (change != "closed"), "Newly opened and expired offers stay as they are")
    }

    @Test("Opening a new offer immediately makes the previous one unusable (P9)")
    func replacesOffer() throws {
        var machine = PairingHostMachine()
        let old = Sample.offer()
        let new = Sample.offer(secret: [UInt8](repeating: 0x77, count: 32))
        machine.open(old)
        machine.open(new)
        #expect(HostStep.steps(try Self.prove(&machine, id: 1, offer: old, at: .now)) == [.finish(.wrongProof)])
        #expect(try Self.prove(&machine, id: 2, offer: new, at: .now).count == 2)
    }

    // MARK: Message length and order (P8)

    @Test("Extra bytes after hello are a violation")
    func rejectsOverlongHello() throws {
        var rehearsal = try Rehearsal()
        #expect(HostStep.steps(rehearsal.toHost(rehearsal.joiner.hello + [0])) == [.finish(.malformed)])
        #expect(rehearsal.machine.sessionCount == 0)
    }

    @Test("After challenge is sent, more bytes than a proof is a violation")
    func rejectsOverlongProof() throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes).sentBytes
        #expect(HostStep.steps(rehearsal.toHost(proof + [0])) == [.finish(.malformed)])
        #expect(rehearsal.machine.hasOpenOffer)
    }

    @Test("Device names with joining format characters (U+200C, U+200D) are accepted", arguments: ["\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} iPad", "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}"])
    func acceptsJoinedDeviceName(name: String) {
        #expect(DeviceName(name)?.text == name)
    }

    @Test(
        "A nonconforming hello closes the connection without a challenge",
        arguments: [
            [0x00],                                                                   // The first byte already differs from the marker
            Array("SWPX".utf8),
            HostMachineTests.rawHello(name: Array("a".utf8), prefix: Array("SWPR".utf8) + [1]),   // Version 1 (carried the nonce directly)
            HostMachineTests.rawHello(name: Array("a".utf8), prefix: Array("SWPR".utf8) + [2]),   // Version 2 (the host revealed its nonce immediately)
            HostMachineTests.rawHello(name: Array("a".utf8), prefix: Array("SWPR".utf8) + [4]),   // Unknown version
            HostMachineTests.rawHello(name: []),                                                   // Name length 0
            HostMachineTests.rawHello(name: [UInt8](repeating: 0x61, count: 65)),                  // Name length 65
            HostMachineTests.rawHello(name: [0xFF, 0xFE]),                                         // Invalid UTF-8
            HostMachineTests.rawHello(name: [0xC3]),                                               // Truncated UTF-8
            HostMachineTests.rawHello(name: Array("a\u{07}b".utf8)),                               // Control character (Cc)
            HostMachineTests.rawHello(name: Array("a\nb".utf8)),
            HostMachineTests.rawHello(name: Array("a\u{7F}".utf8)),
            HostMachineTests.rawHello(name: Array("a\u{202E}b".utf8)),                             // Direction change (Cf)
            HostMachineTests.rawHello(name: Array("a\u{200B}b".utf8)),                             // Zero-width space (Cf)
            HostMachineTests.rawHello(name: Array("a\u{FEFF}".utf8)),
        ])
    func rejectsMalformedHello(bytes: [UInt8]) throws {
        var rehearsal = try Rehearsal()
        #expect(HostStep.steps(rehearsal.toHost(bytes)) == [.finish(.malformed)])
        #expect(rehearsal.machine.hasOpenOffer)
    }

    @Test("Name boundaries: 1 byte, 64 bytes, and multiple characters")
    func acceptsDeviceNames() throws {
        for name in ["a", String(repeating: "a", count: 64), "거실 iPad", "Zoë’s 📱"] {
            var rehearsal = try Rehearsal()
            let actions = rehearsal.toHost(Self.rawHello(name: Array(name.utf8)))
            #expect(HostStep.steps(actions) == [.send([0] + Sample.hostCommitment)], "\(name)")
        }
    }

    @Test("Disconnecting mid-message closes the connection")
    func closesOnTruncatedMessage() throws {
        var rehearsal = try Rehearsal()
        #expect(rehearsal.toHost(Array(rehearsal.joiner.hello.prefix(20))).isEmpty)
        #expect(HostStep.steps(rehearsal.machine.connectionEnded(Self.id)) == [.finish(.disconnected)])
        #expect(rehearsal.machine.connectionEnded(Self.id).isEmpty, "Events for a finished connection are discarded")
    }

    // MARK: Deadlines (P5, P8)

    @Test("The connection closes silently if proof does not arrive within 10 seconds of acceptance")
    func timesOutBeforeProof() throws {
        var silent = try Rehearsal()
        #expect(silent.machine.deadline(of: Self.id) == silent.start + .seconds(10))
        #expect(silent.machine.advance(Self.id, to: silent.start + .milliseconds(9_999)).isEmpty)
        #expect(HostStep.steps(silent.machine.advance(Self.id, to: silent.start + .seconds(10))) == [.finish(.proofTimedOut)])

        // Even if hello arrives late, the deadline is measured from acceptance.
        var slow = try Rehearsal()
        _ = slow.machine.receive(slow.joiner.hello, on: Self.id, wallClock: Sample.wallClock, now: slow.start + .seconds(9))
        #expect(slow.machine.deadline(of: Self.id) == slow.start + .seconds(10))
        #expect(HostStep.steps(slow.machine.advance(Self.id, to: slow.start + .seconds(10))) == [.finish(.proofTimedOut)])
        #expect(slow.machine.hasOpenOffer)
    }

    @Test("If no decision arrives within 120 seconds, send status 3 and close (P5)")
    func timesOutWaitingForDecision() throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes)
        let provedAt = rehearsal.start + .seconds(7)
        let accepted = rehearsal.machine.receive(proof.sentBytes, on: Self.id, wallClock: Sample.wallClock, now: provedAt)
        _ = rehearsal.toJoiner(accepted.sentBytes)

        #expect(rehearsal.machine.deadline(of: Self.id) == provedAt + .seconds(120))
        #expect(rehearsal.machine.advance(Self.id, to: rehearsal.start + .seconds(10)).isEmpty, "The proof deadline no longer applies")
        #expect(rehearsal.machine.advance(Self.id, to: provedAt + .milliseconds(119_999)).isEmpty)
        let actions = rehearsal.machine.advance(Self.id, to: provedAt + .seconds(120))
        #expect(HostStep.steps(actions).last == .finish(.decisionTimedOut))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.timedOut))
        // Discard a late decision.
        let late = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(late.isEmpty)
    }

    // MARK: Decisions (P5–P7)

    @Test("If the app rejects the request, send status 2 and close")
    func denies() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        let actions = rehearsal.machine.decided(
            Self.id, approved: false, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(HostStep.steps(actions).last == .finish(.denied))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
    }

    @Test("A disconnect or incoming bytes while waiting for a decision close the connection. The edge cancels the decision Task (P6)", arguments: [true, false])
    func closesWhenPeerLeavesDuringDecision(byEnding: Bool) throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        let actions = byEnding ? rehearsal.machine.connectionEnded(Self.id) : rehearsal.toHost([0])
        #expect(HostStep.steps(actions) == [.finish(.disconnected)], "The connection ends without sending anything")
        let late = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(late.isEmpty, "Approval for a finished connection creates no paired peer")
    }

    @Test("Closing or opening an offer while a decision is pending leaves that decision in progress (P6)", arguments: [true, false])
    func decisionSurvivesOfferChange(closing: Bool) throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        if closing {
            rehearsal.machine.closeOffer()
        } else {
            rehearsal.machine.open(Sample.offer(secret: [UInt8](repeating: 0x77, count: 32)))
        }
        let saved = rehearsal.approve()
        #expect(HostStep.steps(saved).last == .finish(.paired))
        #expect(rehearsal.toJoiner(saved.sentBytes).result != nil)
        #expect(rehearsal.machine.hasOpenOffer == !closing)
    }

    @Test("If the peer's StableID changed or its identity is missing at approval, return status 2 without storing it (P7)", arguments: [true, false])
    func deniesWhenIdentityChanged(missing: Bool) throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        var other = Sample.joinerIdentity
        other.stableID = "nEXAMPLEOTHER"
        let actions = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: missing ? nil : other, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(HostStep.steps(actions).count == 2)
        #expect(HostStep.steps(actions).last == .finish(.identityChanged))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
    }

    @Test("Without a local identity to disclose, return status 2 without storing the peer")
    func deniesWithoutHostIdentity() throws {
        for host in [nil, PeerIdentity(stableID: "", name: "", computedName: "", loginName: ""),
                     PeerIdentity(stableID: "n\u{7F}", name: "", computedName: "", loginName: "")] {
            var rehearsal = try Rehearsal()
            _ = try rehearsal.reachDecision()
            let actions = rehearsal.machine.decided(
                Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: host, at: Sample.wallClock)
            #expect(HostStep.steps(actions).last == .finish(.hostIdentityUnknown))
            #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
        }
    }

    @Test("If storage fails, return status 2 (P7)")
    func deniesWhenStoreFails() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        let actions = rehearsal.approve(saving: false)
        #expect(HostStep.steps(actions).last == .finish(.storeFailed))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
        #expect(rehearsal.machine.sessionCount == 0)
    }
}
