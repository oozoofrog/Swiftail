import Foundation
import Swiftail
import SwiftailCrypto

/// The host's pairing protocol, with one open offer and the connections in progress (contract behaviors P1–P9).
///
/// Performs no I/O. Accepts received bytes, times, app decisions, and save results, and emits actions (`Action`). The edge
/// (`PairingHost`) handles sockets, clocks, randomness, and files. A single connection follows this flow.
///
/// ```
/// accept ─ hello ─▶ challenge(continue) ─ proof ─▶ accepted + request decision ─ decision ─▶ save ─▶ decision ─▶ end
///            │                               │                                          └ disconnect or 120 seconds
///            └ no offer: challenge(1)        └ nonce does not match commitment, invalid proof, or changed offer: close silently
/// ```
///
/// One offer can be open at a time and each offer is single-use. Remove it immediately upon a valid `proof` (P4). An invalid proof leaves it
/// in place (P3). A 256-bit secret cannot be guessed through attempts, and consuming an offer on a failed attempt would let any tailnet peer invalidate it.
///
/// The connection's nonce goes out only as a commitment in `challenge` and is revealed in `accepted` only after a valid `proof` consumes the offer. The SAS
/// cannot be calculated without that nonce, so even someone who knows the offer secret must use the offer to see the SAS and cannot redial
/// to choose a number.
struct PairingHostMachine: Sendable {
    typealias SessionID = UInt64
    typealias Instant = ContinuousClock.Instant

    /// The limit on connections in progress (P8).
    static let sessionLimit = 8
    /// The per-node (`StableID`) limit within that total (P8). It prevents a single peer from opening repeated connections and holding every slot.
    static let sessionLimitPerPeer = 2
    /// The deadline for `proof`, measured from acceptance so idle connections cannot hold slots (P8).
    static let proofTimeout = Duration.seconds(10)
    /// The deadline for the app's decision (P5).
    static let decisionTimeout = Duration.seconds(120)

    /// An action for the edge.
    enum Action: Sendable {
        /// Sends these bytes.
        case send([UInt8])
        /// Requests app approval. Pass the app's answer to `decided`.
        case requestDecision(PairingRequest)
        /// Adds the paired peer to the list and saves it. Pass the save result to `saved`.
        case save(PairedPeer)
        /// Closes after sending all pending bytes and cancels the connection's decision Task. This is its final action.
        case finish(Ending)
    }

    /// The reason the connection ended. This summary is logged (P10).
    enum Ending: String, Sendable {
        case limitReached = "Reached the limit for connections in progress"
        case peerLimitReached = "Reached the limit for connections in progress from this node"
        case unknownPeer = "Peer identity unknown"
        case noOffer = "No open offer"
        case malformed = "Bytes outside the protocol"
        case wrongProof = "Invalid proof"
        case proofTimedOut = "Proof did not arrive before the deadline"
        case disconnected = "Peer disconnected"
        case denied = "App denied approval"
        case decisionTimedOut = "Approval timed out"
        case identityChanged = "Peer identity changed at approval"
        case hostIdentityUnknown = "Host identity unknown"
        case storeFailed = "Could not save to the paired peer list"
        case paired = "Paired"
    }

    /// The open offer. The number tells the state machine whether the offer seen at `hello` matches the one at `proof`.
    private struct OpenOffer: Sendable {
        let serial: UInt64
        let offer: PairingOffer
    }

    /// What the connection holds after a valid `proof`. The pending approval continues even if the offer is closed or changed (P6).
    private struct Approval: Sendable {
        let transcript: PairingTranscript
        let secret: [UInt8]
        let deviceName: String

        /// The `decision` message body and its HMAC.
        func message(_ decision: PairingMessage.Decision) -> [UInt8] {
            decision.body + transcript.decisionCode(for: decision.body, secret: secret)
        }
    }

    private enum Phase: Sendable {
        /// Accumulating `hello`.
        case hello(buffer: [UInt8])
        /// Sent `challenge` and is accumulating `proof`.
        case proof(buffer: [UInt8], hello: PairingMessage.Hello, offerSerial: UInt64)
        /// Sent `accepted` and is waiting for the app's decision.
        case decision(Approval, deadline: Instant)
        /// The app approved pairing and the connection is waiting for the save result.
        case saving(Approval, approved: PairingMessage.Decision)
    }

    private struct Session: Sendable {
        /// The peer identity at connection acceptance (P1).
        let peer: PeerIdentity
        let endpoints: PairingEndpoints
        /// The host nonce for this connection. Only its commitment goes in `challenge`. It is revealed in `accepted` after a valid `proof`.
        let nonce: [UInt8]

        /// The commitH commitment carried in `challenge`.
        var commitment: [UInt8] { PairingTranscript.commitment(toHostNonce: nonce) }
        let acceptedAt: Instant
        var phase: Phase
    }

    private var offer: OpenOffer?
    private var nextOfferSerial: UInt64 = 0
    private var sessions: [SessionID: Session] = [:]

    /// Whether an offer is open, ignoring expiration.
    var hasOpenOffer: Bool { offer != nil }
    /// The open offer's expiration time, or nil if no offer is open.
    var openOfferExpiry: Date? { offer?.offer.expires }
    /// The number of connections in progress.
    var sessionCount: Int { sessions.count }

    // MARK: Offer (P9)

    /// Opens an offer and invalidates the previous one immediately.
    mutating func open(_ offer: PairingOffer) {
        nextOfferSerial += 1
        self.offer = OpenOffer(serial: nextOfferSerial, offer: offer)
    }

    /// Closes the offer. Connections with valid `proof` awaiting a decision continue (P6).
    mutating func closeOffer() {
        offer = nil
    }

    /// Removes an expired offer. It is already unusable (`usableOffer`), so removal does not affect the protocol. The edge calls this
    /// to report expiration.
    ///
    /// - Returns: true if an offer was removed.
    mutating func expireOffer(at wallClock: Date) -> Bool {
        guard let offer, wallClock >= offer.offer.expires else { return false }
        self.offer = nil
        return true
    }

    // MARK: Connections

    /// Registers one accepted connection (P1, P8). Closes it immediately if the limit (8 overall, 2 from the same node) would be exceeded.
    ///
    /// - Parameters:
    ///   - peer: The remote address's `whoIs` result. An unknown identity causes closure without reading.
    ///   - nonce: 32 random bytes for this connection. They are withheld until a valid `proof` arrives.
    ///   - now: The connection acceptance time, from which the `proof` deadline is measured.
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

    /// Processes bytes received on the connection. Messages must match their exact lengths, and bytes received out of turn are a violation (P8).
    ///
    /// - Parameters:
    ///   - wallClock: The time used to check offer expiration.
    ///   - now: The time from which the decision deadline is measured.
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
                // P2: If no offer is open or it has expired, read the entire hello before reporting this and closing.
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
            // P3: The revealed nonceJ must match the `hello` commitment. A nonce chosen after seeing `challenge` fails here.
            // The commitment is public, so comparison need not be constant-time.
            guard let proof = PairingMessage.Proof(buffer),
                  PairingTranscript.commitment(toJoinerNonce: proof.nonce) == hello.commitment
            else { return finish(id, .malformed) }
            // If the offer was closed, replaced, used by another connection, or expired in the meantime, close without sending anything.
            guard let offer = usableOffer(at: wallClock), offer.serial == offerSerial else {
                return finish(id, .noOffer)
            }
            let secret = offer.offer.secret
            let proofTranscript = PairingProofTranscript(
                joinerNonce: proof.nonce, hostCommitment: session.commitment, offerHost: offer.offer.host,
                offerPort: offer.offer.port, deviceName: hello.deviceName.bytes, endpoints: session.endpoints)
            // P3: Compare in constant time. If the proof is wrong, leave the offer untouched and withhold nonceH.
            guard constantTimeEqual(proof.code, proofTranscript.proof(secret: secret)),
                  let transcript = proofTranscript.opened(with: session.nonce)
            else { return finish(id, .wrongProof) }
            // P4: Use the offer only once. Reveal nonceH afterward.
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
            // P6: Treat bytes received while awaiting a decision as a disconnect.
            return finish(id, .disconnected)
        }
    }

    /// Handles EOF or a read error. If waiting for a decision, the edge cancels the decision Task (P6).
    mutating func connectionEnded(_ id: SessionID) -> [Action] {
        finish(id, .disconnected)
    }

    /// The next deadline for this connection, or nil if none.
    func deadline(of id: SessionID) -> Instant? {
        guard let session = sessions[id] else { return nil }
        switch session.phase {
        case .hello, .proof: return session.acceptedAt + Self.proofTimeout
        case .decision(_, let deadline): return deadline
        case .saving: return nil
        }
    }

    /// Handles elapsed time. If the deadline passed, closes silently before `proof` or sends status 3 and closes while waiting for a decision.
    mutating func advance(_ id: SessionID, to now: Instant) -> [Action] {
        guard let session = sessions[id], let deadline = deadline(of: id), now >= deadline else { return [] }
        if case .decision(let approval, _) = session.phase {
            return [.send(approval.message(.timedOut))] + finish(id, .decisionTimedOut)
        }
        return finish(id, .proofTimedOut)
    }

    /// Processes the app's decision (P5 and P7).
    ///
    /// Even with approval, pairing requires the peer's current identity (`currentPeer`) to have the original `StableID` and this node to have an identity
    /// (`host`) to share. Otherwise, pairing is denied (status 2).
    ///
    /// - Parameters:
    ///   - currentPeer: The current `whoIs(remote address)` result.
    ///   - host: This node's identity (`whoIs(own address)`). `decision` carries the `StableID` and display name.
    ///   - wallClock: The time to record as the pairing time.
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

    /// Handles the save result (P7). Sends status 1 on success or status 2 on failure (write failure or full list), then closes.
    mutating func saved(_ id: SessionID, succeeded: Bool) -> [Action] {
        guard let session = sessions[id], case .saving(let approval, let approved) = session.phase else { return [] }
        return succeeded
            ? [.send(approval.message(approved))] + finish(id, .paired)
            : [.send(approval.message(.denied))] + finish(id, .storeFailed)
    }

    // MARK: Helpers

    private func usableOffer(at wallClock: Date) -> OpenOffer? {
        offer.flatMap { wallClock < $0.offer.expires ? $0 : nil }
    }

    private mutating func finish(_ id: SessionID, _ ending: Ending) -> [Action] {
        guard sessions.removeValue(forKey: id) != nil else { return [] }
        return [.finish(ending)]
    }
}
