import Foundation
import Swiftail
import SwiftailBase
import os

/// The pairing host. Opens offers, accepts joiners on a tailnet port, runs the protocol, and holds the paired peer list.
///
/// This actor is the edge. `PairingHostMachine` makes protocol decisions without I/O, and this actor connects it to the node's listener and connections,
/// clock, randomness, app decision (`decide`), and paired peer list file. Concurrency is structured. Canceling the Task that calls `run()` stops everything.
///
/// ```
/// run()
///  └ TaskGroup: serve(connection) for each accepted connection, plus expireOffers()
///     ├ expireOffers()  Wakes at the open offer's expiration, removes it, and emits `OfferState.expired`
///     └ TaskGroup: One connection's lifetime. Cancels the remaining work when the protocol ends
///        ├ Read            Received bytes or disconnect → state machine
///        ├ Deadline        10 seconds for proof, 120 seconds for approval
///        └ decide(request) The app's decision. Canceled if the peer disconnects
/// ```
///
/// ```swift
/// let host = try await PairingHost(node: node, port: 4747, storeDirectory: directory) { request in
///     await approvalScreen.ask(request)   // Show the SAS and wait for the user's answer
/// }
/// let running = Task { try await host.run() }
/// let offer = try await host.openOffer()
/// show(offer.qrCode(base: pairingBaseURL))   // App address: myapp://pair, https://example.com/pair
/// for await event in host.events { … }       // Changes to the paired peer list and the offer
/// ```
///
/// The app checks connections after pairing. It obtains the connection's identity using `TailnetNode.whoIs(_:)` and queries `pairedPeer(withStableID:)`.
///
/// The host must be an in-process node (`.inProcess`), because `listen` is available only on that device.
/// See contract `docs/contracts/SwiftailPairing.md` §§5 and 6.
public actor PairingHost {
    /// Logs summaries only: acceptance, reason for closure, and decision. Omits secrets, proofs, auth keys, SAS values, names, and addresses (contract behavior P10).
    private static let log = Logger(subsystem: "Swiftail", category: "pairing")
    /// The unread event limit. Discards the oldest events first when full (same as `TailnetNode.events`).
    static let eventBufferLimit = 64

    /// An event entering a single connection's stream.
    private enum SessionEvent: Sendable {
        case received([UInt8])
        /// Reading ended with EOF or an error.
        case ended
        /// The deadline may have arrived. The state machine decides.
        case timer
        case decided(Bool)
    }

    private let node: TailnetNode
    private let port: UInt16
    private let decide: @Sendable (PairingRequest) async -> Bool
    private let file: PairedPeerFile
    /// The key for the claim on the paired peer list directory. Released when discarded.
    private let claim: String
    private var peers: PairedPeerList
    private var machine = PairingHostMachine()
    private var nextSessionID: PairingHostMachine.SessionID = 0
    private let eventStream: AsyncStream<Event>
    private let eventContinuation: AsyncStream<Event>.Continuation
    /// Wakes the expiration timer (`expireOffers()`). Opening a new offer changes the expiration time. Exists only during `run()`.
    private var offerChanges: AsyncStream<Void>.Continuation?

    /// Reads the paired peer list and creates the host. `run()` starts listening.
    ///
    /// - Parameters:
    ///   - node: The node that accepts pairing connections. Its device must be `.inProcess`.
    ///   - port: The tailnet port that accepts pairing connections. It is included in the offer link.
    ///   - storeDirectory: The directory for `paired-peers.json`. Creates it if absent (0700). An existing directory must belong to the current user
    ///     and be unwritable by the group or others.
    ///   - decide: Requests approval. The Task for this call is canceled if the peer disconnects or 120 seconds elapse, so return promptly on cancellation
    ///     (the returned value is discarded). If awaiting a user's answer through a continuation, handle cancellation with `withTaskCancellationHandler`.
    ///     If this call never returns, the connection closes but `run()` cannot finish.
    /// - Throws: `invalidConfiguration` if the node's device is not `.inProcess` or the port is zero, storeWriteFailed if directory creation fails,
    ///   storeUnreadable if the list file cannot be read or the directory belongs to another user or is writable by the group or others,
    ///   or `storeInUse` if a host in this process already uses the same directory.
    public init(
        node: TailnetNode, port: UInt16, storeDirectory: URL,
        decide: @escaping @Sendable (PairingRequest) async -> Bool
    ) async throws(PairingError) {
        guard node.hasInProcessDevice else {
            throw .invalidConfiguration("The host must be a node with an .inProcess device")
        }
        guard port != 0 else { throw .invalidConfiguration("The port must be nonzero") }
        guard storeDirectory.isFileURL else { throw .invalidConfiguration("The paired peer list directory must be a file URL") }
        // Create the directory before claiming it. Symlinks in a nonexistent path do not resolve, giving it a different key from the same directory after creation.
        guard (try? FileManager.default.createDirectory(
            at: storeDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])) != nil
        else { throw .storeWriteFailed }
        guard let claim = StoreDirectoryClaims.shared.claim(storeDirectory) else { throw .storeInUse }
        let file = PairedPeerFile(directory: storeDirectory)
        do throws(PairingError) {
            // A list in a directory writable by others is untrusted (S2). Check the directory before reading the file.
            guard file.hasPrivateDirectory else { throw .storeUnreadable }
            peers = try file.load()
        } catch {
            StoreDirectoryClaims.shared.release(claim)
            throw error
        }
        self.node = node
        self.port = port
        self.decide = decide
        self.file = file
        self.claim = claim
        (eventStream, eventContinuation) = AsyncStream.makeStream(
            of: Event.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
    }

    deinit {
        StoreDirectoryClaims.shared.release(claim)
        eventContinuation.finish()
    }

    // MARK: Events

    /// Changes to the paired peer list and the offer. There is one subscriber. Because the list can change outside `run()`, the stream outlives run()
    /// and ends when this `PairingHost` is gone.
    ///
    /// Retains at most the 64 newest unread events and discards the oldest first. The stream grows no further even if the app never reads it.
    ///
    /// Canceling the consuming Task ends the stream and prevents resubscription. There is only one stream even across `run()` calls, so subscribe once
    /// where the host is created instead of subscribing on every run().
    public nonisolated var events: AsyncStream<Event> { eventStream }

    // MARK: Offer (behavior P9)

    /// Opens a new offer and immediately invalidates the previous offer. Each offer can be used once.
    ///
    /// Can be called before `run()`. Connections can arrive only once run() starts listening. The returned link and QR code are secrets.
    ///
    /// **The auth key is independent of pairing.** Anyone who obtains the link can join the tailnet with the key while it is valid, regardless of the host's
    /// approval (decide). Approval controls only pairing. Give the key the same short lifetime as the offer
    /// (`AuthKeyIssuer.issue(lifetime:)`) and restrict the key's tag in tailnet policy (ACL) to the pairing and app
    /// ports only.
    ///
    /// - Parameters:
    ///   - lifetime: The offer lifetime. Truncated to whole seconds and must be 1–3600 seconds. On a tailnet with lock enabled, give the joiner node
    ///     enough time to be signed.
    ///   - authKey: The single-use auth key the joiner uses to enter the tailnet. Included in the link.
    /// - Throws: `invalidConfiguration` if the lifetime is out of range, invalidAuthKey if the key cannot be included in a link (including wrapped keys),
    ///   or `notRunning` if the node does not yet have its own FQDN.
    public func openOffer(
        lifetime: Duration = .seconds(300), authKey: String? = nil
    ) async throws(PairingError) -> PairingOffer {
        let seconds = lifetime.components.seconds
        guard (1...3600).contains(seconds) else { throw .invalidConfiguration("The offer lifetime must be 1–3600 seconds") }
        if let authKey {
            do throws(PairingOfferError) {
                _ = try OfferField.authKey(authKey.utf8)
            } catch {
                throw .invalidAuthKey
            }
        }
        // Use the reader's rules so the generated link can always be read.
        guard let fqdn = await node.status.fqdn, let host = OfferField.host(fqdn.lowercased().utf8) else {
            throw .notRunning
        }
        let expires = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down) + Double(seconds))
        let offer = PairingOffer(
            host: host, port: port, expires: expires, authKey: authKey,
            secret: PairingRandom.bytes(PairingOffer.secretLength))
        machine.open(offer)
        Self.log.info("Opened an offer with a lifetime of \(seconds, privacy: .public) seconds")
        eventContinuation.yield(.offerChanged(.opened))
        offerChanges?.yield()
        return offer
    }

    /// Closes the open offer. Connections that already proved themselves and await approval continue (behavior P6).
    public func closeOffer() {
        let wasOpen = machine.hasOpenOffer
        machine.closeOffer()
        Self.log.info("Closed the offer")
        if wasOpen { eventContinuation.yield(.offerChanged(.closed)) }
    }

    /// Wakes at the open offer's expiration, removes it, and emits the event. Opening a new offer (`offerChanges`) reschedules the wait for its expiration.
    ///
    /// Creates a fresh stream for change signals each time, because canceling the losing task in the race ends that stream (same pattern as
    /// TailnetNode's timer). There is no `await` between setting up the channel and reading the expiration time, so changes between them cannot be missed.
    private func expireOffers() async {
        while !Task.isCancelled {
            let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            offerChanges = continuation
            let expiry = machine.openOfferExpiry
            await withTaskGroup(of: Void.self) { group in
                if let expiry {
                    let deadline = ContinuousClock.now + .seconds(max(0, expiry.timeIntervalSinceNow))
                    // Reduce delays in expiration events for long offers caused by the system's default timer tolerance.
                    group.addTask { try? await Task.sleep(until: deadline, tolerance: .milliseconds(25)) }
                }
                group.addTask {
                    for await _ in changes { return }
                }
                await group.next()
                group.cancelAll()
            }
            // If the timer woke early (clock difference), wait again without removing the offer.
            if machine.expireOffer(at: Date()) {
                Self.log.info("The offer expired")
                eventContinuation.yield(.offerChanged(.expired))
            }
        }
        offerChanges = nil
    }

    // MARK: Paired Peer List (behaviors S1–S4)

    /// The paired peer list, in pairing order.
    public var pairedPeers: [PairedPeer] { peers.peers }

    /// The paired peer for this `StableID`, or nil if absent. Pass `whoIs(peer address)?.stableID` to check whether a connection's peer is paired.
    public func pairedPeer(withStableID stableID: String) -> PairedPeer? {
        peers.peer(withStableID: stableID)
    }

    /// Removes the paired peer and saves the list. An absent peer has no effect.
    ///
    /// - Throws: `storeWriteFailed` if saving fails. The list stays as it was.
    public func removePairedPeer(withStableID stableID: String) throws(PairingError) {
        var updated = peers
        guard updated.remove(stableID: stableID) else { return }
        try file.save(updated)
        peers = updated
        eventContinuation.yield(.pairedPeerRemoved(stableID: stableID))
    }

    /// Adds the paired peer and saves the list. Returns false without adding if the list is full or saving fails.
    private func save(_ peer: PairedPeer) -> Bool {
        var updated = peers
        guard updated.insert(peer) else { return false }
        do throws(PairingError) {
            try file.save(updated)
        } catch {
            return false
        }
        peers = updated
        eventContinuation.yield(.pairedPeerAdded(peer))
        return true
    }

    // MARK: Protocol

    /// Listens on the port and runs the protocol for each incoming connection. Waits until the calling Task is canceled. On cancellation, closes connections
    /// still in progress and returns.
    ///
    /// - Throws: `invalidConfiguration` if the port is in use or the listener reached its limit, or notRunning if the node's `run()` has ended
    ///   (including while listening).
    public func run() async throws(PairingError) {
        let listener: TailnetListener
        do throws(ConnectionError) {
            listener = try await node.listen(port: port)
        } catch {
            switch error {
            case .notRunning: throw .notRunning
            case .addressInUse: throw .invalidConfiguration("Already listening on that port")
            default: throw .invalidConfiguration("Could not open the port")
            }
        }
        Self.log.info("Started listening for pairing connections")
        await withDiscardingTaskGroup { group in
            group.addTask { await self.expireOffers() }
            for await connection in listener {
                group.addTask { await self.serve(connection) }
            }
            group.cancelAll()
        }
        await listener.close()
        Self.log.info("Stopped listening for pairing connections")
        if !Task.isCancelled { throw .notRunning }
    }

    /// Runs the protocol to completion for one connection and closes it.
    private func serve(_ connection: TailnetConnection) async {
        let acceptedAt = ContinuousClock.now
        let id = nextSessionID
        nextSessionID += 1
        let endpoints = PairingEndpoints(joiner: connection.remoteEndpoint, host: connection.localEndpoint)
        // P1: The remote address belongs to the peer authenticated by WireGuard. Read only if its identity is known.
        let peer = await node.whoIs(endpoints.joiner.address)
        let (events, continuation) = AsyncStream.makeStream(of: SessionEvent.self)

        await withTaskGroup(of: Void.self) { group in
            let first = machine.accept(
                id, from: peer, endpoints: endpoints, nonce: PairingRandom.bytes(PairingMessage.nonceLength),
                at: acceptedAt)
            Self.log.info("Accepted a pairing connection")
            if let deadline = machine.deadline(of: id) {
                group.addTask {
                    // The joiner sends only hello and proof. If more arrived, the state machine already ended the protocol for a violation, so stop
                    // reading. Bytes accumulating while awaiting processing cannot substantially exceed this limit.
                    var remaining = PairingMessage.maximumJoinerLength
                    while remaining >= 0, let bytes = try? await connection.read(upTo: 256) {
                        remaining -= bytes.count
                        continuation.yield(.received(bytes))
                    }
                    continuation.yield(.ended)
                }
                Self.addTimer(until: deadline, to: &group, continuation)
            }
            if await perform(first, for: id, on: connection, in: &group, continuation) {
                for await event in events {
                    let actions: [PairingHostMachine.Action]
                    switch event {
                    case .received(let bytes):
                        let hadOffer = machine.hasOpenOffer
                        actions = machine.receive(bytes, on: id, wallClock: Date(), now: .now)
                        // Only a correct proof removes the offer (P4).
                        if hadOffer, !machine.hasOpenOffer {
                            eventContinuation.yield(.offerChanged(.used))
                        }
                    case .ended:
                        actions = machine.connectionEnded(id)
                    case .timer:
                        actions = machine.advance(id, to: .now)
                    case .decided(let approved):
                        // P7: Recheck identity at the moment of approval.
                        let currentPeer = await node.whoIs(endpoints.joiner.address)
                        let host = await node.whoIs(endpoints.host.address)
                        actions = machine.decided(
                            id, approved: approved, currentPeer: currentPeer, host: host, at: Date())
                    }
                    guard await perform(actions, for: id, on: connection, in: &group, continuation) else { break }
                }
            }
            // A slot remains if `run()` exited on cancellation. Release it.
            _ = machine.connectionEnded(id)
            group.cancelAll()
            // Close with FIN after queued data goes out. The connection closes first even if the decision Task responds slowly to cancellation.
            await connection.close()
        }
    }

    /// Performs the actions emitted by the state machine. Returns false if the connection ended (`finish`).
    private func perform(
        _ actions: [PairingHostMachine.Action], for id: PairingHostMachine.SessionID, on connection: TailnetConnection,
        in group: inout TaskGroup<Void>, _ continuation: AsyncStream<SessionEvent>.Continuation
    ) async -> Bool {
        var pending = actions[...]
        while let action = pending.popFirst() {
            switch action {
            case .send(let bytes):
                // A failed send means the connection ended, and the read reports it.
                try? await connection.write(bytes)
            case .requestDecision(let request):
                Self.log.info("Proof verified. Waiting for app approval")
                let decide = decide
                group.addTask { continuation.yield(.decided(await decide(request))) }
                if let deadline = machine.deadline(of: id) { Self.addTimer(until: deadline, to: &group, continuation) }
            case .save(let peer):
                pending.append(contentsOf: machine.saved(id, succeeded: save(peer)))
            case .finish(let ending):
                Self.log.info("Closing the pairing connection: \(ending.rawValue, privacy: .public)")
                return false
            }
        }
        return true
    }

    private static func addTimer(
        until deadline: ContinuousClock.Instant, to group: inout TaskGroup<Void>,
        _ continuation: AsyncStream<SessionEvent>.Continuation
    ) {
        group.addTask {
            try? await Task.sleep(until: deadline, clock: .continuous)
            continuation.yield(.timer)
        }
    }
}

/// System randomness. The state machine takes random values as arguments. Only the edge generates them.
enum PairingRandom {
    static func bytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}
