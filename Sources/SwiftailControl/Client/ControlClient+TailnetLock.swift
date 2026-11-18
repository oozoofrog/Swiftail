import Foundation
import os
import SwiftailBase
import SwiftailCrypto
import SwiftailHTTP2
import SwiftailIO
import SwiftailTKA

/// Receives and verifies tailnet lock signing authority state in response to the server's reported state and uses it to filter the netmap.
///
/// **Only filtered netmaps leave this actor.** Every netmap from `MapSession` goes through `receivedLock` and becomes an event
/// only in `emitNetmap`. Fails closed by default. If the server reports an enabled lock and the node has the capability but no
/// verified state, emits no peers (`.unverified`). Failures never let a netmap pass unfiltered.
/// If synchronization fails, continues filtering with the previous state. Acts on a disabled claim only after verifying the disablement secret.
///
/// `TailnetLockPlan`, `Authority`, and `Netmap.filtered` make decisions without I/O. This extension handles only RPCs, files, and sequencing.
/// - The map stream (`receiveMap`) calls `receivedLock` for each response. If no action is needed, filters and emits immediately. Otherwise, holds the netmap
///   and wakes the procedure. Stream reads continue. Keeps only the newest netmap received in the meantime.
/// - The procedure (`runLockProcedures`) is a child task of the connection that runs alongside the map stream. Runs one procedure at a time and filters and emits
///   the held netmap using the state at completion, whether the procedure succeeds or fails. Runs separately from signal handling so state-reporting backoff cannot block it.
/// - Keeps signing authority state in memory across disconnects and writes it to `TailnetLockStore` whenever it changes.
///
/// Contract `docs/contracts/SwiftailTailnetLock.md` behaviors N, Y, P, O, T, and K, decisions L2 and L3, and owner response U1.
/// `docs/protocol-notes/tailnet-lock.md` §3.10, §4.7~§4.10 (origin: tailscale.com `ipn/ipnlocal/tailnet-lock.go`
/// `tkaSyncIfNeeded`·`tkaSyncLocked`·`tkaApplyDisablementLocked`·`tkaFetchBootstrap`·`tkaDoSyncOffer`·`tkaDoSyncSend`,
/// BSD-3-Clause).
extension ControlClient {
    /// Lock processing state for one map session. Cleared when establishing a new connection.
    struct LockSession {
        /// The state the server reported in this map session.
        var server = ServerLockState()
        /// The newest netmap in this session, before filtering. Kept without emitting while a procedure runs.
        var netmap: Netmap?
        /// Whether `netmap` has yet to be filtered and emitted.
        var isNetmapPending = false
        /// The lock status on the last emitted netmap. If the status changes after the procedure, filters and emits the same netmap again.
        var emitted: TailnetLockStatus?
        /// Whether a procedure is running. Netmaps received during it are held until the procedure finishes.
        var isProcedureRunning = false
        /// An action is due because of a new netmap or a change in the state reported by the server.
        var isWorkRequested = false
        /// The channel that wakes the waiting procedure. Nil when it is not waiting.
        var wakeup: AsyncStream<Void>.Continuation?
    }

    /// What the procedure could not read in the server's response. Logs only the kind.
    private enum LockResponseError: Error {
        /// The head or an ancestor could not be read as an AUM hash.
        case unreadableHash
    }

    static let lockLog = Logger(subsystem: "Swiftail", category: "tailnet-lock")
    /// The bootstrap and sync/send response body limit (Go's default Noise response limit).
    static let maximumTKAResponseSize = 1 << 20
    /// The sync/offer response body limit. Go uses 512MiB. This lowers it to the map frame limit (contract behavior M, decision L16).
    static let maximumTKASyncOfferResponseSize = 8 << 20

    var lockStore: TailnetLockStore {
        TailnetLockStore(directory: identityStore.fileURL.deletingLastPathComponent())
    }

    /// The local head to include in the map request's `TKAHead`. An empty string when state is absent.
    var lockHeadText: String { lockAuthority?.head.text ?? "" }

    /// Opens stored signing authority state. `run()` calls this once before the first connection (behaviors N7 and T3).
    ///
    /// An open failure leaves the state unverified. Treating it as absent would let file corruption alone transfer trust to a fresh bootstrap.
    /// Keeps the file untouched and remains in `.unverified` (behavior T4).
    func openLockStore() {
        do {
            lockAuthority = try lockStore.load()
        } catch {
            isLockStoreUnreadable = true
            // Storage error messages include only the kind, without paths, keys, or bytes.
            Self.lockLog.error("tailnet lock: Could not open stored state, so peers will be withheld: \(String(describing: error), privacy: .public)")
        }
    }

    // MARK: Map stream side

    /// The action to take now. There is none after storage fails to open (retrying would yield the same result), or before the first netmap of this session. Earlier responses
    /// (KeepAlive) have no place for the server to report the lock, so only the first netmap establishes that `TKAInfo` was absent from the start.
    var lockPlan: TailnetLockPlan {
        guard !isLockStoreUnreadable, let netmap = lockSession.netmap else { return .nothing }
        return TailnetLockPlan(
            localHead: lockAuthority?.head, hasCapability: netmap.selfNode.hasTailnetLockCapability, server: lockSession.server
        )
    }

    /// Receives the result of applying one map response. If no action is due, filters and emits the netmap immediately. Otherwise, keeps it and wakes the procedure (behavior N3).
    ///
    /// A new netmap or a change in server-reported state triggers the procedure. If an action remains due (a failed procedure), an unchanged map response also triggers it.
    /// Go runs the procedure for every map response (`tkaSyncIfNeeded` in `ipn/ipnlocal/tailnet-lock.go`). If the server changes only the disablement secret and
    /// resends the same map, retry on that map (observed at gate (a) 7). KeepAlive does not trigger it.
    func receivedLock(_ update: MapSession.Update) throws {
        if let netmap = update.netmap {
            lockSession.netmap = netmap
            lockSession.isNetmapPending = true
        }
        let serverChanged = update.serverLock != lockSession.server
        lockSession.server = update.serverLock
        guard update.netmap != nil || serverChanged || (update.isMapResponse && lockPlan != .nothing) else { return }
        if lockPlan != .nothing {
            lockSession.isWorkRequested = true
            lockSession.wakeup?.yield()
        } else if !lockSession.isProcedureRunning {
            try emitNetmap()
        }
    }

    /// Filters the held netmap with current lock state and emits it as an event. If the netmap is not new, emits only when the lock state has changed.
    private func emitNetmap() throws {
        guard let raw = lockSession.netmap else { return }
        var netmap: Netmap
        if let lockAuthority {
            netmap = raw.filtered(by: lockAuthority, lockKey: identity.lockPublicKey)
            // If the server later reports this node's head, the chains connect without waiting for synchronization.
            if isLockStateDiverged, lockAuthority.head != lockSession.server.head {
                netmap.tailnetLock.issue = .storedStateDiverged
            }
        } else if isLockStoreUnreadable {
            netmap = raw.withholdingPeers()
            netmap.tailnetLock.issue = .unreadableStoredState
        } else if lockPlan == .bootstrap {
            // The server reports an enabled lock, and verified state is still unavailable (bootstrap has yet to run or failed).
            netmap = raw.withholdingPeers()
            netmap.tailnetLock.issue = .acquiringState
        } else {
            netmap = raw
        }
        let lock = netmap.tailnetLock
        guard lockSession.isNetmapPending || lock != lockSession.emitted else { return }
        if lock != lockSession.emitted {
            Self.lockLog.info("""
                tailnet lock: \(String(describing: lock.mode), privacy: .public), \
                \(lock.filteredPeerCount, privacy: .public) peers filtered, local node locked out: \(lock.isLockedOut, privacy: .public)
                """)
        }
        lockSession.isNetmapPending = false
        lockSession.emitted = lock
        try accept(netmap)
    }

    // MARK: Procedures

    /// Runs one tailnet lock procedure at a time. Exits by throwing on cancellation or key expiration in an emitted netmap.
    ///
    /// After a failed bootstrap (`.unverified`), backs off and retries without waiting for the next netmap because there are no peers
    /// in the meantime (behavior N6). Sync or disablement failure keeps filtering with previous state, so wait for the next trigger.
    func runLockProcedures(over connection: ControlConnection) async throws {
        var bootstrapFailures = 0
        while true {
            let retry = bootstrapFailures > 0 && lockPlan == .bootstrap
                ? Self.lockRetryDelay(failures: bootstrapFailures, within: timeouts.lockRetry) : nil
            try await waitForLockWork(retryAfter: retry)
            lockSession.isWorkRequested = false
            let plan = lockPlan
            if plan != .nothing {
                lockSession.isProcedureRunning = true
                await performLock(plan, over: connection)
                lockSession.isProcedureRunning = false
                try Task.checkCancellation()
                bootstrapFailures = lockPlan == .bootstrap ? bootstrapFailures + 1 : 0
                announceLockHead()
            }
            try emitNetmap()
        }
    }

    /// The retry interval after `failures` consecutive failures in `.unverified`. Starts at the lower bound and doubles up to the upper bound.
    static func lockRetryDelay(failures: Int, within range: ClosedRange<Duration>) -> Duration {
        min(range.lowerBound * (1 << min(max(failures - 1, 0), 16)), range.upperBound)
    }

    /// Waits until a procedure is due or `delay` elapses.
    private func waitForLockWork(retryAfter delay: Duration?) async throws {
        if !lockSession.isWorkRequested {
            // Create a new wakeup channel for each wait because canceling the loser of the race closes its stream.
            let (requests, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            lockSession.wakeup = continuation
            await withTaskGroup(of: Void.self) { group in
                group.addTask { for await _ in requests { return } }
                if let delay {
                    group.addTask { try? await Task.sleep(for: delay, clock: .continuous) }
                }
                await group.next()
                group.cancelAll()
            }
            lockSession.wakeup = nil
        }
        try Task.checkCancellation()
    }

    /// Runs one procedure to completion. Logs only the kind of failure and swallows it, letting `run()` continue and retaining the pre-failure state
    /// (behavior N5). Omits keys, hashes, and server error bodies from logs (behavior K5).
    private func performLock(_ plan: TailnetLockPlan, over connection: ControlConnection) async {
        do {
            switch plan {
            case .nothing:
                return
            case .bootstrap:
                try await bootstrapLock(over: connection)
                // If just enabled, synchronize even when heads match. This tells the server this node's head (Go `didJustEnable`).
                try await synchronizeLock(over: connection)
            case .synchronize:
                try await synchronizeLock(over: connection)
            case .verifyDisablement:
                if try await disableLockIfVerified(over: connection) { return }
                // Wrong secret: keep the lock enabled and proceed with sync if the server's advertised head differs (behavior O4).
                if lockAuthority?.head != lockSession.server.head {
                    try await synchronizeLock(over: connection)
                }
            }
        } catch {
            let kind = switch error {
            case let error as TKAError: "verification (\(error))"
            case ControlError.http(let status): "HTTP \(status)"
            case is LockResponseError: "response hash"
            default: "request or response body"
            }
            Self.lockLog.error(
                "tailnet lock: \(String(describing: plan), privacy: .public) failed, type: \(kind, privacy: .public)"
            )
        }
    }

    /// Initializes signing authority state from the server's checkpoint (`bootstrap` in behavior N2, F5). Initial trust is TOFU for that checkpoint.
    private func bootstrapLock(over connection: ControlConnection) async throws {
        let response = try await tkaBootstrap(head: nil, over: connection)
        let authority = try Authority(bootstrappingWith: AUM(decoding: response.genesisAUM))
        lockAuthority = authority
        saveLock(authority)
        Self.lockLog.info("tailnet lock: bootstrapped")
    }

    /// Exchanges AUMs with the server to align heads (behavior Y, Go `tkaSyncLocked`).
    private func synchronizeLock(over connection: ControlConnection) async throws {
        guard var authority = lockAuthority else { return }
        let offer = authority.syncOffer()
        let response = try await tkaSyncOffer(offer, over: connection)
        let hashes = try ([response.head] + response.ancestors).map { text throws(LockResponseError) -> AUMHash in
            guard let hash = AUMHash(text: text) else { throw .unreadableHash }
            return hash
        }
        let serverOffer = SyncOffer(head: hashes[0], ancestors: Array(hashes.dropFirst()))
        guard serverOffer.head != offer.head else {
            isLockStateDiverged = false
            return
        }

        // First compute the local AUMs unknown to the server. If that computation fails, accept and send nothing (behavior Y4).
        // Only a missing common ancestor (`noIntersection`) counts as divergence (§5 TL-11b item 4). It comes from local computation on the server's
        // returned chain, so it stays distinct from RPC failures. The iteration limit (`iterationLimit`) only indicates a long chain and does not count.
        let unknownToServer: [AUM]
        do {
            unknownToServer = try authority.missingAUMs(for: serverOffer)
            isLockStateDiverged = false
        } catch {
            if error == .noIntersection { isLockStateDiverged = true }
            throw error
        }
        if !response.missingAUMs.isEmpty {
            let updates = try response.missingAUMs.map { bytes throws(TKAError) in try AUM(decoding: bytes) }
            // If any fails verification, accept none and keep filtering with the previous state.
            try authority.inform(updates)
            lockAuthority = authority
            saveLock(authority)
            // The retained count may grow by less than the received count. Already retained items are counted once, and the limit evicts items outside the active chain.
            Self.lockLog.info(
                "tailnet lock: accepted \(updates.count, privacy: .public) AUMs (\(authority.aums.count, privacy: .public) held)")
        }
        let sent = try await tkaSyncSend(head: authority.head, missing: unknownToServer, over: connection)
        guard let serverHead = AUMHash(text: sent.head) else { throw LockResponseError.unreadableHash }
        if serverHead != authority.head {
            Self.lockLog.notice("tailnet lock: head still differs from the server's after sync")
        }
    }

    /// Deletes local state if the server's disablement secret matches (behavior O). Returns true if deleted.
    ///
    /// The server's disabled claim alone cannot authorize deletion. The disablement values are signed in the trusted checkpoint, so secret verification
    /// prevents the control server from disabling the lock.
    private func disableLockIfVerified(over connection: ControlConnection) async throws -> Bool {
        guard let authority = lockAuthority else { return true }
        let response = try await tkaBootstrap(head: authority.head, over: connection)
        guard isValidDisablement(response.disablementSecret, for: authority) else {
            Self.lockLog.notice("tailnet lock: disablement secret did not match, keeping the lock enabled")
            return false
        }
        lockAuthority = nil
        isLockStateDiverged = false
        do {
            try lockStore.remove()
        } catch {
            // In-memory state is gone. If the file remains, the next startup reopens it and keeps the lock enabled (fail closed, behavior T5).
            Self.lockLog.error("tailnet lock: could not delete the state file")
        }
        return true
    }

    /// The number of rejected disablement secrets remembered for one head (contract §5 TL-11b item 2). Forgets the oldest first on overflow.
    static let maximumRejectedDisablementCount = 8

    /// Verifies the disablement secret. Skips recomputing a secret already rejected for the same state (behavior O6, TL-11b item 2).
    ///
    /// Verification uses Argon2i with 16MiB. To avoid running it for each netmap when the server repeatedly sends `Disabled`, keeps BLAKE2s-256 digests
    /// of rejected secrets and the associated head only in memory (disablement values belong to the state identified by the head, so matching heads yield the same decision).
    /// Remembering multiple rejected secrets avoids recomputing their KDFs when the server alternates among them, as long as their digests remain in the bounded cache.
    /// Computation runs on this actor without suspension, so map frame decoding cannot overlap it and the two operations' peak memory usage cannot coincide.
    private func isValidDisablement(_ secret: [UInt8], for authority: Authority) -> Bool {
        let digest = BLAKE2s.hash(secret)
        var rejected = rejectedDisablements?.head == authority.head ? rejectedDisablements?.secretDigests ?? [] : []
        if rejected.contains(where: { constantTimeEqual($0, digest) }) { return false }
        disablementDerivationCount += 1
        guard !authority.isValidDisablement(secret: secret) else {
            rejectedDisablements = nil
            return true
        }
        rejected.append(digest)
        rejectedDisablements = (authority.head, Array(rejected.suffix(Self.maximumRejectedDisablementCount)))
        return false
    }

    /// Writes state to a file. Failure leaves decisions intact: continues filtering with in-memory state and tries writing again on the next change (behavior T2).
    private func saveLock(_ authority: Authority) {
        do {
            try lockStore.save(authority)
        } catch {
            Self.lockLog.error("tailnet lock: could not save state")
        }
    }

    /// Schedules another state report if the local head differs from the last value sent (behavior N4, Go `SetTKAHead`).
    ///
    /// Compares against the value sent, before it is acknowledged in `uploadedTKAHead`. If the head changes while awaiting a report response (including
    /// returning to an empty head after disablement), reports the current head after that response. Go achieves the same by advancing a generation on each change (`auto.go`
    /// `updateControl` and `updateRoutine`). `uploadStatus` avoids sending the same head repeatedly.
    private func announceLockHead() {
        guard lockHeadText != sentTKAHead, !isStatusChangeQueued, let signals else { return }
        isStatusChangeQueued = true
        signals.yield(.statusChanged)
    }

    // MARK: RPC

    /// `GET /machine/tka/bootstrap`. Calls without a head when enabling (receives a checkpoint) and with the local head when disabling
    /// (receives a disablement secret).
    func tkaBootstrap(head: AUMHash?, over connection: ControlConnection) async throws(ControlError) -> TKABootstrapResponse {
        let request = TKABootstrapRequest(nodeKey: try registeredNodeKey(), head: head?.text ?? "")
        return try await tkaExchange("/machine/tka/bootstrap", request, limit: Self.maximumTKAResponseSize, over: connection)
    }

    /// `GET /machine/tka/sync/offer`. Reports the local head and ancestors and receives the server's head and ancestors and the AUMs this node lacks.
    func tkaSyncOffer(_ offer: SyncOffer, over connection: ControlConnection) async throws(ControlError) -> TKASyncOfferResponse {
        let request = TKASyncOfferRequest(
            nodeKey: try registeredNodeKey(), head: offer.head.text, ancestors: offer.ancestors.map(\.text)
        )
        return try await tkaExchange(
            "/machine/tka/sync/offer", request, limit: Self.maximumTKASyncOfferResponseSize, over: connection
        )
    }

    /// `GET /machine/tka/sync/send`. Sends the local head after synchronization and local AUMs unknown to the server.
    func tkaSyncSend(
        head: AUMHash, missing: [AUM], over connection: ControlConnection
    ) async throws(ControlError) -> TKASyncSendResponse {
        let request = TKASyncSendRequest(
            nodeKey: try registeredNodeKey(), head: head.text, missingAUMs: missing.map { $0.serialized() }
        )
        return try await tkaExchange("/machine/tka/sync/send", request, limit: Self.maximumTKAResponseSize, over: connection)
    }

    private func registeredNodeKey() throws(ControlError) -> NodePublicKey {
        guard let nodeKey = nodePublicKey else { throw .connection("Cannot send a TKA request before registration") }
        return nodeKey
    }

    /// One TKA RPC. Sends a `GET` over the Noise channel with a JSON body and receives a JSON response (behavior Y7).
    ///
    /// Omits `Content-Type` and the load-balancing header (Go `DoNoiseRequest`). Fails on a status other than 200 without reading the body.
    /// Has no special handling for 429 or `Retry-After`. Each request must finish within `timeouts.tkaRequest` (60 seconds).
    private func tkaExchange<Response: Decodable & Sendable>(
        _ path: String, _ body: some Encodable, limit: Int, over connection: ControlConnection
    ) async throws(ControlError) -> Response {
        let encoded: [UInt8]
        do {
            encoded = Array(try JSONEncoder().encode(body))
        } catch {
            throw .connection("Could not encode the TKA request as JSON")
        }
        let request = HTTP2ClientConnection.Request(method: "GET", path: path, authority: connection.authority)
        let timeout = timeouts.tkaRequest
        let received: [UInt8]
        do {
            received = try await withTimeout(timeout) {
                var reader = try await connection.responseStream(to: request, body: encoded)
                // Dropping the reader cancels the stream (RST_STREAM). Skip reading the rejection body.
                guard reader.status == 200 else { throw ControlError.http(status: reader.status) }
                var collected: [UInt8] = []
                while let chunk = try await reader.nextChunk() {
                    guard collected.count + chunk.count <= limit else {
                        throw ControlError.connection("TKA response body exceeds the limit of \(limit) bytes")
                    }
                    collected += chunk
                }
                return collected
            }
        } catch let error as ControlError {
            throw error
        } catch is TimeoutError {
            throw .connection("TKA request did not finish within \(timeout)")
        } catch {
            throw .connection("TKA request was canceled")
        }
        do {
            return try JSONDecoder().decode(Response.self, from: Data(received))
        } catch {
            throw .connection("TKA response did not contain the expected JSON")
        }
    }
}
