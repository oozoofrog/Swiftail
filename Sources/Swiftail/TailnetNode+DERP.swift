import Synchronization
import SwiftailBase
import SwiftailDERP
import SwiftailMagicsock

/// The lifecycle of a DERP region connection. There is one connection per region. Nonwaiting actor methods open and close them.
///
/// - **Opening** (`openDERPLink`). Opens when the home region is selected (`isPreferred: true`) or when `Magicsock`
///   wants to send to a region without a connection (`isPreferred: false`). Creates a client and mailbox, adds them to
///   the table, and hands them to `maintainDERP()`. The mailbox accepts datagrams before the client runs, so it retains
///   even the first one. Binds the connection to the current default interface. `DERPClient` skips binding for loopback
///   servers.
/// - **Running** (`maintainDERP`). Starts a child group (`serve`) for each connection received. Canceling `run()` stops all groups.
/// - **Closing** (`closeDERPLink`). Removes the entry from the table and closes the mailbox. When the mailbox ends, the
///   connection's group winds down on its own. Closes if a region leaves the DERPMap, its server definition changes, or
///   the node key or default interface changes. A new home region does not close the old one (magicsock contract E6).
///
/// Contract `docs/contracts/SwiftailEngine.md`, “Changes in M4” N3 and N7, and `docs/contracts/SwiftailTunnel.md` behaviors N 3 and M.
// shortcut: Does not clean up non-home connections after 60 seconds of disuse (DERP notes §4.9 item 5). The number open
// is bounded by the DERPMap region count. Revisit at M5 memory measurements. Does not resend NotePreferred for already
// open connections when the home region changes (server statistics).
extension TailnetNode {
    /// One DERP region connection, with its client and a mailbox for outgoing datagrams.
    struct DERPLink: Sendable {
        let region: Int64
        /// The server list at connection creation. Closes the connection if the DERPMap definition differs.
        let servers: [DERPServer]
        let client: DERPClient
        let outbox: DERPOutbox
    }

    /// A WireGuard or disco message emitted by the engine for DERP.
    struct DERPDatagram: Sendable {
        var bytes: [UInt8]
        var peer: NodePublicKey
    }

    /// Datagrams still waiting to go to a region connection. The connection's sending child takes them one at a time.
    ///
    /// Keeps only the newest 256 datagrams and up to 1MiB total. Drops the oldest first on overflow (contract behavior
    /// M). `AsyncStream`'s `bufferingNewest` limits only count, so keep the buffer here (same design as the
    /// `DatagramSocket` receive queue). There is one consumer.
    final class DERPOutbox: Sendable {
        private struct State {
            var datagrams: [DERPDatagram] = []
            /// The total bytes in `datagrams`.
            var bytes = 0
            /// The consumer waiting for a datagram.
            var waiter: CheckedContinuation<DERPDatagram?, Never>?
            var isClosed = false
        }

        private let state = Mutex(State())

        /// Enqueues a datagram or hands it directly to a waiting consumer. Drops it after close.
        func push(_ datagram: DERPDatagram) {
            let waiter: CheckedContinuation<DERPDatagram?, Never>? = state.withLock { state in
                guard !state.isClosed else { return nil }
                // The queue is empty if a consumer is waiting.
                if let waiter = state.waiter.take() { return waiter }
                if state.datagrams.count >= TailnetNode.outboundDatagramLimit {
                    state.bytes -= state.datagrams.removeFirst().bytes.count
                }
                // Drop the oldest first until the new datagram fits. Stop when the queue is empty even if the datagram exceeds the limit.
                while state.bytes + datagram.bytes.count > TailnetNode.outboundByteLimit, !state.datagrams.isEmpty {
                    state.bytes -= state.datagrams.removeFirst().bytes.count
                }
                state.datagrams.append(datagram)
                state.bytes += datagram.bytes.count
                return nil
            }
            waiter?.resume(returning: datagram)
        }

        /// Closes the mailbox. Drops remaining datagrams and gives nil to a waiting consumer.
        func close() {
            let waiter = state.withLock { state in
                state.isClosed = true
                state.datagrams = []
                state.bytes = 0
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// Returns the next datagram, waiting for it if needed. Returns nil if closed or the waiting Task is canceled.
        func next() async -> DERPDatagram? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<DERPDatagram?, Never>) in
                    let ready: DERPDatagram?? = state.withLock { state in
                        if !state.datagrams.isEmpty {
                            let datagram = state.datagrams.removeFirst()
                            state.bytes -= datagram.bytes.count
                            return .some(datagram)
                        }
                        // If already canceled, the cancellation handler ran first, so do not wait. Also skip waiting for a second consumer.
                        if state.isClosed || Task.isCancelled || state.waiter != nil { return .some(nil) }
                        state.waiter = continuation
                        return .none
                    }
                    if let ready { continuation.resume(returning: ready) }
                }
            } onCancel: {
                state.withLock { $0.waiter.take() }?.resume(returning: nil)
            }
        }

        /// The buffered datagram count and total bytes. Used in tests.
        var backlog: (count: Int, bytes: Int) {
            state.withLock { ($0.datagrams.count, $0.bytes) }
        }
    }

    // MARK: Opening and Closing

    /// Opens the connection for `region`. Returns the existing connection if already open. Returns nil if there is no
    /// node key or no usable server for the region in the DERPMap.
    @discardableResult
    func openDERPLink(to region: Int64) -> DERPLink? {
        if let link = derpLinks[region] { return link }
        let servers = DERPServer.servers(of: lastNetmap?.derpMap?.regions?[region])
        guard let nodeKey, !servers.isEmpty else { return nil }
        let link = DERPLink(
            region: region,
            servers: servers,
            client: DERPClient(servers: servers, privateKey: nodeKey, isPreferred: region == homeRegion, interface: defaultInterface),
            outbox: DERPOutbox()
        )
        derpLinks[region] = link
        openedDERPLinkContinuation.yield(link)
        return link
    }

    /// Closes the connection for `region`. Closing the mailbox ends the connection's group. Drops pending datagrams.
    func closeDERPLink(to region: Int64) {
        connectedDERPRegions.remove(region)
        derpLinks.removeValue(forKey: region)?.outbox.close()
    }

    func closeAllDERPLinks() {
        for region in derpLinks.keys {
            closeDERPLink(to: region)
        }
    }

    /// A datagram `Magicsock` requested to send to `region`. Opens a connection if none exists, for any region in the
    /// DERPMap. Drops the datagram if it cannot open one.
    func sendDERP(_ bytes: [UInt8], to peer: NodePublicKey, region: Int64) {
        openDERPLink(to: region)?.outbox.push(DERPDatagram(bytes: bytes, peer: peer))
    }

    // MARK: Running Connections

    /// Starts each opened connection's group as a child. Runs until canceled.
    func maintainDERP() async {
        await withDiscardingTaskGroup { group in
            for await link in openedDERPLinks {
                group.addTask { await self.serve(link) }
            }
        }
    }

    /// Runs the lifecycle of one connection. A closed mailbox (`closeDERPLink`) or cancellation stops the client and
    /// its companion work together.
    private func serve(_ link: DERPLink) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await link.client.run() }
            group.addTask {
                for await event in link.client.events {
                    await self.handle(event, from: link)
                }
            }
            group.addTask {
                while let datagram = await link.outbox.next() {
                    await link.client.send(datagram.bytes, to: datagram.peer)
                }
            }
            await group.next()
            group.cancelAll()
        }
    }

    private func handle(_ event: DERPClient.Event, from link: DERPLink) {
        // Connection events emitted while an already closed connection winds down do not affect current state.
        let isCurrent = derpLinks[link.region]?.client === link.client
        switch event {
        case let .packet(bytes, from: peer):
            let now = ContinuousClock.now
            process(magicsock?.receiveDERP(bytes, from: peer, region: link.region, at: now) ?? [], at: now)
        case .connected:
            guard isCurrent else { return }
            Self.log.info("DERP region \(link.region, privacy: .public): connected")
            connectedDERPRegions.insert(link.region)
            if link.region == homeRegion { announce(stateMachine.connected()) }
        case .disconnected:
            guard isCurrent else { return }
            // A disconnect after `.running` leaves the state unchanged (behavior B). The client backs off and reconnects.
            Self.log.info("DERP region \(link.region, privacy: .public): disconnected, reconnecting")
            connectedDERPRegions.remove(link.region)
        case let .attemptFailed(failure, consecutiveFailures):
            // The 5-second backoff cap means failures continue indefinitely without a network. Log only the first
            // consecutive failure and every tenth one thereafter.
            guard isCurrent, consecutiveFailures == 1 || consecutiveFailures.isMultiple(of: 10) else { return }
            Self.log.info(
                "DERP region \(link.region, privacy: .public): connection failed (\(String(describing: failure), privacy: .public)), \(consecutiveFailures, privacy: .public) consecutive failures"
            )
        case .peerGone:
            // shortcut: Does not use reverse DERP regions, so there is nothing to remove (magicsock contract D3).
            break
        }
    }
}
