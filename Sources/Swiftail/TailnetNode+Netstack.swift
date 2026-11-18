import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import SwiftailNetstack

/// Connects the node to the in-process TCP stack (`docs/contracts/SwiftailNetstack.md` behaviors N, X10, and K).
///
/// ```
/// engine.receive ─ .ipPacket ─► deliverToDevice ─► inbox ─► stack.receive ─┬ .ipPacket ─► engine.send ─► Magicsock …
///                                                                       │                  └ .ipPacket(local address) ─► inbox
///                                                                       └ .event ─► Wake waiting read, write, accept, or connect
/// App call (read, write, connect, close…) ─► stack.<call> ─► Process output as above
/// Timer ─► stack.advance(to:)
/// ```
///
/// The stack is a value stored on the node actor. Exchanges between the stack, engine, and `Magicsock` complete in one
/// actor execution without `await`. There is therefore no buffer, drop, or second timer between the node and stack
/// (contract “Architecture,” item 3).
///
/// Work from one event runs through a queue (`Netstack.inbox`) without recursion (behavior N4). Packets the engine
/// emits for the device (from peers, or looped back from a connection to a local address) accumulate in the queue. Pass
/// them to the stack in order when the node's outermost processing pass ends (`settleNetstack(at:)`). When the queue is
/// empty, call `advance(to:)` with the same timestamp to emit delayed ACKs.
///
/// Waiting calls suspend with `suspend(until:)` and stack events wake them. The wakeup channel carries no value. The
/// resumed call checks state again and decides what to do. This avoids losing data or connections if cancellation races
/// with wakeup.
extension TailnetNode {
    // MARK: Lifecycle (Behavior N8)

    /// Creates the stack at the start of `run()`. Does nothing for devices other than `.inProcess`, which have no stack state.
    ///
    /// Draws the 32-byte ISN secret from system randomness on each `run()` (contract behavior S7). Installs listeners
    /// opened before `run()` on the stack (behavior A1).
    func startNetstack() {
        guard case .inProcess = device else { return }
        closeDroppedListeners()
        var generator = SystemRandomNumberGenerator()
        let isnSecret = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        netstack = Netstack(stack: TCPStack(isnSecret: isnSecret, now: .now))
        for token in listenerRecords.keys.sorted() {
            guard let port = listenerRecords[token]?.port else { continue }
            do throws(TCPStack.ListenError) {
                listenerRecords[token]?.stackID = try netstack?.stack.listen(on: port)
            } catch {
                // This does not occur because `listen(port:)` checks the same duplicate and limit rules as the stack
                // first. If it occurs, end that listener's stream.
                listenerRecords.removeValue(forKey: token)?.waiter?.finish()
            }
        }
    }

    /// Called at the end of `run()`. May be called twice.
    ///
    /// Closes all listeners (RST for unaccepted connections) and emits one RST per application-held connection. Call
    /// while the socket and engine still exist so the RSTs can go out directly. Items in the DERP channel may be lost.
    /// Wakes all waiting calls, which see the missing stack and throw `notRunning`, and ends listener streams. Ignores
    /// handles released afterward.
    func stopNetstack() {
        let now = ContinuousClock.now
        for token in listenerRecords.keys.sorted() {
            closeListener(token, at: now)
        }
        if let ids = netstack?.connections.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            for id in ids {
                process(netstack?.stack.abort(id, at: now) ?? [], at: now)
            }
            // Also aborts connections with RST if the application released them with `close` but they are still
            // closing, or if they are still establishing. This keeps the peer from waiting until the retransmission
            // limit.
            process(netstack?.stack.abortAll() ?? [], at: now)
            netstack?.connections.values.forEach { $0.finishWaiters() }
            netstack = nil
        }
        handleReleases.finish()
    }

    /// Closes listeners whose handles were released, first called by `listen(port:)` and the start of `run()`. Only a
    /// child of `run()` receives close requests from released handles, so this keeps listeners released before `run()`
    /// or not yet received by the child from holding ports or counting toward the limit.
    func closeDroppedListeners() {
        for token in listenerRecords.keys.sorted() where listenerRecords[token]?.handle == nil {
            closeListener(token)
        }
    }

    /// Cleans up released connection and listener handles. Runs until canceled (behavior N9).
    func releaseHandles() async {
        for await release in handleReleaseStream {
            switch release {
            case let .connection(id):
                abortConnection(id)
            case let .listener(token):
                closeListener(token)
            }
        }
    }

    // MARK: Output Processing (Behaviors N2~N5)

    /// Enqueues one packet emitted by the engine for the device (behavior N2). Called only within a node processing
    /// pass. The packet enters the stack when the outermost pass ends. The stack drops non-TCP packets.
    func deliverToNetstack(_ ipPacket: [UInt8]) {
        guard netstack != nil, inProcessLoss?.dropsNext() != true else { return }
        netstack?.inbox.append(ipPacket)
        netstack?.needsSettling = true
    }

    /// Processes stack output in emission order. Called after every call that mutates the stack. Finishes the queue and
    /// delayed ACKs at the end of the outermost pass.
    func process(_ outputs: [TCPStack.Output], at now: ContinuousClock.Instant) {
        guard netstack != nil else { return }
        beginProcessing()
        netstack?.needsSettling = true
        handle(outputs, at: now)
        endProcessing(at: now)
    }

    /// If the stack took a step during this pass, passes queued packets to it in order. Once the queue is empty, calls
    /// `advance(to:)` with the same timestamp to send due ACKs. If output loops back (a connection to a local address) and
    /// fills the queue again, repeats until done. The stack's buffering limits ensure that the loop terminates. Called when the node's outermost
    /// processing pass ends (`endProcessing(at:)`). A whole group of received UDP datagrams concludes with one
    /// `advance`.
    func settleNetstack(at now: ContinuousClock.Instant) {
        guard netstack?.needsSettling == true else { return }
        repeat {
            while let batch = netstack?.inbox, !batch.isEmpty {
                netstack?.inbox = []
                for packet in batch {
                    handle(netstack?.stack.receive(packet, at: now) ?? [], at: now)
                }
            }
            handle(netstack?.stack.advance(to: now) ?? [], at: now)
        } while netstack?.inbox.isEmpty == false
        netstack?.needsSettling = false
    }

    private func handle(_ outputs: [TCPStack.Output], at now: ContinuousClock.Instant) {
        for output in outputs {
            switch output {
            case let .ipPacket(bytes):
                // The engine preserves M5 local processing. Loops back packets to local addresses (→ queue) and refuses
                // the service IP with RST (N3).
                guard inProcessLoss?.dropsNext() != true else { continue }
                process(engine?.send(bytes, at: now) ?? [], at: now)
            case let .event(event):
                dispatch(event, at: now)
            case let .dropped(.limitReached(limit)):
                countLimitDrop(limit)
            case .dropped:
                break
            case let .releasedConnectionClosed(reason, statistics):
                logClose(reason, statistics, afterRelease: true, at: now)
            }
        }
    }

    /// Wakes waiting calls on stack events (behavior N5).
    private func dispatch(_ event: TCPStack.Event, at now: ContinuousClock.Instant) {
        switch event {
        case let .established(id):
            netstack?.connections[id]?.isEstablished = true
            wakeWriter(id)
        case let .acceptable(listenerID):
            for (token, record) in listenerRecords where record.stackID == listenerID {
                listenerRecords[token]?.waiter?.finish()
            }
        case let .readable(id), let .endOfStream(id):
            wakeReader(id)
        case let .writable(id):
            wakeWriter(id)
        case let .closed(id, reason, statistics):
            // A missing record means a connection released by the app via close or abort ended immediately within that
            // call (abort, close with unread data, or a canceled connect). There is no call to wake, so only log it.
            let isHeld = netstack?.connections[id] != nil
            if isHeld {
                netstack?.connections[id]?.closeReason = reason
                wakeReader(id)
                wakeWriter(id)
            }
            logClose(reason, statistics, afterRelease: !isHeld, at: now)
        }
    }

    /// Logs one `Connection ended` line (contract “Connection close statistics log”). Contains only numbers and Booleans.
    private func logClose(
        _ reason: TCPStack.CloseReason, _ statistics: TCPConnection.Statistics, afterRelease: Bool,
        at now: ContinuousClock.Instant
    ) {
        Self.log.info(
            "\(statistics.closeLogLine(reason: reason, closedAt: now, afterRelease: afterRelease), privacy: .public)")
    }

    /// Records a read-side event and wakes a waiting `read`. An event may occur in the call's own output processing
    /// before anything is waiting to be woken, as on a connection to a local address. The record lets the call check
    /// and retry before waiting.
    func wakeReader(_ id: TCPStack.ConnectionID) {
        netstack?.connections[id]?.hasReadEvent = true
        netstack?.connections[id]?.readWaiter?.finish()
    }

    /// Records a write-side event (space, establishment, or closure) and wakes a waiting `write` or `connect`.
    func wakeWriter(_ id: TCPStack.ConnectionID) {
        netstack?.connections[id]?.hasWriteEvent = true
        netstack?.connections[id]?.writeWaiter?.finish()
    }

    /// Counts SYNs dropped at a limit. Logs only the 1st, 2nd, 4th, 8th, and so on, to keep a flood from overwhelming the log (behavior K2).
    private func countLimitDrop(_ limit: TCPStack.Limit) {
        netstack?.limitDropCount += 1
        let count = netstack?.limitDropCount ?? 0
        guard count & (count - 1) == 0 else { return }
        Self.log.notice("Dropped SYN at limit: \(limit.logName, privacy: .public), \(count, privacy: .public) total")
    }

    // MARK: Waiting

    /// Installs the wakeup channel in state through `register` and waits for a wakeup or cancellation of the calling Task.
    ///
    /// Creates a fresh one-use channel per wait. The waking side only calls `finish()`, so the call wakes exactly once
    /// because `finish()` on an already ended channel has no effect. The resumed call removes the channel from state.
    /// There is no `await` between registration and waiting, so a wakeup in between cannot be missed. Two requirements
    /// follow.
    /// - Before calling, check that there is a record where the channel can be installed. No one wakes a channel installed without a record.
    /// - Any code that removes a whole record from state calls `finish()` on that record's channel.
    func suspend(until register: (Wakeup) -> Void) async {
        let (wakeups, wakeup) = AsyncStream.makeStream(of: Void.self)
        register(wakeup)
        for await _ in wakeups {}
    }

    // MARK: Netmap (Behaviors N7, S9, X10)

    /// Called whenever the engine recomputes peers, both when applying a netmap and after handling key expiration
    /// (which changes address ownership without a new netmap). Replaces the owner table with the one the engine built
    /// alongside its peers and passes it to the stack. Since `whoIs` and the stack see the same table from the same
    /// instant, `whoIs` on a live connection's remote address identifies the peer on the other end when the connection was established (host
    /// contract behavior W6).
    ///
    /// Without an engine (before registration), there is no data plane. Performs the same calculation directly from the netmap.
    func updateAddressOwners(for netmap: Netmap) {
        addressOwners = engine?.addressOwners ?? EnginePeer.addressOwners(in: netmap, at: Date())
        updateNetstack(for: netmap)
    }

    /// Called on every change to the owner table (`addressOwners`). Passes local addresses to the stack and compares
    /// each data plane peer address's owner (node key). Ends connections for addresses whose owner disappeared or
    /// changed (`peerRemoved`, sends nothing). Prevents a different node inheriting an address from continuing the
    /// previous node's connection (contract lead session decision N8). Also passes per-peer address groups from the
    /// same table so connections across a peer's IPv4 and IPv6 addresses count toward the same per-peer limit.
    ///
    /// Peer packets have their source checked against that peer's AllowedIPs (engine contract M3 behaviors 2 and 5), so
    /// all connections for an address were established with its owner at the time. Compare owners per address without
    /// storing keys per connection. Also ends establishing and queued connections.
    private func updateNetstack(for netmap: Netmap) {
        guard netstack != nil else { return }
        let owners = addressOwners.mapValues(\.key)
        let previous = netstack?.addressOwners ?? [:]
        netstack?.addressOwners = owners
        netstack?.stack.setRemoteAddressGroups(addressOwners.mapValues { Int(truncatingIfNeeded: $0.id) })

        let localAddresses = netmap.selfNode.addresses.filter(\.isSingleAddress).map(\.address)
        var outputs = netstack?.stack.setLocalAddresses(localAddresses) ?? []
        let lost = previous.filter { owners[$0.key] != $0.value }.keys
        for address in lost.sorted(by: { $0.bytes.lexicographicallyPrecedes($1.bytes) }) {
            outputs += netstack?.stack.removeConnections(toRemoteAddress: address) ?? []
        }
        process(outputs, at: .now)
    }

    // MARK: Test Loss (Behavior N11)

    /// For tests only (outside the public API). Drops packets between the stack and engine in both directions with
    /// probability `rate`. Generates randomness from `seed`, so the same seed drops packets at the same positions. A
    /// value of 0 (the default) drops nothing. Packets for a connection to a local address are checked twice, on the
    /// way out and back. Clamps `rate` to 0…1.
    ///
    /// Used by the gate (`SwiftailInteropTests`) to measure throughput at 1% and 5% loss (contract gate (a) items 8 and
    /// 9). No loss injection on the Go peer's side.
    package func setInProcessLoss(rate: Double, seed: UInt64) {
        let clamped = rate.isNaN ? 0 : min(max(rate, 0), 1)
        inProcessLoss = clamped > 0 ? PacketLoss(rate: clamped, generator: SplitMix64(seed: seed)) : nil
    }
}

// MARK: - Values Held by the Node

/// A released handle (`deinit`). A child of `run()` receives and closes it.
enum HandleRelease: Sendable {
    case connection(TCPStack.ConnectionID)
    case listener(UInt64)
}

/// A channel for waking one waiting call (`TailnetNode.suspend(until:)`).
typealias Wakeup = AsyncStream<Void>.Continuation

/// TCP state the node holds during `run()` with an `.inProcess` device.
struct Netstack: Sendable {
    var stack: TCPStack
    /// Maps data plane peers' tailnet addresses to their owners. Compared whenever the node's owner table changes (behavior X10).
    var addressOwners: [IPAddress: NodePublicKey] = [:]
    /// Connections held by the application or still connecting. Removed on app `close` or `abort`, or when the handle is released.
    var connections: [TCPStack.ConnectionID: ConnectionRecord] = [:]
    /// Packets the engine emitted for the device that have yet to enter the stack (behavior N4).
    var inbox: [[UInt8]] = []
    /// The stack took a step or a packet entered the queue in this pass. Pass in the queue and call `advance` when the outermost pass ends.
    var needsSettling = false
    /// The count of SYNs dropped at a limit, for logging.
    var limitDropCount = 0
}

/// Edge state for one application-held or connecting connection. Only the stack holds data. There is no separate buffer
/// at the edge (behavior A5).
struct ConnectionRecord: Sendable {
    /// A waiting `read`.
    var readWaiter: Wakeup?
    /// A waiting `write`, or a `connect` waiting for establishment.
    var writeWaiter: Wakeup?
    /// A read-side or write-side event arrived after the last attempt (`TailnetNode.wakeReader(_:)`).
    var hasReadEvent = false
    var hasWriteEvent = false
    /// The three-way handshake completed. True from the start on an accepted connection.
    var isEstablished = false
    /// The application called `finishWriting`. Later `write` calls throw `closed`.
    var hasFinishedWriting = false
    /// The closure reason reported by the stack. For `finished`, returns nil after remaining data is read.
    var closeReason: TCPStack.CloseReason?

    func finishWaiters() {
        readWaiter?.finish()
        writeWaiter?.finish()
    }
}

/// An open listener.
struct ListenerRecord: Sendable {
    let port: UInt16
    /// The handle held by the app. A weak reference, so nil means the handle was released. Treat the listener as closed
    /// even before the node handles the `deinit` close request (`HandleRelease`,
    /// `TailnetNode.closeDroppedListeners()`).
    weak var handle: TailnetListener?
    /// The stack listener. If opened before `run()`, nil until `run()` starts.
    var stackID: TCPStack.ListenerID?
    /// A stream waiting for the next connection.
    var waiter: Wakeup?
}

/// Loss injection for tests (`TailnetNode.setInProcessLoss(rate:seed:)`).
struct PacketLoss: Sendable {
    let rate: Double
    var generator: SplitMix64

    /// Decides whether to drop the next packet.
    mutating func dropsNext() -> Bool {
        Double.random(in: 0..<1, using: &generator) < rate
    }
}

/// A seeded random number generator (SplitMix64, Steele·Lea·Flood 2014). Used only for loss injection in tests. It is not cryptographic.
struct SplitMix64: RandomNumberGenerator, Sendable {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

extension IPPrefix {
    /// A prefix for one address (/32, /128). These are the node's tailnet addresses.
    var isSingleAddress: Bool {
        length == address.bytes.count * 8
    }
}

extension ConnectionError {
    /// Converts the closure reason reported by the stack to the error later calls throw. `finished` is not an error, so
    /// read remaining data and then return nil. `aborted` means this side aborted, so it maps to `closed`.
    init?(closedBy reason: TCPStack.CloseReason) {
        switch reason {
        case .finished: return nil
        case .reset: self = .reset
        case .refused: self = .refused
        case .timedOut: self = .timedOut
        case .aborted: self = .closed
        case .peerRemoved: self = .peerRemoved
        }
    }
}

extension TCPStack.CloseReason {
    /// A name for logging.
    var logName: String {
        switch self {
        case .finished: "finished"
        case .reset: "reset"
        case .refused: "refused"
        case .timedOut: "timedOut"
        case .aborted: "aborted"
        case .peerRemoved: "peerRemoved"
        }
    }
}

extension TCPConnection.Statistics {
    /// The line to log when the connection ends. It contains only numbers and Booleans. The contract's “Connection close
    /// statistics log” describes each value. If the connection ended after the app released it, appends
    /// `, ended after release`.
    func closeLogLine(
        reason: TCPStack.CloseReason, closedAt now: ContinuousClock.Instant, afterRelease: Bool
    ) -> String {
        let lifetime = Int((now - openedAt) / .milliseconds(1))
        return "Connection ended: \(reason.logName), lifetime \(lifetime)ms, sent \(sentBytes)B, retransmitted \(retransmittedBytes)B, "
            + "RTO \(retransmissionTimeouts), fast retransmits \(fastRetransmits), "
            + "partial ACK retransmits \(partialAcknowledgmentRetransmits), duplicate ACKs \(duplicateAcknowledgments), "
            + "ACKs with SACK \(acknowledgmentsWithSACK), SACK negotiated \(sackPermitted), "
            + "peak cwnd \(maximumCongestionWindow)B, ssthresh reductions \(slowStartThresholdReductions)"
            + (afterRelease ? ", ended after release" : "")
    }
}

extension TCPStack.Limit {
    /// A name for logging.
    var logName: String {
        switch self {
        case .halfOpenConnections: "halfOpenConnections"
        case .halfOpenConnectionsPerAddress: "halfOpenConnectionsPerAddress"
        case .acceptQueue: "acceptQueue"
        case .acceptQueueShare: "acceptQueueShare"
        case .connections: "connections"
        case .connectionsPerAddress: "connectionsPerAddress"
        case .timeWaitRecords: "timeWaitRecords"
        }
    }
}
