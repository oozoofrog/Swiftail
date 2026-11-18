import SwiftailBase
import SwiftailNetstack

/// Listening, connecting, and connection handle calls (`docs/contracts/SwiftailNetstack.md`, “Public API,” behavior A).
///
/// The app's Task crosses to the node actor and calls the stack. If it must wait, that Task suspends on the node
/// (`suspend(until:)`) and a stack event wakes it. There are no detached Tasks. A wait ends in four ways, with one
/// return from the call in every case.
/// - Event (readable data, available space, establishment, or entry in the queue) → retry.
/// - Connection ends → throw the corresponding error, or `closed` if the app called `close` or `abort`.
/// - Calling task is canceled → `read` throws `cancelled` and preserves the connection and data, `write` aborts
///   with RST and throws `cancelled`, `connect` discards the attempt and throws `cancelled`, and the listener stream
///   returns nil.
/// - `run()` ends → throw `notRunning`, or return nil for the listener stream.
extension TailnetNode {
    /// The listener limit (contract behaviors S3 and M), the same as the stack's. The node counts first so listeners
    /// opened before `run()` count toward it.
    static let listenerLimit = 16

    // MARK: Listening (Behavior A1)

    /// Listens on one TCP port on this node's tailnet addresses (IPv4 and IPv6). Corresponds to tsnet `Listen("tcp", ":<port>")`.
    ///
    /// May be called before `run()`, which installs the listener on the stack when it starts, and before a netmap
    /// arrives. The listener listens until it is closed or released or `run()` ends. This call first closes released
    /// listeners so they do not hold ports or count toward the limit (16).
    ///
    /// - Throws: `invalidConfiguration` if the device is not `.inProcess` or the port is 0, `addressInUse` if a
    ///   listener still uses that port, `limitReached` if 16 listeners are in use, or `notRunning` if `run()` ended or
    ///   if startup checks ended `run()` (`stateDirectoryInUse` and so on).
    public func listen(port: UInt16) throws(ConnectionError) -> TailnetListener {
        try checkInProcessDevice(port: port)
        if hasRun, !isRunning { throw .notRunning }
        closeDroppedListeners()
        guard !listenerRecords.values.contains(where: { $0.port == port }) else { throw .addressInUse }
        guard listenerRecords.count < Self.listenerLimit else { throw .limitReached }
        var stackID: TCPStack.ListenerID?
        do throws(TCPStack.ListenError) {
            stackID = try netstack?.stack.listen(on: port)
        } catch {
            throw error == .addressInUse ? .addressInUse : .limitReached
        }
        let token = nextListenerToken
        nextListenerToken += 1
        let listener = TailnetListener(node: self, token: token, port: port)
        listenerRecords[token] = ListenerRecord(port: port, handle: listener, stackID: stackID)
        Self.log.info("Started listening: port \(port, privacy: .public)")
        return listener
    }

    /// The listener's next connection. Returns immediately if queued or waits for one to arrive.
    ///
    /// The accepted connection still holds data and FIN received while queued. `read` reads from the stack.
    func nextConnection(from token: UInt64) async -> TailnetConnection? {
        while let record = listenerRecords[token], record.waiter == nil {
            let now = ContinuousClock.now
            if let stackID = record.stackID, let accepted = netstack?.stack.accept(from: stackID, at: now) {
                let connection = adoptConnection(accepted.connection)
                // Sends an ACK opening the receive window that was capped while queued.
                process(accepted.outputs, at: now)
                if let connection {
                    Self.log.info("Accepted connection: port \(record.port, privacy: .public)")
                    return connection
                }
            }
            await suspend { listenerRecords[token]?.waiter = $0 }
            listenerRecords[token]?.waiter = nil
            if Task.isCancelled { return nil }
        }
        return nil
    }

    /// Stops listening. Aborts queued connections with RST and ends the waiting stream. An unknown listener has no effect.
    func closeListener(_ token: UInt64, at now: ContinuousClock.Instant = .now) {
        guard let record = listenerRecords.removeValue(forKey: token) else { return }
        record.waiter?.finish()
        if let stackID = record.stackID {
            process(netstack?.stack.stopListening(stackID) ?? [], at: now)
        }
        Self.log.info("Stopped listening: port \(record.port, privacy: .public)")
    }

    // MARK: Connecting (Behavior A2)

    /// Opens a TCP connection to a tailnet peer. Corresponds to tsnet `Dial(ctx, "tcp", "<host>:<port>")`. Waits for
    /// the connection to establish.
    ///
    /// `host` is an IP address or a name in the netmap, either a MagicDNS FQDN (`rd-phone-1a2b3c4d.tail0001.ts.net`) or
    /// a short name without the MagicDNS suffix (`rd-phone-1a2b3c4d`). Ignores case and a trailing dot. When given a
    /// name, prefers the node's IPv4 address. The address must belong to a peer installed in the data plane or to this
    /// node. Unlike tsnet, does not look up names outside the tailnet through system DNS or dial through an OS socket.
    /// A connection to a local address reaches a local listener.
    ///
    /// - Throws: `invalidConfiguration` if the device is not `.inProcess`, the port is 0, or the host is empty. Throws
    ///   `notRunning` if the state is not `.running` or `run()` ends during establishment, `unknownHost` if the name or
    ///   address is not found, `limitReached` at 256 connections or 64 to that peer, `refused` if the peer refuses,
    ///   `timedOut` if no reply arrives within 247 seconds, `peerRemoved` if the address owner changes during the
    ///   attempt, `reset` if the peer sends RST just after establishment and before this call returns, or `cancelled`
    ///   if the calling Task is canceled (discards the attempt).
    public func connect(to host: String, port: UInt16) async throws(ConnectionError) -> TailnetConnection {
        try checkInProcessDevice(port: port)
        guard !host.isEmpty else { throw .invalidConfiguration("Host is empty") }
        guard netstack != nil, stateMachine.state == .running else { throw .notRunning }
        guard let address = lastNetmap?.address(ofHost: host),
            netstack?.addressOwners[address] != nil || netstack?.stack.localAddresses.contains(address) == true
        else { throw .unknownHost }

        let now = ContinuousClock.now
        let opened: (connection: TCPStack.ConnectionID, outputs: [TCPStack.Output])?
        do throws(TCPStack.ConnectError) {
            opened = try netstack?.stack.connect(to: IPEndpoint(address: address, port: port), at: now)
        } catch {
            throw error == .limitReached ? .limitReached : .unknownHost
        }
        guard let id = opened?.connection else { throw .notRunning }
        netstack?.connections[id] = ConnectionRecord()
        process(opened?.outputs ?? [], at: now)

        while let record = netstack?.connections[id] {
            if let reason = record.closeReason {
                netstack?.connections[id] = nil
                throw ConnectionError(closedBy: reason) ?? .closed
            }
            if record.isEstablished, let connection = adoptConnection(id) {
                Self.log.info("Connected: port \(port, privacy: .public)")
                return connection
            }
            await suspend { netstack?.connections[id]?.writeWaiter = $0 }
            netstack?.connections[id]?.writeWaiter = nil
            if Task.isCancelled {
                if netstack?.connections.removeValue(forKey: id) != nil {
                    let now = ContinuousClock.now
                    process(netstack?.stack.abort(id, at: now) ?? [], at: now)
                }
                throw .cancelled
            }
        }
        throw .notRunning
    }

    // MARK: Connection Handle Calls (Behaviors A3~A7)

    /// `TailnetConnection.read(upTo:)`.
    func readConnection(_ id: TCPStack.ConnectionID, upTo maximumLength: Int) async throws(ConnectionError) -> [UInt8]? {
        guard maximumLength > 0 else { throw .invalidConfiguration("Read length must be at least 1") }
        guard try usableRecord(id).readWaiter == nil else { throw .concurrentUse }
        while true {
            netstack?.connections[id]?.hasReadEvent = false
            let now = ContinuousClock.now
            let result = netstack?.stack.read(upTo: maximumLength, from: id, at: now) ?? (bytes: [], outputs: [])
            process(result.outputs, at: now)
            if !result.bytes.isEmpty { return result.bytes }

            let record = try usableRecord(id)
            if record.closeReason == .finished || netstack?.stack.connection(id)?.hasReceivedEndOfStream == true {
                return nil
            }
            guard !record.hasReadEvent else { continue }
            await suspend { netstack?.connections[id]?.readWaiter = $0 }
            netstack?.connections[id]?.readWaiter = nil
            if Task.isCancelled { throw .cancelled }
        }
    }

    /// `TailnetConnection.write(_:)`. Writes as much as fits, then waits for free space before continuing with the rest
    /// (behaviors A4 and A5).
    func writeConnection(_ id: TCPStack.ConnectionID, _ bytes: [UInt8]) async throws(ConnectionError) {
        guard try usableRecord(id).writeWaiter == nil else { throw .concurrentUse }
        var written = 0
        while true {
            guard !(try usableRecord(id).hasFinishedWriting) else { throw .closed }
            guard written < bytes.count else { return }
            netstack?.connections[id]?.hasWriteEvent = false
            let now = ContinuousClock.now
            let result = netstack?.stack.write(bytes[written...], to: id, at: now) ?? (accepted: 0, outputs: [])
            written += result.accepted
            process(result.outputs, at: now)
            guard written < bytes.count else { return }

            guard !(try usableRecord(id).hasWriteEvent) else { continue }
            await suspend { netstack?.connections[id]?.writeWaiter = $0 }
            netstack?.connections[id]?.writeWaiter = nil
            if Task.isCancelled {
                // Abort the connection because the app cannot know how many bytes were accepted (first adopter review result 3).
                let now = ContinuousClock.now
                process(netstack?.stack.abort(id, at: now) ?? [], at: now)
                throw .cancelled
            }
        }
    }

    /// `TailnetConnection.finishWriting()`. A waiting `write` wakes with `closed`.
    func finishWritingConnection(_ id: TCPStack.ConnectionID) throws(ConnectionError) {
        guard !(try usableRecord(id).hasFinishedWriting) else { return }
        netstack?.connections[id]?.hasFinishedWriting = true
        let now = ContinuousClock.now
        process(netstack?.stack.finishWriting(id, at: now) ?? [], at: now)
        wakeWriter(id)
    }

    /// `TailnetConnection.close()`. Removes the record and wakes waiting calls with `closed`. The stack completes the close.
    func closeConnection(_ id: TCPStack.ConnectionID) {
        guard let record = netstack?.connections.removeValue(forKey: id) else { return }
        record.finishWaiters()
        let now = ContinuousClock.now
        process(netstack?.stack.close(id, at: now) ?? [], at: now)
    }

    /// `TailnetConnection.abort()` and released connections (`deinit`). Aborts with RST.
    func abortConnection(_ id: TCPStack.ConnectionID) {
        guard let record = netstack?.connections.removeValue(forKey: id) else { return }
        record.finishWaiters()
        let now = ContinuousClock.now
        process(netstack?.stack.abort(id, at: now) ?? [], at: now)
    }

    // MARK: Helpers

    /// Whether the device is `.inProcess`. `SwiftailPairing` checks if the node supports `listen` and `connect` when
    /// creating a `PairingHost`.
    package nonisolated var hasInProcessDevice: Bool {
        if case .inProcess = device { return true }
        return false
    }

    private func checkInProcessDevice(port: UInt16) throws(ConnectionError) {
        guard case .inProcess = device else { throw .invalidConfiguration("listen and connect require an .inProcess device") }
        guard port != 0 else { throw .invalidConfiguration("Port must be nonzero") }
    }

    /// The record for connection `id` if the app can still use it. Throws `notRunning` after `run()` ends, `closed`
    /// after the app closes it, or the error for the peer-related reason if it ended due to the peer (behavior A7).
    /// Returns the record for a `finished` connection so remaining data can be read.
    private func usableRecord(_ id: TCPStack.ConnectionID) throws(ConnectionError) -> ConnectionRecord {
        guard netstack != nil else { throw .notRunning }
        guard let record = netstack?.connections[id] else { throw .closed }
        if let reason = record.closeReason, let error = ConnectionError(closedBy: reason) { throw error }
        return record
    }

    /// Creates a handle for an established connection. Also creates a record for an accepted connection.
    private func adoptConnection(_ id: TCPStack.ConnectionID) -> TailnetConnection? {
        guard let connection = netstack?.stack.connection(id) else { return nil }
        if netstack?.connections[id] == nil {
            netstack?.connections[id] = ConnectionRecord(isEstablished: true)
        }
        return TailnetConnection(
            node: self, id: id, localEndpoint: connection.localEndpoint, remoteEndpoint: connection.remoteEndpoint)
    }
}
