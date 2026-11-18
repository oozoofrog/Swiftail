import Network
import SwiftailBase
import SwiftailIO
import SwiftailMagicsock

/// Handles default interface changes and the UDP socket lifecycle (`docs/contracts/SwiftailTunnel.md` behavior N).
///
/// Swiftail has no `AF_ROUTE` watcher, so the app's `setDefaultInterface` call is the only source of network change
/// notifications (decision D6). Rereads local addresses for each notification and decides what to do with
/// `DefaultLink.change(from:tunnelName:)`.
///
/// Rebind order, following the Go engine (dns-state-node notes §4.6.3 item 1).
/// 1. Set the new interface as current. All sockets and connections opened afterward bind to it.
/// 2. DERP. Close all open region connections and reopen the home region on the new interface.
/// 3. UDP. Close the socket and bind again to the same port. Fall back to port 0 and then to a socket without an
///    interface binding. Only inability to create a socket ends `run()` with `udpUnavailable`. Then call
///    `Magicsock.rebind`, process outputs in order, and call `advance` at `nextDeadline` (handled by the timer).
/// 4. Control. `ControlClient.setNetworkInterface` closes the current connection and immediately reconnects on the new interface.
/// 5. Settings. The netmap did not change, so do not publish settings again (behavior E 2).
///
/// The old socket's `close(2)` runs later on its dispatch queue, so binding the same port immediately would give
/// `EADDRINUSE`. For step 3, the `rebindUDP()` child retries after short waits. Without a socket in the meantime,
/// outgoing UDP is dropped. It also goes over DERP or WireGuard or disco retransmits it.
///
/// - `shortcut:` Close all DERP connections. Reopen the home connection immediately and other connections as
///   needed. Go keeps connections whose local address belongs to the default interface and verifies them with a
///   3-second Ping. The only extra cost is reconnecting non-home connections. Revisit if
///   reconnection latency becomes a problem in real-device transitions.
/// - `shortcut:` Does not handle network loss (no satisfied path). The app reports only satisfied paths. While
///   disconnected, connections rely on their own retries and backoff. Revisit if retries without a network become a
///   battery or memory problem.
/// - `shortcut:` No automatic rebind after a UDP send error (`EPERM` or broken pipe). Revisit if the socket dies during
///   a real-device transition test without `setDefaultInterface`.
extension TailnetNode {
    /// The number and interval of attempts to rebind the same port. Waits for the old socket to close (0.5 seconds total).
    static let rebindAttempts = 25
    static let rebindRetryInterval = Duration.milliseconds(20)

    /// Reports that the device's default path uses this interface (the app's `NWPathMonitor`). Binds node control,
    /// DERP, and UDP sockets to it and rebinds if it changes.
    ///
    /// May be called for every satisfied path without filtering. If the interface and addresses are unchanged, reruns
    /// only STUN. This call is the node's only way to learn of an address-only change on the same Wi-Fi. The node
    /// ignores its own utun. Outside `run()`, the node only remembers the latest interface. A subsequent start of
    /// `run()` opens sockets and connections on the remembered interface.
    public func setDefaultInterface(_ interface: NWInterface) {
        // If addresses cannot be read, decide without them. Advertise only endpoints found by STUN, with no local endpoints.
        let link = DefaultLink(interface, addresses: (try? LocalInterfaceAddresses.current()) ?? ([], []))
        let change = link.change(from: defaultLink, tunnelName: tunnelName)
        guard change != .ignore else { return }
        guard isRunning else {
            defaultInterface = interface
            return
        }
        switch change {
        case .ignore:
            return
        case .restartSTUN:
            Self.log.debug("Same default interface (\(interface.name, privacy: .public)): restarting STUN")
            let now = ContinuousClock.now
            process(magicsock?.restartSTUN(at: now) ?? [], at: now)
        case .rebind:
            Self.log.info("Rebinding default interface: \(interface.name, privacy: .public)")
            defaultInterface = interface
            defaultLink = link
            interfaceAddresses = (link.addresses, link.loopbackAddresses)
            closeAllDERPLinks()
            if homeRegion != 0 {
                openDERPLink(to: homeRegion)
            }
            rebindContinuation.yield()
        }
    }

    // MARK: UDP Socket

    /// Opens a UDP socket bound to the current interface.
    func openSocket(port: UInt16) throws(NodeError) -> DatagramSocket {
        do {
            return try DatagramSocket(port: port, interfaceIndex: defaultInterface.flatMap { UInt32(exactly: $0.index) })
        } catch {
            throw .udpUnavailable(error.message)
        }
    }

    /// Opens a socket on an OS-selected port. Falls back to an unbound socket if it cannot bind to the current interface.
    ///
    /// If the reported interface disappeared in the meantime (unstable Wi-Fi or airplane mode), binding fails.
    /// Restarting could resolve it, so do not end `run()`. Keep going with an unbound socket and clear the last link so
    /// the next `setDefaultInterface` notification always rebinds. Throws only if it cannot create a socket at all.
    func openSocketOnAnyPort() throws(NodeError) -> DatagramSocket {
        if let bound = try? openSocket(port: 0) { return bound }
        do {
            let unbound = try DatagramSocket(port: 0)
            if defaultInterface != nil {
                Self.log.error("Could not bind the UDP socket to the default interface. Opening it unbound.")
            }
            defaultLink = nil
            return unbound
        } catch {
            throw .udpUnavailable(error.message)
        }
    }

    /// Sets the new socket as current and starts reading.
    func adopt(_ socket: DatagramSocket) {
        self.socket = socket
        openedSocketContinuation.yield(socket)
    }

    /// Feeds each open socket's datagrams to `Magicsock`. Work for a socket ends when the socket closes. Runs until canceled.
    func receiveUDP() async {
        await withDiscardingTaskGroup { group in
            for await socket in openedSockets {
                group.addTask { await self.receiveUDP(from: socket) }
            }
        }
    }

    /// When a datagram arrives, process it and everything queued on the socket in one group. The group is one
    /// processing pass, so the stack queue, `advance`, and timer reset run once at its end (netstack contract behavior
    /// N4). The group is bounded by the newly received datagram plus the socket receive queue limit (256), so it does
    /// not hold the actor for long.
    private func receiveUDP(from socket: DatagramSocket) async {
        for await datagram in socket.datagrams {
            let now = ContinuousClock.now
            beginProcessing()
            receiveUDP(datagram, at: now)
            for queued in socket.takeQueuedDatagrams() {
                receiveUDP(queued, at: now)
            }
            endProcessing(at: now)
        }
        // If the stream ended without close or cancellation, an error stopped the socket's reads. Reopen it to avoid
        // leaving a socket that sends but cannot receive.
        if self.socket === socket, !Task.isCancelled {
            Self.log.error("UDP receive stopped: reopening the socket")
            rebindContinuation.yield()
        }
    }

    private func receiveUDP(_ datagram: DatagramSocket.Datagram, at now: ContinuousClock.Instant) {
        guard !blockedUDPPorts.contains(datagram.source.port) else { return }
        process(magicsock?.receiveUDP(datagram.bytes, from: datagram.source, at: now) ?? [], at: now)
    }

    /// Reopens the socket on the current interface for each rebind request (step 3). Overlapping requests coalesce into
    /// one. If the interface changes while waiting, the next request reopens on that interface. Runs until canceled.
    func rebindUDP() async {
        for await _ in rebindRequests {
            let port = closeSocket()
            var reopened: DatagramSocket?
            for attempt in 0..<Self.rebindAttempts where reopened == nil {
                if attempt > 0 {
                    do {
                        try await Task.sleep(for: Self.rebindRetryInterval)
                    } catch {
                        return
                    }
                }
                reopened = try? openSocket(port: port)
            }
            do throws(NodeError) {
                if reopened == nil {
                    reopened = try openSocketOnAnyPort()
                }
            } catch {
                Self.log.error("Rebind: could not open UDP socket (\(error.kind, privacy: .public))")
                failureContinuation.yield(error)
                return
            }
            if let reopened {
                adoptRebound(reopened)
            }
        }
    }

    /// Closes the current socket and returns its port. Returns 0 if there is no socket (the OS chooses).
    private func closeSocket() -> UInt16 {
        defer {
            socket?.close()
            socket = nil
        }
        return socket?.localPort ?? 0
    }

    /// Uses the reopened socket and notifies `Magicsock`, which drops direct paths and starts STUN immediately. Then
    /// reconnects control (step 4).
    private func adoptRebound(_ socket: DatagramSocket) {
        adopt(socket)
        Self.log.info("Rebind: UDP port \(socket.localPort, privacy: .public)")
        let now = ContinuousClock.now
        process(
            magicsock?.rebind(
                localPort: socket.localPort,
                localAddresses: interfaceAddresses.regular,
                loopbackAddresses: interfaceAddresses.loopback,
                at: now
            ) ?? [],
            at: now
        )
        if let defaultInterface {
            interfaceContinuation.yield(defaultInterface)
        }
    }
}
