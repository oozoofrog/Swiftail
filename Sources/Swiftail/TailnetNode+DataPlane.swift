import Foundation
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock

/// Drives the data plane by passing outputs between the engine and `Magicsock` and forwarding them to I/O. Also handles
/// timers. `TailnetNode+Netstack.swift` handles communication with the TCP stack for the `.inProcess` device.
///
/// ```
/// Device ─► engine.send ─┬ .datagram(to: peer) ─► magicsock.send ─┬ .udp ─► socket
///                        │                                        └ .derp ─► connection for that region
///                        └ .ipPacket(local reply or looped-back packet) ─► device
/// Socket ──► magicsock.receiveUDP ┐
/// DERP ───► magicsock.receiveDERP ┴ .wireGuard(from: path) ─► engine.receive ─ .ipPacket ─► device
///                                                                            ├ .datagram(handshake reply, etc.) ─► magicsock.send …
///                                                                            ├ .cookieReply ─► incoming path (UDP address, DERP sender)
///                                                                            └ .discoKeyAdvertised ─► magicsock.receiveDiscoKeyAdvertisement
/// ```
///
/// Each event starts with `process` and runs the exchange between the two state machines to completion without `await`.
/// I/O only enqueues work in nonblocking channels (UDP send group, region connection channel, event stream). Processes
/// output lists in the order received (the `Magicsock` calling rules). All calls within one event use the same time
/// `now`.
///
/// Processing can nest, with one `process` calling another `process`. Finish accumulated work only when the outermost pass ends
/// (`endProcessing(at:)`): drain the stack queue and delayed ACKs, pass accumulated UDP datagrams to the socket, and
/// reset the timer. An entry point that handles several events together (UDP group or timer) opens one pass for the
/// whole set.
///
/// Contract `docs/contracts/SwiftailEngine.md`, “Changes in M4” N5, N6, and N8, and `docs/contracts/SwiftailTunnel.md` behaviors L and B.
extension TailnetNode {
    // MARK: Connecting the State Machines

    /// Processes engine output. Call after every call that mutates the engine.
    ///
    /// - Parameter source: For output of `engine.receive`, the path the datagram arrived on. Sends `.cookieReply` back along that path.
    func process(_ outputs: [TailnetEngine.Output], repliesTo source: Magicsock.Source? = nil, at now: ContinuousClock.Instant) {
        beginProcessing()
        defer { endProcessing(at: now) }
        for output in outputs {
            switch output {
            case let .datagram(bytes, to: peer):
                process(magicsock?.send(bytes, to: peer, at: now) ?? [], at: now)
            case let .ipPacket(bytes):
                // The engine emits local replies, packets looped back to local addresses, and packets from peers as
                // packets to write to the device.
                deliverToDevice(bytes)
            case let .cookieReply(bytes):
                // The peer is not known yet, so send back along the incoming path without path selection (`magicsock.send`).
                if let source {
                    process([source.reply(bytes)], at: now)
                }
            case let .discoKeyAdvertised(key, from: peer):
                // The key is public but omitted from logs (magicsock contract behavior T6).
                Self.log.debug("Received TSMP disco key advertisement")
                process(magicsock?.receiveDiscoKeyAdvertisement(key, from: peer, at: now) ?? [], at: now)
            case .dropped:
                break
            }
        }
    }

    /// Processes `Magicsock` output. Call after every call that mutates `Magicsock`.
    func process(_ outputs: [Magicsock.Output], at now: ContinuousClock.Instant) {
        beginProcessing()
        defer { endProcessing(at: now) }
        for output in outputs {
            switch output {
            case let .udp(bytes, to: destination):
                sendUDP(bytes, to: destination)
            case let .derp(bytes, to: peer, region: region):
                sendDERP(bytes, to: peer, region: region)
            case let .wireGuard(bytes, from: source):
                let received = engine?.receive(bytes, from: source.engineSource, at: now) ?? []
                if received.contains(where: \.provesSession) {
                    announce(stateMachine.connected())
                }
                process(received, repliesTo: source, at: now)
            case let .endpointsChanged(endpoints):
                endpointsChanged(endpoints)
            case let .homeRegionChanged(region):
                homeRegionChanged(to: region)
            case let .pathChanged(peer, path):
                let line = pathEventTally.line(for: peer, path: path, downgrade: magicsock?.downgrade(of: peer), at: now)
                Self.log.info("\(line, privacy: .public)")
                if let name = peerDirectory.name(of: peer) {
                    eventQueue.push(.peerPathChanged(fqdn: name, path: path))
                }
            case let .dropped(reason):
                pathEventTally.count(reason)
            }
        }
    }

    // MARK: Starting and Ending Processing

    /// Opens a processing pass. Pair with an equal number of `endProcessing(at:)` calls.
    func beginProcessing() {
        processingDepth += 1
    }

    /// Ends a processing pass. If it is the outermost pass, finishes accumulated work.
    ///
    /// 1. Stack. Pass in queued packets and call `advance(to:)` at the same time (`settleNetstack(at:)`). Handle its output in a nested pass.
    /// 2. Pass the accumulated UDP datagrams to the socket's send queue together.
    /// 3. Reset the timer. Calculate the deadline once after updating all state machines.
    func endProcessing(at now: ContinuousClock.Instant) {
        guard processingDepth == 1 else {
            processingDepth -= 1
            return
        }
        settleNetstack(at: now)
        processingDepth = 0
        flushUDP()
        rearmTimer()
    }

    // MARK: UDP

    /// Adds one datagram to this processing pass's UDP send group. It goes to the socket when the outermost pass ends (`flushUDP()`).
    private func sendUDP(_ bytes: [UInt8], to destination: IPEndpoint) {
        guard !blockedUDPPorts.contains(destination.port) else { return }
        outgoingUDP.append((bytes, destination))
    }

    /// Passes the accumulated datagrams to the current socket's send queue together. The socket's serial queue calls
    /// `sendto` outside this actor (tunnel contract behavior M, “UDP Send Queue”). Drops datagrams if there is no
    /// socket (during rebinding) or a send fails. They also go over DERP or are retransmitted by WireGuard or disco.
    /// Processing does not wait, so the socket cannot change while handing off the group.
    // shortcut: Does not rebind after a send error (`EHOSTUNREACH`, `EPERM`, and so on) (tunnel contract behavior N 6).
    // Revisit if a socket dies without `setDefaultInterface` in a real-device network switch test.
    private func flushUDP() {
        guard !outgoingUDP.isEmpty else { return }
        socket?.enqueue(outgoingUDP)
        outgoingUDP.removeAll(keepingCapacity: true)
    }

    // MARK: Timer

    /// The earliest next deadline of the engine, `Magicsock`, and stack (netstack contract behavior N6). Called every
    /// processing pass, so it avoids allocating an array.
    private var nextDeadline: ContinuousClock.Instant? {
        var earliest = engine?.nextDeadline
        if let deadline = magicsock?.nextDeadline, earliest.map({ deadline < $0 }) ?? true {
            earliest = deadline
        }
        if let deadline = netstack?.stack.nextDeadline, earliest.map({ deadline < $0 }) ?? true {
            earliest = deadline
        }
        return earliest
    }

    /// Wakes at the next deadline and calls `advance` on the engine, `Magicsock`, and stack. Recomputes when the
    /// deadline moves earlier. Runs until canceled.
    ///
    /// Creates a fresh stream for change notifications each time and attaches the channel to the actor. Canceling the
    /// loser of the race would end that stream. There is no `await` between installing the channel and reading the
    /// deadline, so changes in between cannot be missed.
    func runTimer() async {
        while !Task.isCancelled {
            let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            timerChanged = continuation
            let deadline = nextDeadline
            armedDeadline = deadline
            await withTaskGroup(of: Void.self) { group in
                if let deadline {
                    group.addTask { try? await Task.sleep(until: deadline, clock: .continuous) }
                }
                group.addTask {
                    for await _ in changes { return }
                }
                await group.next()
                group.cancelAll()
            }
            // An early wakeup is fine. Advance before the deadline does nothing.
            let now = ContinuousClock.now
            beginProcessing()
            // If key expiration causes the engine to change its peers, owners may change too. Reread the owner table at the same time.
            let recomputesPeers = engine?.recomputesPeers(at: now) ?? false
            process(engine?.advance(to: now) ?? [], at: now)
            if recomputesPeers, let lastNetmap {
                updateAddressOwners(for: lastNetmap)
            }
            process(magicsock?.advance(to: now) ?? [], at: now)
            process(netstack?.stack.advance(to: now) ?? [], at: now)
            endProcessing(at: now)
        }
        timerChanged = nil
    }

    /// Wakes the timer if the next deadline is earlier than its scheduled wakeup. For a later deadline, the timer recomputes when it wakes.
    func rearmTimer() {
        guard let next = nextDeadline else { return }
        if let armedDeadline, armedDeadline <= next { return }
        timerChanged?.yield()
    }
}

extension TailnetEngine.Output {
    /// Whether the output proves that a WireGuard session with a peer was established. Ask only of `engine.receive` outputs.
    ///
    /// Returns true for outputs produced only by a decrypted transport packet (a packet to deliver, a drop by
    /// filtering, parsing, or TSMP, or a TSMP disco key advertisement). The engine does not report when the handshake
    /// completed, so this measures the state machine condition that a session has been established with a peer
    /// (behavior B 5).
    // shortcut: Go observes handshake completion (`LastHandshake`). This observes the first transport packet received
    // on the session, excluding keepalive, so it may be slightly later. If the home DERP connection establishes first,
    // the node enters `.running` earlier, so there is usually no difference. Revisit if `.running` is noticeably
    // delayed on a tailnet that uses only direct paths without DERP (add a session event to the engine).
    var provesSession: Bool {
        switch self {
        case .ipPacket, .discoKeyAdvertised: true
        case .datagram, .cookieReply: false
        case let .dropped(reason):
            switch reason {
            case .inbound, .malformedPacket, .unsupportedPacket, .consumedControlPacket: true
            case .serviceIPPacket, .noPeerForDestination, .wireGuard: false
            }
        }
    }
}

extension Magicsock.Source {
    /// The origin to pass to the WireGuard device. The cookie is bound to `address` and rate limiting to `host`.
    ///
    /// UDP follows Go's standard bind. `address` is the binary representation of `netip.AddrPort` (address ‖ port LE),
    /// and `host` is the address. DERP has the same semantics as Tailscale magicsock, with one value per peer and no
    /// region. Go binds the cookie to a synthetic per-peer address and rate-limits by the peer's tailnet address
    /// (`DstToBytes` and `DstIP` in `wgengine/magicsock/endpoint.go`). Here both are the 32-byte node public key. They
    /// cannot collide with UDP values (4, 6, 16, or 18 bytes) because their lengths differ.
    var engineSource: TailnetEngine.Source {
        switch self {
        case let .udp(endpoint):
            let address = endpoint.address.bytes
            return TailnetEngine.Source(address: address + [UInt8(endpoint.port & 0xFF), UInt8(endpoint.port >> 8)], host: address)
        case let .derp(peer, _):
            return TailnetEngine.Source(address: peer.rawValue, host: peer.rawValue)
        }
    }

    /// A `Magicsock` output that sends `bytes` back along this path. UDP goes to the address, and DERP goes to the peer in the same region.
    func reply(_ bytes: [UInt8]) -> Magicsock.Output {
        switch self {
        case let .udp(endpoint): .udp(bytes, to: endpoint)
        case let .derp(peer, region): .derp(bytes, to: peer, region: region)
        }
    }
}

/// Builds a “Peer N path” log line. Diagnoses why a path changed on a real device and which peer changed.
///
/// The line includes the peer number, path, reason if it degraded, time since that peer's previous path event, and
/// counts by kind of disco dropped since the previous path event for any peer. Example:
/// `Peer 2 path: relayed(7) (trust expired, 96.5s since previous event, dropped disco: unknown key 0, unopened 0, routing rule 0)`.
/// - Assign peer numbers in order of first path events, starting at 1. When a peer leaves, discard its record and never
///   reuse the number. Logs appear in the public repository, so omit keys, addresses, names, and stable IDs.
/// - Drops accumulating as unknown key mean the peer's new disco key is not known yet (a late netmap). Drops
///   accumulating as unopened mean the peer sealed messages with this node's old key. If neither occurs, disco was
///   exchanged but UDP did not reach its destination.
///
/// “Fixes” in “Investigation of Direct Path Delay” and “Findings” in “`relayed` about 100 seconds after `direct` was
/// established” in `docs/contracts/SwiftailMagicsock.md`.
struct PathEventTally: Sendable {
    /// The number of the peer that emitted the path event and the time of its previous event.
    private var peers: [NodePublicKey: (number: Int, lastEvent: ContinuousClock.Instant)] = [:]
    private var nextPeerNumber = 1
    private var unknownKey = 0
    private var unopened = 0
    private var misrouted = 0

    /// Discards a departed peer's record after processing its final path event, so records do not accumulate over a long run.
    mutating func retainPeers(_ keys: Set<NodePublicKey>) {
        peers = peers.filter { keys.contains($0.key) }
    }

    /// Counts a disco drop reason. Other reasons are not counted.
    mutating func count(_ drop: Magicsock.Drop) {
        switch drop {
        case .unknownDiscoKey: unknownKey += 1
        case .malformedDisco: unopened += 1
        case .misroutedDisco: misrouted += 1
        default: break
        }
    }

    /// The log line for one path event. Remembers the peer's event time and resets dropped disco counts to 0.
    mutating func line(
        for peer: NodePublicKey,
        path: PeerPath?,
        downgrade: PathDowngrade?,
        at now: ContinuousClock.Instant
    ) -> String {
        var details: [String] = []
        if let downgrade {
            details.append(downgrade.logName)
        }
        let number: Int
        if let previous = peers[peer] {
            number = previous.number
            let (seconds, attoseconds) = max(.zero, previous.lastEvent.duration(to: now)).components
            let tenths = seconds * 10 + attoseconds / 100_000_000_000_000_000
            details.append("\(tenths / 10).\(tenths % 10)s since previous event")
        } else {
            number = nextPeerNumber
            nextPeerNumber += 1
            details.append("first event")
        }
        details.append("dropped disco: unknown key \(unknownKey), unopened \(unopened), routing rule \(misrouted)")
        peers[peer] = (number, now)
        (unknownKey, unopened, misrouted) = (0, 0, 0)
        return "Peer \(number) path: \(path.logName) (\(details.joined(separator: ", ")))"
    }
}

extension PathDowngrade {
    /// A word for logging.
    var logName: String {
        switch self {
        case .trustExpired: "trust expired"
        case .candidateRemoved: "candidate removed"
        case .rebind: "rebind"
        case .discoKeyChanged: "disco key changed"
        case .idle: "idle"
        case .peerRemoved: "peer removed"
        }
    }
}

extension Optional<PeerPath> {
    /// The path kind to log. Omits addresses.
    var logName: String {
        switch self {
        case .direct: "direct"
        case let .relayed(region): "relayed(\(region))"
        case nil: "none"
        }
    }
}
