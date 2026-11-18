import CryptoKit
import Foundation
import Network
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailEngine
import SwiftailIO
import SwiftailMagicsock
import SwiftailNetstack
import os

/// A node on a tailnet.
///
/// The node exchanges IP packets through a tunnel device (utun or in-memory), publishes tunnel settings for the
/// app to apply to the OS, and answers MagicDNS queries sent to the service IP. It finds and uses direct UDP paths
/// to peers and falls back to DERP relay if it cannot find a path or the path drops. With an `.inProcess` device,
/// it listens and connects using the in-process TCP stack without OS sockets (`listen(port:)`, `connect(to:port:)`).
///
/// This actor connects the protocol components to devices, sockets, and clocks at the I/O edge. Protocol decisions
/// come from `ControlClient` (registration and maps), `DERPClient` (relay), and the state machines without I/O.
/// These are `TailnetEngine` (WireGuard, filtering, local replies), `Magicsock` (path discovery, STUN, home region),
/// `TCPStack` (in-process TCP), `NodeStateMachine` (node state), `NetworkSettingsPublisher` (settings publication),
/// and `DefaultLink` (network change decisions).
///
/// The state machines are value types stored in this actor's properties and mutated only in place. For one event
/// (a received UDP datagram or DERP packet, an IP packet read from the device, or a timer), the actor passes outputs
/// between components to completion without `await` and only enqueues I/O. This prevents actor reentrancy between
/// state updates. Only this actor reads the current time (`ContinuousClock.now`, `Date()`).
///
/// Concurrency is structured. All work runs as children of the TaskGroup in `run()`. Canceling the Task that called `run()` stops all of it.
///
/// ```
/// run()
///  └ TaskGroup: Node lifetime. When one child ends, cancel the rest and return from run()
///     ├ control.run()             Register, stream maps, and reconnect on disconnect. Throw on terminal failure
///     ├ follow(control)           Control events → engine and Magicsock, state machine, settings
///     ├ forwardLoginRequests      startInteractiveLogin() → control
///     ├ forwardInterfaces         Interface selected by setDefaultInterface() → control (reconnect)
///     ├ uploadLocalStatus         Endpoints and home region changed by Magicsock → control
///     ├ receiveUDP()              Datagrams from each open UDP socket → Magicsock. Work for a socket ends when it closes
///     ├ rebindUDP()               Open a new socket on each rebind request (same port, or 0 on failure) → Magicsock.rebind
///     ├ maintainDERP()            One group below per open region connection. Closing its mailbox ends the group
///     │   └ TaskGroup: Lifetime of one DERP region connection
///     │      ├ client.run()
///     │      ├ client.events → Magicsock, state machine
///     │      └ Datagrams for this region → client.send. Mailbox closure ends this and winds down the group
///     ├ runTimer()                Wake at the earliest engine, Magicsock, or stack deadline and advance all three
///     ├ releaseHandles()          Released TailnetConnection or TailnetListener (deinit) → abort with RST or stop listening
///     ├ awaitFailure()            Could not open UDP on rebind, or in-memory device failure (tests) → end with that failure
///     └ readTunnel()              (With utun) Packets read from the device → engine. Device closure ends with tunnelDeviceClosed
/// ```
///
/// ```swift
/// let node = try TailnetNode(
///     configuration: .init(stateDirectory: directory, hostname: "rd-phone-1a2b3c4d"),
///     device: .utun(fileDescriptor: descriptor, mtu: 1280))
/// let runTask = Task { try await node.run() }
/// for await settings in node.networkSettings { … }   // The app applies these settings to the OS
/// runTask.cancel(); _ = await runTask.result          // Stop
/// ```
///
/// Contract `docs/contracts/SwiftailTunnel.md`, `docs/contracts/SwiftailEngine.md` “Node API (`Swiftail`)” and “Changes
/// in M4,” and `docs/contracts/SwiftailNetstack.md` behaviors N and A.
public actor TailnetNode {
    /// The unread event limit. Drops the oldest events first on overflow.
    static let eventBufferLimit = 64
    /// The unread inbound packet limit for an in-memory device. Drops the oldest first on overflow, as IP allows.
    static let inboundPacketLimit = 256
    /// The count and total byte limits for data still waiting to go over DERP, per region connection. Drops the oldest
    /// datagrams first on overflow. WireGuard retransmits them (contract behavior M).
    static let outboundDatagramLimit = 256
    static let outboundByteLimit = 1 << 20

    /// Logs only summaries without secrets: state transitions, control and DERP connects and disconnects, path changes,
    /// rebinding, and settings computation. Omits keys, auth keys, login URLs, full addresses, and DNS names (first
    /// adopter review result 5).
    static let log = Logger(subsystem: "Swiftail", category: "node")

    let configuration: NodeConfiguration
    let device: TunnelDevice
    /// The utun device's interface name. `init` reads it. Used to filter out the node's own utun from default interface
    /// notifications (behavior N 1).
    let tunnelName: String?
    let identityStore: NodeIdentityStore
    /// Unread events. `events` pulls from this queue (`NodeEventQueue`).
    nonisolated let eventQueue = NodeEventQueue()
    let inboundContinuation: AsyncStream<[UInt8]>.Continuation
    let settingsContinuation: AsyncStream<TunnelNetworkSettings>.Continuation
    private let eventStream: AsyncStream<NodeEvent>
    private let inboundStream: AsyncStream<[UInt8]>
    private let settingsStream: AsyncStream<TunnelNetworkSettings>
    /// The subscription for facts published to the certificate manager (`certificateFacts`).
    nonisolated let certificateFactsPublisher = CertificateFactsPublisher(CertificateFacts(state: .starting, netmap: nil))
    /// `startInteractiveLogin()` can be called outside `run()`, so buffer requests in the stream and have a child pass them to control.
    private let loginRequests: AsyncStream<Void>
    private let loginContinuation: AsyncStream<Void>.Continuation
    /// The interface to bind the control connection to. Only the latest one matters.
    private let interfaceRequests: AsyncStream<NWInterface>
    let interfaceContinuation: AsyncStream<NWInterface>.Continuation
    /// The status to upload to the control server. Only the latest one matters.
    private let statusUploads: AsyncStream<ControlClient.LocalStatus>
    let statusUploadContinuation: AsyncStream<ControlClient.LocalStatus>.Continuation
    /// Newly opened DERP region connections. `maintainDERP()` takes and runs them. Created here so connections opened
    /// before that child starts are retained.
    let openedDERPLinks: AsyncStream<DERPLink>
    let openedDERPLinkContinuation: AsyncStream<DERPLink>.Continuation
    /// Newly opened UDP sockets. `receiveUDP()` takes and reads them.
    let openedSockets: AsyncStream<DatagramSocket>
    let openedSocketContinuation: AsyncStream<DatagramSocket>.Continuation
    /// Requests to reopen the UDP socket on a new interface. Overlapping requests coalesce into one.
    let rebindRequests: AsyncStream<Void>
    let rebindContinuation: AsyncStream<Void>.Continuation
    /// Released connection and listener handles. `deinit` cannot wait, so enqueue them here. A child in `run()` takes
    /// and closes them (contract behavior N9). The stream closes at the end of `run()`, and later items are dropped.
    let handleReleaseStream: AsyncStream<HandleRelease>
    nonisolated let handleReleases: AsyncStream<HandleRelease>.Continuation
    /// A failure that ends `run()`. Only the first is used.
    private let failures: AsyncStream<NodeError>
    let failureContinuation: AsyncStream<NodeError>.Continuation
    private(set) var hasRun = false
    /// `run()` is in progress, from the end of startup checks until completion.
    var isRunning = false

    /// This node's private disco key. Generated anew per node and never stored (disco-magicsock notes §4.10 item 4).
    /// Omitted from events, errors, and `dump` (`customMirror`).
    let discoKey = Curve25519.KeyAgreement.PrivateKey()

    // MARK: Data Plane State

    /// The UDP socket open during `run()`, shared by WireGuard, disco, and STUN. Briefly nil while rebinding.
    var socket: DatagramSocket?
    /// The last interface addresses read. Become `Magicsock`'s local endpoints.
    var interfaceAddresses: (regular: [SwiftailBase.IPAddress], loopback: [SwiftailBase.IPAddress]) = ([], [])
    /// The duplicate utun device used during `run()`. Nil for an in-memory device.
    var tunnel: UTUNDevice?
    /// Created after registration. Recreated together with `magicsock` if the node key changes.
    var engine: TailnetEngine?
    /// Selects paths to peers. Created and replaced with `engine`.
    var magicsock: Magicsock?
    /// The private node key used by the engine and DERP client. Read from the identity file.
    var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    /// The last netmap received. Reapplied when recreating the engine and used to find DERP region servers and create `status`.
    var lastNetmap: Netmap?
    /// Maps data plane addresses to their owner nodes. Replaces it with the engine's table whenever the engine
    /// recomputes peers (netmap application or key expiration). `whoIs` reads it. The stack's ownership check
    /// (`Netstack.addressOwners`) also comes from it (`updateAddressOwners(for:)`).
    var addressOwners: [SwiftailBase.IPAddress: Node] = [:]
    /// Data plane peer keys and names.
    var peerDirectory = PeerDirectory()
    /// The home DERP region selected by `Magicsock`. 0 means none yet.
    var homeRegion: Int64 = 0
    /// Open DERP region connections, keyed by region ID.
    var derpLinks: [Int64: DERPLink] = [:]
    /// Regions with an established server connection.
    var connectedDERPRegions: Set<Int64> = []
    /// The control connection dropped and no netmap has arrived since. Used only to log reconnection once.
    var isControlDisconnected = false
    /// This node's status to upload to the control server (disco key, endpoints, home region).
    var localStatus = ControlClient.LocalStatus()
    /// For tests. Drops UDP sent to this remote port and UDP received from this port at the socket edge.
    var blockedUDPPorts: Set<UInt16> = []
    /// UDP datagrams to send during this processing pass. Passed to the socket's send queue when the outermost pass ends.
    var outgoingUDP: [DatagramSocket.OutgoingDatagram] = []
    /// Diagnostics attached to path event logs (peer number, time since the same peer's previous event, and dropped disco counts).
    var pathEventTally = PathEventTally()

    // MARK: Default Interface (Behavior N)

    /// The last default interface reported by the app. All new sockets and connections bind to it. Nil leaves them unbound.
    var defaultInterface: NWInterface?
    /// The interface currently bound to sockets and connections and the addresses read at the time. Present only during `run()`.
    var defaultLink: DefaultLink?

    // MARK: Published State

    var stateMachine = NodeStateMachine()
    /// The `status` at the last `statusChanged`. Starts with the initial snapshot (`.starting`, no netmap).
    var announcedStatus = NodeStatus(state: .starting, netmap: nil, networkSettings: nil)
    var settingsPublisher = NetworkSettingsPublisher()
    /// The control client used during `run()`. Used by `setDNS`.
    var control: ControlClient?

    // MARK: In-Process TCP (`.inProcess`)

    /// The stack and application-held connections. Present only during `run()` with an `.inProcess` device (contract M6 behavior N).
    var netstack: Netstack?
    /// Open listeners. Records listeners opened before `run()` without a stack and installs them on the stack when
    /// `run()` starts (behavior A1).
    var listenerRecords: [UInt64: ListenerRecord] = [:]
    var nextListenerToken: UInt64 = 1
    /// For tests. The packet loss probability and random number generator between the stack and engine (contract
    /// behavior N11). Nil disables drops.
    var inProcessLoss: PacketLoss?

    // MARK: Processing Depth

    /// The number of open processing passes (`beginProcessing()`). Finishes accumulated work when it returns to 0 (`endProcessing(at:)`).
    var processingDepth = 0

    // MARK: Timer Wakeup Channel

    /// The next deadline moved earlier than the timer's scheduled wakeup.
    var timerChanged: AsyncStream<Void>.Continuation?
    /// The scheduled wakeup time.
    var armedDeadline: ContinuousClock.Instant?

    /// Validates configuration and the device. Creates no files, sockets, or Tasks. utun validation uses read-only system calls.
    ///
    /// - Throws: `NodeError.invalidConfiguration` if the state directory is not a file URL, the control server URL does
    ///   not use `http(s)://` or has no host, the hostname is empty, the MTU is outside 1280…1420, or the descriptor is
    ///   not a utun descriptor.
    public init(configuration: NodeConfiguration, device: TunnelDevice = .memory()) throws(NodeError) {
        try configuration.validate()
        tunnelName = try device.validate()
        self.configuration = configuration
        self.device = device
        identityStore = NodeIdentityStore(directory: configuration.stateDirectory)
        let queue = eventQueue
        eventStream = AsyncStream(unfolding: { await queue.next() })
        (inboundStream, inboundContinuation) = AsyncStream.makeStream(of: [UInt8].self, bufferingPolicy: .bufferingNewest(Self.inboundPacketLimit))
        (settingsStream, settingsContinuation) = AsyncStream.makeStream(of: TunnelNetworkSettings.self, bufferingPolicy: .bufferingNewest(1))
        (loginRequests, loginContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        (interfaceRequests, interfaceContinuation) = AsyncStream.makeStream(of: NWInterface.self, bufferingPolicy: .bufferingNewest(1))
        (statusUploads, statusUploadContinuation) = AsyncStream.makeStream(of: ControlClient.LocalStatus.self, bufferingPolicy: .bufferingNewest(1))
        (openedDERPLinks, openedDERPLinkContinuation) = AsyncStream.makeStream(of: DERPLink.self)
        (openedSockets, openedSocketContinuation) = AsyncStream.makeStream(of: DatagramSocket.self)
        (rebindRequests, rebindContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        (handleReleaseStream, handleReleases) = AsyncStream.makeStream(of: HandleRelease.self)
        (failures, failureContinuation) = AsyncStream.makeStream(of: NodeError.self, bufferingPolicy: .bufferingOldest(1))
    }

    /// A stream of changes to node state, peer paths, tailnet lock, and node status.
    ///
    /// Use one subscriber. The stream ends when `run()` ends.
    ///
    /// Keeps only the newest 64 unread events and drops older events first. Keeps only one unread `statusChanged` at
    /// the end, outside this limit (`NodeEvent.statusChanged`).
    ///
    /// Canceling the consumer Task ends the stream and prevents resubscription. Subscribe once from one place in the app.
    public nonisolated var events: AsyncStream<NodeEvent> { eventStream }

    /// Tunnel settings for the app to apply to the OS. Emits only changes and keeps only the newest unread settings
    /// (behavior E). One subscriber. The stream ends when `run()` ends.
    public nonisolated var networkSettings: AsyncStream<TunnelNetworkSettings> { settingsStream }

    /// IP packets to write to the in-memory device, including packets from peers that passed the filter, locally
    /// generated replies (such as MagicDNS), and packets sent to local addresses and looped back. Emits nothing for
    /// utun and `.inProcess` devices because packets go to utun or the stack. One subscriber. The stream ends when
    /// `run()` ends.
    ///
    /// If the consumer falls behind, keeps only the newest 256 and drops the oldest first.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { inboundStream }

    /// The node's current status. Changes produce `statusChanged` in `events`.
    public var status: NodeStatus {
        NodeStatus(state: stateMachine.state, netmap: lastNetmap, networkSettings: settingsPublisher.published)
    }

    /// Registers the node, receives netmaps, and maintains the data plane until canceled or a terminal error occurs.
    ///
    /// On disconnect, the node backs off and reconnects internally. Call `run()` once per node. A second call throws
    /// `invalidConfiguration` during or after the first run.
    ///
    /// - Throws: A terminal control failure (`control`, including state directory setup failures), an invalid utun
    ///   descriptor at startup (`invalidConfiguration`), an unavailable or closed tunnel device
    ///   (`tunnelDeviceClosed`), a directory claim held by another node in the same process (`stateDirectoryInUse`,
    ///   before opening files or sockets), or failure to open a UDP socket (`udpUnavailable`).
    ///
    /// Inside `Task { }`, write `do throws(NodeError) { try await node.run() } catch { … }` to get a `NodeError` as the
    /// `error` in `catch`. Omitting `throws(NodeError)` infers `any Error`.
    public func run() async throws(NodeError) {
        guard !hasRun else { throw .invalidConfiguration("Call run() only once per node") }
        hasRun = true
        defer {
            // If startup checks end the run, close listeners opened before `run()` here.
            stopNetstack()
            eventQueue.finish()
            inboundContinuation.finish()
            settingsContinuation.finish()
            certificateFactsPublisher.finish()
        }
        let claim = try StateDirectoryClaims.shared.claimCreating(configuration.stateDirectory)
        defer { StateDirectoryClaims.shared.release(claim) }

        if case let .utun(descriptor, mtu) = device {
            do {
                tunnel = try UTUNDevice(duplicating: descriptor, mtu: mtu)
            } catch {
                throw NodeError(openingTunnel: error)
            }
        }
        // If addresses cannot be read, proceed without local endpoints. Only endpoints found by STUN are advertised (contract N1).
        interfaceAddresses = (try? LocalInterfaceAddresses.current()) ?? ([], [])
        if let defaultInterface {
            defaultLink = DefaultLink(defaultInterface, addresses: interfaceAddresses)
        }
        let socket: DatagramSocket
        do {
            socket = try openSocketOnAnyPort()
        } catch {
            tunnel?.close()
            tunnel = nil
            throw error
        }
        adopt(socket)
        isRunning = true
        defer {
            isRunning = false
            // Release the active node key, WireGuard sessions, connections, and descriptors. `path(toPeerNamed:)`
            // returns nil and `send` drops input. Closes only the duplicate utun descriptor (behavior U2). The socket closes after
            // sending the RSTs `stopNetstack()` placed in the send queue.
            self.socket?.closeAfterSending()
            self.socket = nil
            tunnel?.close()
            tunnel = nil
            closeAllDERPLinks()
            openedDERPLinkContinuation.finish()
            openedSocketContinuation.finish()
            engine = nil
            magicsock = nil
            nodeKey = nil
            defaultLink = nil
        }
        startNetstack()
        // Runs before the cleanup above, emitting one RST per open connection while the socket and engine still exist (behavior N8).
        defer { stopNetstack() }

        let control = ControlClient(
            configuration: .init(
                serverURL: configuration.controlURL,
                hostname: configuration.hostname,
                authKey: configuration.authKey,
                ephemeral: configuration.ephemeral
            ),
            identityStore: identityStore
        )
        self.control = control
        defer { self.control = nil }
        // Advertise a nonzero DiscoKey so Go peers install this node as a peer (derp-stun notes §6 item 7).
        localStatus = .init(discoKey: DiscoPublicKey(discoKey.publicKey))
        await control.setLocalStatus(localStatus)
        if let defaultInterface {
            await control.setNetworkInterface(defaultInterface)
        }

        let failure = await withTaskGroup(of: NodeError?.self, returning: NodeError?.self) { group in
            group.addTask {
                do throws(ControlError) {
                    try await control.run()
                    return nil
                } catch {
                    return NodeError(error)
                }
            }
            group.addTask { await self.follow(control) }
            group.addTask { await self.forwardLoginRequests(to: control); return nil }
            group.addTask { await self.forwardInterfaces(to: control); return nil }
            group.addTask { await self.uploadLocalStatus(to: control); return nil }
            group.addTask { await self.receiveUDP(); return nil }
            group.addTask { await self.rebindUDP(); return nil }
            group.addTask { await self.maintainDERP(); return nil }
            group.addTask { await self.runTimer(); return nil }
            group.addTask { await self.releaseHandles(); return nil }
            group.addTask { await self.awaitFailure() }
            if let tunnel = self.tunnel {
                group.addTask { await self.readTunnel(tunnel) }
            }

            // Children run until canceled, so if any child ends, the node has ended. Cancel the rest and collect
            // failures. A control failure also ends the event stream, so either can return first. Check more than just
            // the first result.
            var failure: NodeError?
            for await result in group {
                group.cancelAll()
                failure = failure ?? result
            }
            return failure
        }
        if let failure {
            Self.log.error("Node terminated: \(failure.kind, privacy: .public)")
            throw failure
        }
        Self.log.info("Node stopped")
    }

    /// Submits an IP packet from the in-memory tunnel device.
    ///
    /// Uses the same processing as a utun read. Silently drops the packet before registration or if no peer or path
    /// is available. With a utun or `.inProcess` device, drops the packet.
    public func send(_ ipPacket: [UInt8]) {
        guard case .memory = device else { return }
        deliverFromDevice(ipPacket)
    }

    /// Returns the current path to the peer named `fqdn`.
    ///
    /// Returns nil if the peer is absent from the data plane or idle. The path is idle until the node sends to the
    /// peer and again once more than 45 seconds have passed since the last send.
    ///
    /// Compares names after removing one trailing dot and ignoring ASCII case. If two peers share a name, the lower
    /// node ID wins. A path has the same meaning as the direct address (`CurAddr`) in Go `tailscale status`
    /// (`PeerPath`).
    public func path(toPeerNamed fqdn: String) -> PeerPath? {
        guard let key = peerDirectory.key(named: fqdn) else { return nil }
        return magicsock?.path(to: key, at: .now)
    }

    /// The path to the peer with `stableID`. Has the same meaning as `path(toPeerNamed:)` and uses a different lookup key.
    ///
    /// A name can change, but `StableID` stays fixed. Use this for persistent peer references such as allowlists and
    /// pairing records. Nil if the netmap has no peer with that ID. An empty string matches no peer.
    public func path(toPeerWithStableID stableID: String) -> PeerPath? {
        guard !stableID.isEmpty, let key = lastNetmap?.peers.first(where: { $0.stableID == stableID })?.key else { return nil }
        return magicsock?.path(to: key, at: .now)
    }

    /// Requests a new interactive login URL even if already registered. The URL arrives via `.stateChanged(.needsLogin(url))`.
    public func startInteractiveLogin() {
        loginContinuation.yield()
    }

    /// For tests only (outside the public API). At the socket edge, drops UDP sent to this remote port and received from this port.
    ///
    /// Simulates a broken direct path. `Magicsock` and the engine are unaware of this set. It is empty by default (contract N8).
    package func setBlockedUDPPorts(_ ports: Set<UInt16>) {
        blockedUDPPorts = ports
    }

    private func forwardLoginRequests(to control: ControlClient) async {
        for await _ in loginRequests {
            await control.startInteractiveLogin()
        }
    }

    private func forwardInterfaces(to control: ControlClient) async {
        for await interface in interfaceRequests {
            await control.setNetworkInterface(interface)
        }
    }

    private func uploadLocalStatus(to control: ControlClient) async {
        for await status in statusUploads {
            await control.setLocalStatus(status)
        }
    }

    /// Waits for a failure that ends `run()`.
    private func awaitFailure() async -> NodeError? {
        for await failure in failures {
            return failure
        }
        return nil
    }

    /// Reports the new state emitted by the state machine.
    func announce(_ state: NodeState?) {
        guard let state else { return }
        Self.log.info("State: \(state.logName, privacy: .public)")
        eventQueue.push(.stateChanged(state))
        announceStatusIfChanged()
        publishCertificateFacts()
    }

    /// Emits `statusChanged` when `status` differs from the last reported value. Call after the other events from the same update.
    func announceStatusIfChanged() {
        let current = status
        guard current != announcedStatus else { return }
        announcedStatus = current
        eventQueue.push(.statusChanged)
    }
}

extension TailnetNode: CustomReflectable {
    /// Hides its children because it holds the private node key, private disco key, and engine (WireGuard sessions).
    public nonisolated var customMirror: Mirror {
        Mirror(self, children: ["hostname": configuration.hostname])
    }
}

extension DefaultLink {
    init(_ interface: NWInterface, addresses: (regular: [SwiftailBase.IPAddress], loopback: [SwiftailBase.IPAddress])) {
        self.init(name: interface.name, index: interface.index, addresses: addresses.regular, loopbackAddresses: addresses.loopback)
    }
}

extension NodeState {
    /// A name for logging. Omits the login URL.
    var logName: String {
        switch self {
        case .starting: "starting"
        case .needsLogin: "needsLogin"
        case .needsMachineAuth: "needsMachineAuth"
        case .running: "running"
        }
    }
}

extension NodeError {
    /// A failure to duplicate utun. A descriptor closed or changed after validation (`init`) is a configuration error.
    /// Other failures indicate the device is unavailable.
    init(openingTunnel error: SocketError) {
        if case .invalidDevice = error {
            self = .invalidConfiguration("Not a utun descriptor")
        } else {
            self = .tunnelDeviceClosed(error.message)
        }
    }

    /// The kind to log. Omits server diagnostic strings.
    var kind: String {
        switch self {
        case let .control(error): "control(\(error.kind))"
        case .invalidConfiguration: "invalidConfiguration"
        case let .udpUnavailable(message): "udpUnavailable(\(message))"
        case .stateDirectoryInUse: "stateDirectoryInUse"
        case let .tunnelDeviceClosed(message): "tunnelDeviceClosed(\(message))"
        }
    }
}

extension ControlError {
    /// The kind to log.
    var kind: String {
        switch self {
        case .invalidConfiguration: "invalidConfiguration"
        case .storage: "storage"
        case .connection: "connection"
        case let .http(status): "http(\(status))"
        case .authKeyRejected: "authKeyRejected"
        case .registrationRejected: "registrationRejected"
        case .nodeKeyExpired: "nodeKeyExpired"
        }
    }
}

extension SocketError {
    /// A human-readable message such as an errno name. Omits paths and keys.
    var message: String {
        switch self {
        case let .connectFailed(message), let .readFailed(message), let .bindFailed(message), let .sendFailed(message),
            let .invalidDevice(message):
            message
        }
    }
}
