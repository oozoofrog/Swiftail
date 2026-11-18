import CryptoKit
import Foundation
import Network
import SwiftailBase
import SwiftailIO
import SwiftailTKA

/// A control server client that registers the node, reports its state, and maintains a netmap from the map stream.
///
/// This is the only part of the control module that owns both sockets and a clock. I/O-free state machines
/// (`ControlHandshake`, `ControlSession`, `HTTP2ClientConnection`, `MapResponseFramer`, and `MapSession`) make protocol decisions. This actor
/// feeds them bytes and times and emits the results as events (`events`).
///
/// Uses structured concurrency. For the lifetime of one connection, `run()` runs the read loop, map stream, watchdog, state reporting, and tailnet lock procedures as children
/// of one TaskGroup. Canceling the Task that called `run()` stops all children and closes the socket.
///
/// Emitted netmaps have already been filtered by tailnet lock (`ControlClient+TailnetLock.swift`).
///
/// ```swift
/// let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d"),
///                            identityStore: NodeIdentityStore(directory: stateDirectory))
/// async let running: Void = client.run()
/// for await event in client.events { … }
/// ```
///
/// Contract `docs/contracts/SwiftailControl.md` unit 4. The procedures are in `docs/protocol-notes/control-map.md` §4.1, §4.2, §4.4, §4.5,
/// and `docs/protocol-notes/control-transport.md` Chapter 4 (origin: tailscale.com `control/controlclient/direct.go` and `auto.go`).
public actor ControlClient {
    public struct Configuration: Sendable {
        /// The control server URL, using `http://` or `https://`.
        public var serverURL: URL
        /// The node's hostname. The server uses it to name the node.
        public var hostname: String
        /// The auth key. Used only to register a fresh node key, at initial registration or during rotation. It is never logged.
        public var authKey: String?
        /// Registers the node for removal by the server after prolonged inactivity.
        public var ephemeral: Bool

        public init(serverURL: URL, hostname: String, authKey: String? = nil, ephemeral: Bool = false) {
            self.serverURL = serverURL
            self.hostname = hostname
            self.authKey = authKey
            self.ephemeral = ephemeral
        }
    }

    public enum Event: Sendable {
        /// The user must log in at this URL to complete registration.
        case loginRequired(URL)
        /// Registration completed and the identity was saved.
        case registered(NodePublicKey)
        /// The netmap changed, including the first response in the map stream. Tailnet lock has filtered it, and `tailnetLock` shows the lock state.
        /// Emits it again even if only the lock state changes (a change to the signing authority state) and peers stay the same.
        case netmap(Netmap)
        /// The map stream disconnected. Backs off and reconnects. The last netmap remains valid in the meantime.
        case disconnected
    }

    /// The current state to report for this node. Sent in a request separate from the map stream.
    public struct LocalStatus: Sendable, Equatable {
        public var discoKey: DiscoPublicKey
        public var endpoints: [IPEndpoint]
        public var endpointTypes: [EndpointType]
        public var netInfo: NetInfo?

        public init(
            discoKey: DiscoPublicKey = .zero,
            endpoints: [IPEndpoint] = [],
            endpointTypes: [EndpointType] = [],
            netInfo: NetInfo? = nil
        ) {
            self.discoKey = discoKey
            self.endpoints = endpoints
            self.endpointTypes = endpointTypes
            self.netInfo = netInfo
        }
    }

    /// Work to handle outside the map stream while one connection is open.
    enum SessionSignal: Sendable {
        case statusChanged
        case loginRequested
        case ping(PingRequest)
    }

    /// Deadlines for requests that wait for a reply. A missed deadline is a connection error followed by backoff and reconnection.
    ///
    /// Go uses a 120-second watchdog timer only for map requests (both streaming and state updates) and has no deadline for registration or Followup
    /// (`watchdogTimeout` in `direct.go`'s `sendMapRequest`, and `doLogin`). To avoid being stuck indefinitely on an unresponsive server, applies
    /// the same 120 seconds to registration and 10 minutes to a Followup long poll waiting for the user to log in. Keeps the candidate key and
    /// Followup URL if Followup is interrupted so reconnection resumes waiting for the same login.
    struct Timeouts: Sendable {
        /// Registration other than Followup, and state reporting.
        var request = Duration.seconds(120)
        /// A Followup long poll.
        var followup = Duration.seconds(600)
        /// `setDNS`: Total deadline for waiting for a connection and receiving the response (contract `docs/contracts/SwiftailHost.md`, behavior D2).
        var setDNS = Duration.seconds(60)
        /// One tailnet lock RPC (1 minute, as in Go. Contract `docs/contracts/SwiftailTailnetLock.md`, behavior M).
        var tkaRequest = Duration.seconds(60)
        /// The range of bootstrap retry intervals when the client fails closed without verified state (`.unverified`) (behavior N6).
        var lockRetry = Duration.seconds(5)...Duration.seconds(300)
        /// `logOut()`: Total deadline for fetching the server key, connecting, and receiving the response. Go has no logout-specific deadline (uses the caller's context).
        /// Uses the 10 seconds in contract `docs/contracts/SwiftailHost.md`, "Logout", behavior O5.
        var logout = Duration.seconds(10)
    }

    let configuration: Configuration
    let identityStore: NodeIdentityStore
    let timeouts: Timeouts
    let eventContinuation: AsyncStream<Event>.Continuation
    private let eventStream: AsyncStream<Event>

    /// Uncommitted registration holds the candidate node key and the server's Followup URL. The user's login at that URL completes registration with this key,
    /// so keep it across reconnections until registration is committed or a new login is requested. Does not persist it (as with Go `Direct.tryingNewKey`
    /// `LoginGoal.url`).
    struct PendingRegistration {
        var nodeKey: Curve25519.KeyAgreement.PrivateKey
        var oldNodeKey: NodePublicKey
        var followup: String
    }

    /// The number of events retained before dropping any. Drops the oldest first if the subscriber does not read them.
    static let eventBufferLimit = 64

    /// The current identity. `run()` loads or creates it.
    var identity = NodeIdentity()
    /// The parsed configuration auth key if it is a signed auth key (`--TL`). `run()` parses it once before the first connection.
    var wrappedAuthKey: WrappedAuthKey?
    var localStatus = LocalStatus()
    /// The last state reported on the current connection. Skips reporting the same state again.
    var uploadedStatus: LocalStatus?
    /// The last `TKAHead` reported on the current connection for which a response arrived. Skips reporting when both the state and this value match.
    var uploadedTKAHead: String?
    /// The last `TKAHead` sent on the current connection, possibly still awaiting a response. Head reporting compares against this value, so a head change
    /// during reporting causes the current head to be sent after the response.
    var sentTKAHead: String?
    var needsRegistration = true
    /// Creates a fresh node key for the next registration (interactive login or expiration).
    var rotateNodeKey = false
    /// The number of `startInteractiveLogin()` calls. Registration satisfies that request only if this value is the same at the start and end.
    var loginRequests = 0
    var pendingRegistration: PendingRegistration?
    /// The channel that stops a Followup long poll awaiting login when a new login is requested.
    var followupInterrupt: AsyncStream<Void>.Continuation?
    /// A fresh key was registered due to expiration and an unexpired self node has yet to arrive. Stops on a second expiration in this state.
    var renewedExpiredKey = false
    /// The self node key's expiration time from the last netmap on the current connection. The watchdog wakes at that time.
    var selfKeyExpiry: Date?
    /// Wakes the sleeping watchdog when `selfKeyExpiry` changes.
    var selfKeyExpiryChanged: AsyncStream<Void>.Continuation?
    /// The consecutive failure count. Resets to 0 after a usable netmap or when the network interface changes.
    var consecutiveFailures = 0
    /// Whether a map stream is currently open.
    var mapStreamOpen = false
    /// The latest time any data arrived on the map stream. The 120-second watchdog uses this time.
    var lastMapActivity = ContinuousClock.now
    /// The URLs of pings already answered. Replies only once even if the server resends the same ping.
    var lastPingURL: String?
    /// The verified signing authority state, or nil without lock. `run()` opens it from storage and retains it across reconnects.
    var lockAuthority: Authority?
    /// The stored signing authority state could not be opened. Withholds peers until the app deletes the file and restarts.
    var isLockStoreUnreadable = false
    /// The BLAKE2s-256 digests of rejected disablement secrets (oldest first, up to `maximumRejectedDisablementCount`) and the head at that time. These avoid
    /// rerunning the KDF (16MiB) for the same secret. Resets on a head change. Kept only in memory.
    var rejectedDisablements: (head: AUMHash, secretDigests: [[UInt8]])?
    /// The stored state failed to connect to the chain reported by the server (synchronization found no intersection). Clears when a later sync finds an intersection or the lock is
    /// disabled. Retained across disconnects.
    var isLockStateDiverged = false
    /// The number of times the disablement secret KDF ran. Tests verify that the same secret is not recomputed.
    var disablementDerivationCount = 0
    /// Tailnet lock processing state for the current map session.
    var lockSession = LockSession()
    /// The signal channel for the current connection, or nil without a connection.
    var signals: AsyncStream<SessionSignal>.Continuation?
    /// The current registered connection. Requests outside the map stream (`setDNS`) use new streams on it. Nil without a connection.
    var activeConnection: ControlConnection?
    /// The wakeup channel for `setDNS` calls waiting for `activeConnection`. Wakes them all when the connection opens.
    var connectionWaiters: [Int: AsyncStream<Void>.Continuation] = [:]
    var nextConnectionWaiter = 0
    /// Signals queued in the channel and not yet handled. Keeps the channel from growing unbounded while processing is blocked (state-reporting backoff or ping replies).
    /// One state-change signal suffices because reporting reads the latest value. Queues at most `queuedPingLimit` pings.
    var isStatusChangeQueued = false
    var queuedPings = 0
    static let queuedPingLimit = 8
    /// The interface to bind the connection to. Nil leaves it unbound. Read when `run()` starts a connection and when `logOut()` connects.
    private(set) var networkInterface: NWInterface?
    /// The number of `setNetworkInterface` calls. Drops a connection attempt if this value differs from its starting value. This keeps signals
    /// received between attempts from being lost (like `loginRequests`).
    private var interfaceGeneration = 0
    /// The wakeup channel for the current waiter, or nil when nothing is waiting.
    private var interfaceChange: AsyncStream<Void>.Continuation?
    /// The currently cached control server Noise public key. Clears it on connection failure and fetches it again next time.
    private var serverKey: MachinePublicKey?
    private var hasRun = false

    public init(configuration: Configuration, identityStore: NodeIdentityStore) {
        self.init(configuration: configuration, identityStore: identityStore, timeouts: Timeouts())
    }

    /// Creates a client with specified deadlines. Tests use it to supply short deadlines.
    init(configuration: Configuration, identityStore: NodeIdentityStore, timeouts: Timeouts) {
        self.configuration = configuration
        self.identityStore = identityStore
        self.timeouts = timeouts
        (eventStream, eventContinuation) = AsyncStream.makeStream(of: Event.self, bufferingPolicy: .bufferingNewest(Self.eventBufferLimit))
    }

    /// The event stream. Supports one subscriber. Finishes after `run()` ends and any buffered events are consumed.
    ///
    /// Keeps up to the newest 64 unread events and drops the oldest first. A `netmap` always contains the full state, so reading only the latest
    /// one suffices.
    public nonisolated var events: AsyncStream<Event> { eventStream }

    /// Updates the state. Reports it immediately when connected or on the next connection otherwise. Keeps only the latest value.
    public func setLocalStatus(_ status: LocalStatus) {
        localStatus = status
        guard !isStatusChangeQueued, let signals else { return }
        isStatusChangeQueued = true
        signals.yield(.statusChanged)
    }

    /// Requests a new interactive login URL even if already registered. Re-registers with a fresh node key and
    /// reports the server's URL in `loginRequired`.
    public func startInteractiveLogin() {
        rotateNodeKey = true
        needsRegistration = true
        loginRequests += 1
        pendingRegistration = nil
        followupInterrupt?.yield()
        signals?.yield(.loginRequested)
    }

    /// Changes the interface the connection is bound to, closes the current connection, and immediately reconnects on the new interface.
    ///
    /// Skips backoff. Whether connecting, receiving the map stream on an open connection, or backing off after a failure, abandons the current work
    /// and immediately starts a new connection. Retains registration state and the last netmap (the map stream starts with a full map
    /// on the new connection). Reports the closed connection as `disconnected`.
    ///
    /// **Reporting the same interface also triggers reconnection.** On the same Wi-Fi network, an address-only change (a different AP or a DHCP renewal) leaves the old connection
    /// dead. The caller decides whether to reconnect (whether the interface or local address changed, `docs/contracts/SwiftailTunnel.md`
    /// behavior N §2). This method reconnects when called. Several calls in succession start only one new attempt
    /// with the latest value.
    ///
    /// `shortcut:` does not report network loss (no satisfied path). The connection relies on retries and backoff in `run()` while the network is down.
    /// Add reporting if retries while the network is unavailable cause battery or memory problems on a real device
    /// (`docs/contracts/SwiftailTunnel.md` behavior N §5).
    ///
    /// Calling before `run()` starts or after it finishes only stores the value. A `nil` value leaves the connection unbound. Loopback servers
    /// always use an unbound connection (`NetworkSocket.bindableInterface`).
    public func setNetworkInterface(_ interface: NWInterface?) {
        networkInterface = interface
        interfaceGeneration += 1
        interfaceChange?.yield()
    }

    /// Registers, reports state, and maintains the map stream. Backs off and reconnects after a disconnect.
    /// Continues until the calling task is canceled or an error cannot be resolved by retrying. Throws that error.
    /// Call once per client. A repeated call while running or after completion throws `invalidConfiguration`.
    public func run() async throws(ControlError) {
        guard !hasRun else { throw .invalidConfiguration("Call run() only once per client") }
        hasRun = true
        defer { eventContinuation.finish() }

        let endpoint = try ControlEndpoint(serverURL: configuration.serverURL)
        guard !configuration.hostname.isEmpty else { throw .invalidConfiguration("Hostname is empty") }
        try prepareRegistration()
        openLockStore()
        needsRegistration = true

        while !Task.isCancelled {
            // Read the interface and its generation together at the start of the attempt, with no suspension point between them.
            let (interface, generation) = (networkInterface, interfaceGeneration)
            let delay: Duration
            do {
                try await untilInterfaceChanges(since: generation) {
                    try await self.connectAndServe(to: endpoint, interface: interface)
                }
                delay = .zero
            } catch {
                if Task.isCancelled { return }
                switch error {
                case SessionInterruption.loginRequested:
                    delay = .zero
                case SessionInterruption.interfaceChanged:
                    // Failures accumulated on the old network must not delay the first attempt on the new network.
                    consecutiveFailures = 0
                    delay = .zero
                case SessionInterruption.rateLimited(let wait):
                    delay = wait
                case let error as ControlError where !error.isRetryable:
                    throw error
                default:
                    // Connection or HTTP failure, or re-registration after expiration. Fetch the server key again because the server may have changed it.
                    serverKey = nil
                    consecutiveFailures += 1
                    delay = Backoff.delay(failures: consecutiveFailures, maximum: RetryPolicy.maximumBackoff, jitter: .random(in: 0..<1))
                }
            }
            if mapStreamOpen {
                mapStreamOpen = false
                eventContinuation.yield(.disconnected)
            }
            do {
                // If the interface changes during backoff, reconnect immediately without waiting.
                try await untilInterfaceChanges(since: generation) {
                    try await Task.sleep(for: delay, clock: .continuous)
                }
            } catch SessionInterruption.interfaceChanged {
                consecutiveFailures = 0
            } catch {
                return
            }
        }
    }

    /// Fetches the server key if needed, establishes a connection, and runs `serve`. Ends only by throwing.
    private func connectAndServe(to endpoint: ControlEndpoint, interface: NWInterface?) async throws {
        let key: MachinePublicKey
        if let serverKey { key = serverKey } else { key = try await ServerKey.fetch(for: endpoint) }
        serverKey = key
        try await ControlConnection.withConnection(to: endpoint, interface: interface, machineKey: identity.machineKey, serverKey: key) {
            try await self.serve($0)
        }
    }

    /// Runs `operation`. If the interface changes after `generation`, cancels it and throws `SessionInterruption.interfaceChanged`.
    /// If `operation` finishes first, returns its result or throws its error.
    ///
    /// Creates a fresh wakeup channel for each wait because canceling the loser of the race closes its stream. If the interface already changed
    /// (`generation` is stale), the channel wakes immediately. This also preserves changes that arrive between attempts.
    private func untilInterfaceChanges<Result: Sendable>(
        since generation: Int, _ operation: @escaping @Sendable () async throws -> Result
    ) async throws -> Result {
        let (changes, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        if interfaceGeneration != generation { continuation.yield() }
        interfaceChange = continuation
        defer { interfaceChange = nil }
        return try await withThrowingTaskGroup(of: Result?.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await operation() }
            group.addTask {
                for await _ in changes { return nil }
                return nil
            }
            guard let first = try await group.next(), let result = first else {
                throw SessionInterruption.interfaceChanged
            }
            return result
        }
    }

    /// Handles one connection: registers if needed, reports state, then runs the map stream, watchdog, signal handling, and tailnet lock procedures together.
    /// Ends only by throwing.
    private func serve(_ connection: ControlConnection) async throws {
        let (signalStream, continuation) = AsyncStream.makeStream(of: SessionSignal.self)
        signals = continuation
        isStatusChangeQueued = false
        queuedPings = 0
        uploadedStatus = nil
        uploadedTKAHead = nil
        sentTKAHead = nil
        lockSession = LockSession()
        selfKeyExpiry = nil
        selfKeyExpiryChanged = nil
        defer {
            continuation.finish()
            signals = nil
            activeConnection = nil
        }

        if needsRegistration {
            try await register(over: connection)
        }
        activeConnection = connection
        for waiter in connectionWaiters.values { waiter.yield() }
        try await uploadStatus(over: connection)

        lastMapActivity = .now
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await self.receiveMap(over: connection) }
            group.addTask { try await self.watchMapActivity() }
            group.addTask { try await self.handle(signalStream, over: connection) }
            group.addTask { try await self.runLockProcedures(over: connection) }
            try await group.next()
            throw ControlError.connection("Map processing has ended")
        }
    }

    /// The node public key for the current identity, or nil before registration.
    var nodePublicKey: NodePublicKey? { identity.nodePublicKey }

    /// The Hostinfo to send with registration and state reporting.
    var hostinfo: Hostinfo {
        Hostinfo.swiftail(
            hostname: configuration.hostname,
            machineKey: identity.machinePublicKey,
            netInfo: localStatus.netInfo
        )
    }
}

/// Reasons a connection ends that are outside `ControlError`.
enum SessionInterruption: Error {
    /// Interactive login was requested. Reconnects immediately to register.
    case loginRequested
    /// The self node key expired (a map response or the expiration time arrived). Backs off and registers again with a fresh key.
    case nodeKeyExpired
    /// The server instructed the client to wait (429, or 503 with `Retry-After`).
    case rateLimited(Duration)
    /// `setNetworkInterface` was called. Reconnects immediately on the new interface without backoff.
    case interfaceChanged
}

extension ControlClient.PendingRegistration: CustomReflectable {
    /// Exposes only the public key of the candidate node key.
    var customMirror: Mirror {
        Mirror(self, children: ["nodePublicKey": NodePublicKey(nodeKey.publicKey), "oldNodeKey": oldNodeKey, "followup": followup])
    }
}

extension ControlClient.Configuration: CustomStringConvertible, CustomReflectable {
    /// Redacts the auth key so logging the configuration value as is does not leak the secret.
    public var description: String {
        "Configuration(serverURL: \(serverURL), hostname: \(hostname), authKey: \(authKey == nil ? "none" : "<redacted>"), ephemeral: \(ephemeral))"
    }

    /// Redacts the auth key here too because `dump` bypasses `description`.
    public var customMirror: Mirror {
        Mirror(self, children: [
            "serverURL": serverURL,
            "hostname": hostname,
            "authKey": authKey == nil ? "none" : "<redacted>",
            "ephemeral": ephemeral,
        ])
    }
}
