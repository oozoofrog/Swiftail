import Foundation
import Observation
import Swiftail

/// Manages the lifecycle and on-screen state of a single in-process tailnet node.
///
/// `start(authKey:)` creates the node. `stop()` or a failure in `run()` discards it. Restarting creates a new `TailnetNode`
/// (`run()` can be called only once per node).
@MainActor @Observable
final class NodeModel {
    /// The running node, or nil before startup and after shutdown.
    private(set) var node: TailnetNode?
    private(set) var status: NodeStatus?
    /// Guidance for the error thrown by `run()`. Cleared on restart.
    private(set) var failure: String?

    private let controlURL: URL
    private let log: EventLog
    private var running: Task<Void, Never>?

    init(controlURL: URL?, log: EventLog) {
        self.controlURL = controlURL ?? NodeConfiguration.defaultControlURL
        self.log = log
    }

    /// Whether this device has registered before. If so, the app starts the node without authentication at launch.
    ///
    /// Returns true if the identity file cannot be read. The node starts so a failure from `run()` (`.control(.storage)`) can provide guidance.
    var hasSavedIdentity: Bool {
        do throws(NodeError) {
            return try TailnetNode.hasSavedIdentity(in: Storage.nodeState)
        } catch {
            return true
        }
    }

    /// Creates and runs the node. Does nothing if the node is already running.
    ///
    /// - Parameter authKey: The auth key for the first registration. Passed to the node configuration once and never stored. If nil, connects with the saved identity,
    ///     or the node provides a sign-in URL via `.needsLogin(url)` if no identity exists.
    func start(authKey: String?) {
        guard node == nil else { return }
        failure = nil
        do throws(NodeError) {
            let node = try TailnetNode(
                configuration: NodeConfiguration(
                    stateDirectory: Storage.nodeState, hostname: Self.hostname, controlURL: controlURL, authKey: authKey),
                device: .inProcess)
            self.node = node
            log.record(.node, "start", authKey == nil ? "Saved identity or sign-in" : "Auth key")
            running = Task { await self.run(node) }
        } catch {
            fail(error)
        }
    }

    func stop() async {
        running?.cancel()
        await running?.value
    }

    /// Waits for the node to reach `.running` and know its own name. Returns nil if the node stops or the calling Task is canceled.
    func waitUntilRunning() async -> TailnetNode? {
        while let node, !Task.isCancelled {
            if status?.state == .running, status?.fqdn != nil { return node }
            try? await Task.sleep(for: .milliseconds(200))
        }
        return nil
    }

    /// Runs until `run()` completes and keeps the on-screen state current. Logs state transitions and lock changes, and reloads
    /// `status` for the UI on each `statusChanged` event.
    private func run(_ node: TailnetNode) async {
        // The initial state does not arrive as an event.
        await refresh(from: node)
        if let status {
            log.record(.node, "state", status.state.label)
            log.record(.node, "tailnet-lock", status.tailnetLock.label)
        }
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                for await event in node.events { await self.handle(event, from: node) }
            }
            do throws(NodeError) {
                try await node.run()
            } catch {
                fail(error)
            }
            group.cancelAll()
        }
        self.node = nil
        status = nil
        running = nil
        log.record(.node, "stopped", failure == nil ? "Stopped" : "Failed")
    }

    private func handle(_ event: NodeEvent, from node: TailnetNode) async {
        switch event {
        case .stateChanged(let state): log.record(.node, "state", state.label)
        case .tailnetLockChanged(let lock): log.record(.node, "tailnet-lock", lock.label)
        case .statusChanged: await refresh(from: node)
        case .peerPathChanged: break
        }
    }

    private func refresh(from node: TailnetNode) async {
        let status = await node.status
        guard self.node === node else { return }
        self.status = status
    }

    private func fail(_ error: NodeError) {
        failure = error.guidance
        log.record(.node, "failed", error.logName)
    }

    /// The hostname the control server uses to name the node. Keeps the real device name off the tailnet.
    private static var hostname: String {
        #if os(macOS)
        "pairing-demo-mac"
        #else
        "pairing-demo-iphone"
        #endif
    }
}

extension NodeState {
    /// The label for the UI and log. Omits the sign-in URL.
    var label: String {
        switch self {
        case .starting: "Starting"
        case .needsLogin: "Sign-in required"
        case .needsMachineAuth: "Awaiting admin approval"
        case .running: "Connected"
        }
    }
}

extension TailnetLockStatus {
    /// The label for the UI and log.
    var label: String {
        switch mode {
        case .disabled: "Disabled"
        case .enforcing: signingRequest == nil ? "Enabled · This node is signed" : "Enabled · Awaiting signature"
        case .unverified: "Unverified · Peers are not brought up"
        }
    }
}

extension NodeError {
    /// Guidance on what the user can do next.
    var guidance: String {
        switch self {
        case .control(.authKeyRejected):
            "The auth key was rejected. It is invalid, expired, or already used. Start again with a new key or offer."
        case .control(.registrationRejected):
            "The control server rejected registration. Check the tailnet admin policy."
        case .control(.nodeKeyExpired):
            "The node key expired. Restart the node and sign in."
        case .control(.storage):
            "Could not read or write the identity file. Check the app's storage space."
        case .control:
            "Communication with the control server failed. Restart the node."
        case .invalidConfiguration(let message):
            "Invalid node configuration: \(message)"
        case .udpUnavailable(let reason):
            "Could not open the UDP socket (\(reason)). Check the network permissions."
        case .stateDirectoryInUse:
            "Another node is running with the same identity. Relaunch the app."
        case .tunnelDeviceClosed(let reason):
            "The tunnel device closed (\(reason))."
        }
    }

    /// The category to log. Omits diagnostic strings from the server.
    var logName: String {
        switch self {
        case .control(.authKeyRejected): "authKeyRejected"
        case .control(.registrationRejected): "registrationRejected"
        case .control(.nodeKeyExpired): "nodeKeyExpired"
        case .control(.storage): "storage"
        case .control: "control"
        case .invalidConfiguration: "invalidConfiguration"
        case .udpUnavailable(let reason): "udpUnavailable(\(reason))"
        case .stateDirectoryInUse: "stateDirectoryInUse"
        case .tunnelDeviceClosed: "tunnelDeviceClosed"
        }
    }
}
