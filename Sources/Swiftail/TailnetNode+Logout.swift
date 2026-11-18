import SwiftailControl

/// Server-side logout. Contract `docs/contracts/SwiftailHost.md`, “Logout,” behavior O.
extension TailnetNode {
    /// Asks the control server to expire this node's node key (the server side of Go `tailscale logout`).
    ///
    /// Call before `run()` starts or after it ends. The app cancels `run()` and waits for it to end, calls `logOut()`,
    /// then empties the state directory. This method leaves local files (identity, lock state, and certificates) in
    /// place. The app can clear the directory after a failure. If the request never reached the server, for example
    /// because there was no network, the old node remains there. After a cancellation or timeout following delivery
    /// of the request, the server may already have expired the key.
    ///
    /// Overlapping calls are prevented **only within the same process**. If another process (a tunnel extension) is in
    /// `run()` with the same state directory, it is not blocked. That node sees its key expire and registers again with
    /// a new key. An auth key that the server accepts lets the other process undo the logout by reauthenticating. The app stops that process first.
    ///
    /// Returns without sending anything if the node was never registered (no stored node key). Does not retry a request
    /// that was sent. Connects through the interface reported by `setDefaultInterface`, if any.
    ///
    /// - Throws: `stateDirectoryInUse` if a `run()` or another `logOut()` for the same directory is in progress in this
    ///   process, whether on this node or another. Throws `control(.registrationRejected)` if the server rejects it,
    ///   `control(.connection)` if it does not finish within 10 seconds or cannot connect, `control(.http(status:))`
    ///   for a response other than 200, or `control(.storage)` if the identity file cannot be read.
    public func logOut() async throws(NodeError) {
        // Uses the same table as `run()` to prevent overlap. A `run()` started while this directory is claimed ends
        // with `stateDirectoryInUse`.
        let claim = try StateDirectoryClaims.shared.claimCreating(configuration.stateDirectory)
        defer { StateDirectoryClaims.shared.release(claim) }

        let control = ControlClient(
            configuration: .init(serverURL: configuration.controlURL, hostname: configuration.hostname, authKey: configuration.authKey),
            identityStore: identityStore
        )
        if let defaultInterface {
            await control.setNetworkInterface(defaultInterface)
        }
        do throws(ControlError) {
            try await control.logOut()
        } catch {
            Self.log.error("Logout failed")
            throw NodeError(error)
        }
        Self.log.info("Logout: notified the server of node key expiration")
    }
}
