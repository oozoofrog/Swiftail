import Foundation
import SwiftailBase
import SwiftailIO

/// Logs out by asking the control server to expire the current node key (the server side of Go `tailscale logout`).
///
/// Uses the registration path (`POST /machine/register` over Noise) with the stored node key as is and `Expiry` in the distant past. The server
/// treats a past `Expiry` with the current node key as expiration of that key (the comment on `tailcfg.RegisterRequest.Expiry`).
///
/// Matches Go for `NodeKey` (current key), `NLKey`, `Hostinfo`, empty `Followup`, no `Ephemeral`, and `Expiry` = 1970-01-01T00:02:03Z.
/// Treats only `Error` in the response as a failure and ignores `NodeKeyExpired`, `NodeKeySignature`, and `AuthURL` (Go `TryLogout`
/// discards `doLogin`'s `mustRegen` and `newURL`). Does not retry.
///
/// Differences from Go (contract `docs/contracts/SwiftailHost.md` "Logout", behavior O).
/// - Omits the auth key. When Go's control client holds an auth key, it includes `Auth` and the wrapped key's signature in the logout request too.
/// - `OldNodeKey` is always a zero key because Swiftail does not store the old node key. Go includes the stored old key if it has rotated the key.
/// - Applies a deadline (`Timeouts.logout`, 10 seconds). Go uses only the caller's context, and the CLI and LocalAPI set no deadline.
/// - Leaves the identity file intact. Go clears the in-memory persist and deletes the profile regardless of the response. The app handles file cleanup.
///
/// Origin: `TryLogout` and `doLogin` (`loginOpt.Logout`) in tailscale.com `control/controlclient/direct.go`,
/// `control/controlclient/auto.go` `Logout`, `ipn/ipnlocal/local.go` `Logout`, BSD-3-Clause.
extension ControlClient {
    /// The `Expiry` Go `doLogin` sends for logout (`time.Unix(123, 0)`, "far in the past").
    static let logoutExpiry = Date(timeIntervalSince1970: 123)

    /// Requests that the control server expire the stored node key and waits for its reply.
    ///
    /// Do not call this concurrently with `run()`. The caller (`TailnetNode.logOut()`) prevents overlap with `run()` using the same state directory.
    /// Only reads the identity file and does not create it if absent.
    ///
    /// - Throws: `invalidConfiguration` for an invalid server URL, `storage` if the identity file cannot be read, `registrationRejected`
    ///   for a nonempty response `Error`, `http(status:)` for a status other than 200, or `connection` if it cannot connect, the deadline passes without a reply,
    ///   the response cannot be parsed, or the task is canceled.
    package func logOut() async throws(ControlError) {
        let endpoint = try ControlEndpoint(serverURL: configuration.serverURL)
        // With no prior registration, there is no key to report to the server (Go `LocalBackend.Logout`'s `hasNodeKeyLocked`).
        guard let identity = try identityStore.load(), let nodeKey = identity.nodePublicKey else { return }
        let request = RegisterRequest(
            nodeKey: nodeKey,
            nlKey: identity.lockPublicKey,
            expiry: Self.logoutExpiry,
            hostinfo: Hostinfo.swiftail(hostname: configuration.hostname, machineKey: identity.machinePublicKey, netInfo: nil)
        )
        guard let body = try? Self.encode(request) else { throw .connection("Could not encode the logout request as JSON") }
        let interface = networkInterface
        let limit = timeouts.logout
        let response: RegisterResponse
        do {
            response = try await withTimeout(limit) {
                let serverKey = try await ServerKey.fetch(for: endpoint)
                return try await ControlConnection.withConnection(
                    to: endpoint, interface: interface, machineKey: identity.machineKey, serverKey: serverKey
                ) { connection in
                    let reply = try await connection.response(
                        to: connection.jsonRequest("POST", path: "/machine/register", nodeKey: nodeKey),
                        body: body,
                        limit: Self.maximumRegisterResponseSize
                    )
                    guard reply.status == 200 else { throw ControlError.http(status: reply.status) }
                    guard let decoded = try? JSONDecoder().decode(RegisterResponse.self, from: Data(reply.body)) else {
                        throw ControlError.connection("Could not parse the logout response")
                    }
                    return decoded
                }
            }
        } catch let error as ControlError {
            throw error
        } catch is TimeoutError {
            throw .connection("Logout did not finish within \(limit)")
        } catch {
            throw .connection(Task.isCancelled ? "Logout was canceled" : "Logout request failed")
        }
        guard response.error.isEmpty else {
            throw .registrationRejected(Self.rejectionMessage(response.error, authKey: configuration.authKey))
        }
    }
}
