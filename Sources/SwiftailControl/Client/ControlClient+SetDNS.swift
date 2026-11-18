import Foundation
import SwiftailIO

/// Posts an ACME DNS-01 TXT record to the control server with `POST /machine/set-dns`.
///
/// Sends on a new HTTP/2 stream over the connection the same `ControlClient` uses for the map stream during `run()`. Sharing the Noise client
/// matches Go. Sharing the physical connection is a Swiftail implementation choice, and there is no evidence the server requires it.
///
/// Swiftail's choices that differ from Go (contract `docs/contracts/SwiftailHost.md` behaviors D2 and D3).
/// - If disconnected (reconnecting), waits until a connection opens. Waiting and the response have a combined 60 seconds. Go fails immediately with `not connected`.
/// - For a status other than 200, includes only the status code and skips reading or logging the body. Go includes up to 200 code points of the body.
/// - For a 200, reads up to 4KiB and requires a JSON object. Go reads up to 1MiB and also accepts `null`.
///
/// Error messages and logs omit the name and value (behaviors K2 and K3).
///
/// `docs/protocol-notes/whois-certs-state.md` §3.2 (origin: `setDNSNoise` in tailscale.com `control/controlclient/direct.go`,
/// `ipn/ipnlocal/local.go` `SetDNS`, BSD-3-Clause).
extension ControlClient {
    /// The 200 response body limit (contract limits table).
    static let maximumSetDNSResponseSize = 4 << 10

    /// Requests publication of one TXT record and waits for the control server's reply.
    ///
    /// The caller (`TailnetNode.setDNS`) checks which record name is required (`_acme-challenge.` for its own cert domain).
    ///
    /// - Throws: `invalidConfiguration` for an empty name or value. Throws `connection` immediately before registration (no node key).
    ///   Throws `connection` if no connection or reply arrives within 60 seconds, the connection drops, or the 200 body exceeds 4KiB or is not a JSON object.
    ///   Throws `http(status:)` for a status other than 200.
    package func setDNS(name: String, value: String) async throws(ControlError) {
        guard !name.isEmpty, !value.isEmpty else { throw .invalidConfiguration("set-dns requires a nonempty name and value") }
        guard nodePublicKey?.isZero == false else { throw .connection("Cannot send set-dns before registration") }
        let limit = timeouts.setDNS
        do {
            try await withTimeout(limit) { try await self.sendSetDNS(name: name, value: value) }
        } catch let error as ControlError {
            throw error
        } catch is TimeoutError {
            throw .connection("set-dns did not finish within \(limit)")
        } catch {
            throw .connection("set-dns was canceled")
        }
    }

    private func sendSetDNS(name: String, value: String) async throws(ControlError) {
        let connection = try await waitForConnection()
        // Use the key at send time, since it may have changed while waiting.
        guard let nodeKey = nodePublicKey, !nodeKey.isZero else { throw .connection("Cannot send set-dns before registration") }
        let body: [UInt8]
        do {
            body = Array(try JSONEncoder().encode(SetDNSRequest(nodeKey: nodeKey, name: name, value: value)))
        } catch {
            throw .connection("Could not encode the set-dns request as JSON")
        }
        var reader = try await connection.responseStream(
            to: connection.jsonRequest("POST", path: "/machine/set-dns", nodeKey: nodeKey),
            body: body
        )
        // Dropping the reader cancels the stream (RST_STREAM). Skip reading the rejection body.
        guard reader.status == 200 else { throw .http(status: reader.status) }
        var collected: [UInt8] = []
        while let chunk = try await reader.nextChunk() {
            guard collected.count + chunk.count <= Self.maximumSetDNSResponseSize else {
                throw .connection("set-dns response body exceeds the limit of \(Self.maximumSetDNSResponseSize) bytes")
            }
            collected += chunk
        }
        guard (try? JSONDecoder().decode(SetDNSResponse.self, from: Data(collected))) != nil else {
            throw .connection("Expected a JSON object in the set-dns response")
        }
    }

    /// Waits for a registered connection. Throws `connection` if the waiting Task is canceled.
    private func waitForConnection() async throws(ControlError) -> ControlConnection {
        while true {
            if let activeConnection { return activeConnection }
            let (wakeups, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            let id = nextConnectionWaiter
            nextConnectionWaiter += 1
            connectionWaiters[id] = continuation
            for await _ in wakeups { break }
            connectionWaiters[id] = nil
            guard !Task.isCancelled else { throw .connection("Canceled") }
        }
    }
}
