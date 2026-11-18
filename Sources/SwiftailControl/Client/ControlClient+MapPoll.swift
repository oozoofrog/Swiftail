import Foundation
import SwiftailHTTP2
import SwiftailIO

/// The two `POST /machine/map` requests after registration and operations accompanying the map stream.
///
/// - State reporting: `Stream=false, OmitPeers=true`. Reports Hostinfo, NetInfo, DiscoKey, and Endpoints, then reads and discards
///   the full response body. Also uses only this form for changes after the stream opens. Other forms (such as `Stream=false,
///   OmitPeers=false`) make the server close the existing stream. A response that fails to finish within `timeouts.request` is a connection error.
/// - Map stream: `Stream=true, KeepAlive=true, Compress=""`. Passes the body through `MapResponseFramer` → `MapSession` and
///   hands off the result to tailnet lock processing (`receivedLock`). Emits the netmap as an event after filtering. Starts each stream
///   with a new `MapSession`, without session resumption.
/// - Both requests include the head of the local signing authority state in `TKAHead`, starting with the first request if state was stored.
/// - Watchdog: Disconnects if nothing arrives on the map stream for 120 seconds. The server sends KeepAlive at intervals of less than 1 minute.
///   Also wakes at the self node's key expiration time in the last netmap so it can detect expiration even without a new map.
/// - Expiration: Re-registers with a fresh key when the self node key expires. If the new key also expires immediately, ends with `nodeKeyExpired`.
///   Retrying would produce the same result, and repeated attempts would hammer the server.
/// - Ping: Replies to a `PingRequest` with empty `Types` by sending HEAD to its URL. Ignores other types.
///
/// `docs/protocol-notes/control-map.md` §3.4, §3.5, §4.2, §4.5, Chapter 5, §6.2
/// (origin: `sendMapRequest` and `answerPing` in tailscale.com `control/controlclient/direct.go`, BSD-3-Clause).
extension ControlClient {
    static let watchdogTimeout = Duration.seconds(120)
    static let pingTimeout = Duration.seconds(15)

    // MARK: State reporting

    func uploadStatus(over connection: ControlConnection) async throws {
        let status = localStatus
        let tkaHead = lockHeadText
        guard status != uploadedStatus || tkaHead != uploadedTKAHead else { return }
        guard let nodeKey = nodePublicKey else { throw ControlError.connection("Cannot report state before registration") }
        let request = MapRequest(
            nodeKey: nodeKey,
            discoKey: status.discoKey,
            hostinfo: hostinfo,
            endpoints: status.endpoints,
            endpointTypes: status.endpointTypes,
            omitPeers: true,
            tkaHead: tkaHead
        )
        let httpRequest = connection.jsonRequest("POST", path: "/machine/map", nodeKey: nodeKey)
        let body = try Self.encode(request)
        sentTKAHead = tkaHead
        try await withControlTimeout(timeouts.request) {
            var reader = try await connection.responseStream(to: httpRequest, body: body)
            try Self.check(status: reader.status, retryAfter: reader.header("retry-after"))
            while try await reader.nextChunk() != nil {}
        }
        uploadedStatus = status
        uploadedTKAHead = tkaHead
    }

    // MARK: Map stream

    func receiveMap(over connection: ControlConnection) async throws {
        guard let nodeKey = nodePublicKey else { throw ControlError.connection("Cannot receive the map before registration") }
        let status = localStatus
        let request = MapRequest(
            compress: "",
            keepAlive: true,
            nodeKey: nodeKey,
            discoKey: status.discoKey,
            stream: true,
            hostinfo: hostinfo,
            endpoints: status.endpoints,
            endpointTypes: status.endpointTypes,
            tkaHead: lockHeadText
        )
        var reader = try await connection.responseStream(
            to: connection.jsonRequest("POST", path: "/machine/map", nodeKey: nodeKey),
            body: Self.encode(request)
        )
        lastMapActivity = .now
        try Self.check(status: reader.status, retryAfter: reader.header("retry-after"))
        mapStreamOpen = true

        var framer = MapResponseFramer()
        var session = MapSession()
        while let chunk = try await reader.nextChunk() {
            lastMapActivity = .now
            let responses: [MapResponse]
            do {
                responses = try framer.receive(chunk)
            } catch {
                throw ControlError.connection("Map frame error: \(error)")
            }
            for response in responses {
                let update: MapSession.Update
                do {
                    update = try session.apply(response, receivedAt: Date())
                } catch {
                    throw ControlError.connection("Error applying the map response: \(error)")
                }
                if let ping = update.pingRequest, queuedPings < Self.queuedPingLimit, let signals {
                    queuedPings += 1
                    signals.yield(.ping(ping))
                }
                try receivedLock(update)
            }
        }
        throw ControlError.connection("Server ended the map stream")
    }

    /// Emits the filtered netmap as an event and checks the self node's key expiration. Called only by tailnet lock processing (`emitNetmap`).
    func accept(_ netmap: Netmap) throws {
        eventContinuation.yield(.netmap(netmap))
        if netmap.selfNode.keyExpiry != selfKeyExpiry {
            selfKeyExpiry = netmap.selfNode.keyExpiry
            selfKeyExpiryChanged?.yield()
        }
        if let expiry = selfKeyExpiry, expiry <= Date() {
            try selfKeyExpired()
        }
        // Only a usable netmap resets backoff. An expired self node does not count as success.
        renewedExpiredKey = false
        consecutiveFailures = 0
    }

    /// Ends the connection and triggers registration with a fresh key when the self node key expires. Stops if the server also reports that new key as already expired.
    private func selfKeyExpired() throws {
        if renewedExpiredKey { throw ControlError.nodeKeyExpired }
        renewedExpiredKey = true
        rotateNodeKey = true
        needsRegistration = true
        throw SessionInterruption.nodeKeyExpired
    }

    /// Throws after 120 seconds of map stream inactivity. `receiveMap` advances the reference time whenever it receives data.
    /// If the self node key expires sooner, wakes then to handle expiration. When the expiration time changes (including the first netmap),
    /// wakes immediately to recalculate when to wake up.
    func watchMapActivity() async throws {
        while true {
            var deadline = lastMapActivity + Self.watchdogTimeout
            if let expiry = selfKeyExpiry {
                // Check expirations beyond the watchdog interval at the next wakeup. Avoid converting a distant date to Duration.
                let untilExpiry = expiry.timeIntervalSinceNow
                if untilExpiry < Self.watchdogTimeout / .seconds(1) {
                    deadline = min(deadline, .now + .seconds(max(untilExpiry, 0)))
                }
            }
            // Receive change notifications on a fresh stream for each sleep, since canceling the loser of the race closes that stream.
            let (expiryChanges, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            selfKeyExpiryChanged = continuation
            let wake = deadline
            await withTaskGroup(of: Void.self) { group in
                group.addTask { try? await Task.sleep(until: wake, clock: .continuous) }
                group.addTask { for await _ in expiryChanges { return } }
                await group.next()
                group.cancelAll()
            }
            try Task.checkCancellation()
            if let expiry = selfKeyExpiry, expiry <= Date() {
                try selfKeyExpired()
            }
            if lastMapActivity + Self.watchdogTimeout <= .now {
                throw ControlError.connection("No data arrived on the map stream for 120 seconds")
            }
        }
    }

    // MARK: Signals

    /// Handles work outside the map stream in order: report changed state, request interactive login, and answer pings.
    func handle(_ signals: AsyncStream<SessionSignal>, over connection: ControlConnection) async throws {
        for await signal in signals {
            switch signal {
            case .statusChanged:
                // Clear the flag first so another change during reporting can enqueue a new signal.
                isStatusChangeQueued = false
                try await uploadStatusRetrying(over: connection)
            case .loginRequested:
                throw SessionInterruption.loginRequested
            case .ping(let ping):
                queuedPings -= 1
                guard ping.types.isEmpty, !ping.url.isEmpty, ping.url != lastPingURL else { continue }
                lastPingURL = ping.url
                await answer(ping, over: connection)
            }
        }
    }

    /// If state reporting fails with an HTTP error, keeps the stream open and backs off before reporting again.
    /// Throws connection errors because they also end the stream on that connection.
    private func uploadStatusRetrying(over connection: ControlConnection) async throws {
        var failures = 0
        while true {
            do {
                try await uploadStatus(over: connection)
                return
            } catch SessionInterruption.rateLimited(let wait) {
                try await Task.sleep(for: wait, clock: .continuous)
            } catch ControlError.http {
                failures += 1
                try await Task.sleep(for: Backoff.delay(failures: failures, maximum: RetryPolicy.maximumBackoff, jitter: .random(in: 0..<1)), clock: .continuous)
            }
        }
    }

    /// Sends HEAD to the ping URL over the Noise connection when `URLIsNoise` is set, or over ordinary HTTP(S) otherwise. Ignores failures
    /// (Go only logs them).
    ///
    /// shortcut: uses URLSession for non-Noise HEAD pings, so they are not bound to the interface from `setNetworkInterface` (the same as `ServerKey`'s
    /// `/key`). Add binding if a real device shows these requests entering the tunnel.
    private func answer(_ ping: PingRequest, over connection: ControlConnection) async {
        guard let url = URL(string: ping.url), ["http", "https"].contains(url.scheme?.lowercased()) else { return }
        if ping.urlIsNoise {
            var path = url.path(percentEncoded: true)
            if path.isEmpty { path = "/" }
            if let query = url.query(percentEncoded: true) { path += "?" + query }
            let request = HTTP2ClientConnection.Request(method: "HEAD", path: path, authority: connection.authority)
            _ = try? await withControlTimeout(Self.pingTimeout) {
                try await connection.responseStream(to: request, body: nil).status
            }
        } else {
            var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
            request.httpMethod = "HEAD"
            _ = try? await URLSession.shared.data(for: request)
        }
    }
}
