import Foundation
import SwiftailBase
import Testing

@testable import SwiftailControl

let controlFaultsBinary = ProcessInfo.processInfo.environment["SWIFTAIL_CONTROLFAULTS"].flatMap { $0.isEmpty ? nil : $0 }

/// Regression tests against a deliberately misbehaving control server (`Tools/interop/cmd/controlfaults`).
/// Verifies counts of requests from the server, events, the `run()` result, and the identity file without inspecting client internals.
@Suite("Control client: Misbehaving server", .enabled(if: controlFaultsBinary != nil,
    "Skipping because SWIFTAIL_CONTROLFAULTS is missing"), .timeLimit(.minutes(2)))
struct ControlFaultsTests {
    @Test("Reconnects after the deadline if the server does not answer the state upload")
    func statusUploadWithoutResponse() async throws {
        let timeouts = ControlClient.Timeouts(request: .seconds(1), followup: .seconds(1))
        try await withFaultClient("initialUploadHang", timeouts: timeouts) { server, client, _ in
            _ = try await server.wait("State upload on the second connection after the deadline", timeout: .seconds(10)) {
                $0.connections >= 2 && $0.maps >= 2
            }
        }
    }

    @Test("Interactive login requested during registration registers again with a new key after that registration finishes")
    func interactiveLoginDuringRegistration() async throws {
        try await withFaultClient("interactiveRace") { server, client, _ in
            _ = try await server.wait("Held first registration") { $0.registers == 1 }
            await client.client.startInteractiveLogin()
            try await server.release()
            let first = try await client.registered("First registration complete")
            let second = try await client.registered("New registration for interactive login")
            #expect(first != second, "Interactive login registers with a new node key")
            let probe = try await server.probe()
            #expect(probe.registers == 2)
            #expect(probe.nodeKeys == 2)
        }
    }

    @Test("A disconnect during Followup keeps waiting for login with the same candidate key and Followup URL")
    func followupSurvivesReconnect() async throws {
        try await withFaultClient("followupReconnect") { server, client, directory in
            var loginRequests = 0
            var registered: NodePublicKey?
            while registered == nil {
                switch try await client.next("Registration complete after loginRequired") {
                case .loginRequired: loginRequests += 1
                case .registered(let key): registered = key
                case .netmap, .disconnected: throw GateFailure("A map event arrived before registration")
                }
            }
            #expect(loginRequests == 1, "The user must receive only one login URL")
            let probe = try await server.probe()
            #expect(probe.connections == 2)
            #expect(probe.followups == 2, "Registration after reconnecting must also be a Followup")
            #expect(probe.nodeKeys == 1, "Reconnecting does not change the candidate key")
            #expect(try NodeIdentityStore(directory: directory).load()?.nodePublicKey == registered)
        }
    }

    @Test("Registers again with a new key when the self key expires, even if no new map arrives")
    func selfKeyExpiresWithoutNewMap() async throws {
        try await withFaultClient("expiryTimer") { _, client, _ in
            let first = try await client.registered("First registration")
            let second = try await client.registered("New registration after expiration", timeout: .seconds(10))
            #expect(first != second)
        }
    }

    @Test("Sends the auth key each time a new node key is registered, both initially and after expiration")
    func authKeyOnEveryRegistration() async throws {
        try await withFaultClient("expiryTimer", authKey: "tskey-auth-EXAMPLE-0000") { server, client, _ in
            _ = try await client.registered("First registration")
            _ = try await client.registered("New registration after expiration", timeout: .seconds(10))
            let probe = try await server.probe()
            #expect(probe.registers >= 2)
            #expect(probe.withAuth == probe.registers)
        }
    }

    @Test("Does not send the auth key when reconnecting with an already registered key (restart)")
    func authKeyNotResentForStoredKey() async throws {
        try await withFaultServer("basic") { server, directory in
            let authKey = "tskey-auth-EXAMPLE-0000"
            let first = FaultClient(server: server, directory: directory, authKey: authKey, timeouts: .init(), observes: true)
            let firstKey: NodePublicKey
            do {
                firstKey = try await first.registered("First registration")
                await first.stop()
            } catch {
                await first.stop()
                throw error
            }
            // The single-use auth key was used during initial registration. The production server may reject it if sent again when starting with the same identity.
            let second = FaultClient(server: server, directory: directory, authKey: authKey, timeouts: .init(), observes: true)
            do {
                let secondKey = try await second.registered("Registration after restart")
                #expect(secondKey == firstKey)
                let probe = try await server.probe()
                #expect(probe.registers == 2)
                #expect(probe.withAuth == 1, "Registration with the stored key must omit the auth key")
                #expect(probe.nodeKeys == 1)
                await second.stop()
            } catch {
                await second.stop()
                throw error
            }
        }
    }

    @Test("Requesting a new login during a long poll waiting for login immediately restarts with a new key and URL")
    func interactiveLoginDuringFollowup() async throws {
        try await withFaultClient("followupHold") { server, client, _ in
            guard case .loginRequired(let firstURL) = try await client.next("First login URL") else {
                throw GateFailure("Expected loginRequired")
            }
            _ = try await server.wait("Held Followup") { $0.followups == 1 }
            await client.client.startInteractiveLogin()
            // The default Followup deadline is 10 minutes. Unless it is abandoned, the event below does not arrive in time.
            guard case .loginRequired(let secondURL) = try await client.next("New login URL") else {
                throw GateFailure("Expected a new loginRequired")
            }
            #expect(firstURL != secondURL)
            let probe = try await server.wait("Followup for the new candidate key") { $0.followups == 2 }
            #expect(probe.nodeKeys == 2, "The new login starts with a new candidate key")
        }
    }

    @Test("A new login requested while backing off with the same AuthURL does not revive the previous candidate key")
    func interactiveLoginDuringRepeatedURLBackoff() async throws {
        try await withFaultClient("sameAuthURL") { server, client, _ in
            // Backoff grows as the same URL repeats. After the seventh time, it is almost always asleep.
            _ = try await server.wait("Repeat of the same URL", timeout: .seconds(20)) { $0.registers >= 7 }
            #expect(try await server.probe().nodeKeys == 1)
            await client.client.startInteractiveLogin()
            _ = try await server.wait("Registration with the new candidate key", timeout: .seconds(20)) { $0.nodeKeys == 2 }
            try await server.release()
            var loginURLs = 0
            registration: while true {
                switch try await client.next("Registration after release", timeout: .seconds(20)) {
                case .loginRequired: loginURLs += 1
                case .registered: break registration
                case .netmap, .disconnected: continue
                }
            }
            #expect(loginURLs == 2, "Notifies twice, once for the initial URL and once for the new login URL")
            #expect(try await server.probe().nodeKeys == 2, "The new candidate key was committed")
        }
    }

    @Test("Ends with nodeKeyExpired if registration with the new key also reports expiration")
    func alwaysExpired() async throws {
        try await withFaultClient("alwaysExpired") { server, client, _ in
            let error = try await client.result(timeout: .seconds(10))
            guard case .nodeKeyExpired? = error else {
                Issue.record("Expected nodeKeyExpired, got \(String(describing: error))")
                return
            }
            #expect(try await server.probe().registers == 2, "Registers again with a new key only once after expiration")
        }
    }

    @Test("Retains only the 64 newest unconsumed events")
    func eventBufferKeepsNewest() async throws {
        try await withFaultClient("manyMaps", observes: false) { server, client, _ in
            // Once the second map stream request arrives, it has already emitted 200 responses and disconnected for the first stream.
            _ = try await server.wait("Second map stream", timeout: .seconds(10)) { $0.maps >= 4 }
            _ = try await client.result(cancelling: true)
            var events: [ControlClient.Event] = []
            for await event in client.client.events { events.append(event) }
            #expect(events.count == 64)
            guard events.count >= 2, case .disconnected = events[events.count - 1],
                  case .netmap(let last) = events[events.count - 2] else {
                Issue.record("The last two events are not netmap and disconnected")
                return
            }
            #expect(last.domain == "d199")
        }
    }

    @Test("An auth key echoed by a rejection message is absent from the error")
    func rejectionHidesEchoedAuthKey() async throws {
        let controlValue = "tskey-auth-" + UUID().uuidString
        // An undecodable `--TL` suffix is now rejected before registration (`SwiftailTailnetLock.md`, decision L12), so use an ordinary auth key here.
        // `RegistrationSigningTests` checks that the suffix and wrapped key do not reach the server.
        try await withFaultClient("authEcho", authKey: controlValue) { _, client, _ in
            let error = try await client.result(timeout: .seconds(10))
            guard case .authKeyRejected(let message)? = error else {
                Issue.record("Expected authKeyRejected")
                return
            }
            #expect(message.hasPrefix("invalid authkey: "))
            var dumped = ""
            dump(error, to: &dumped)
            for rendered in [message, dumped, String(describing: error)] {
                #expect(!rendered.contains(controlValue))
            }
        }
    }
}

// MARK: - Running the tool

/// One controlfaults process. The first stdout line is the server URL, and closing stdin ends it.
struct FaultServer: Sendable {
    struct Probe: Decodable, Sendable {
        var connections: Int
        var registers: Int
        var followups: Int
        var withAuth: Int
        var maps: Int
        var nodeKeys: Int
    }

    let url: URL

    func probe() async throws -> Probe {
        let (data, _) = try await URLSession.shared.data(from: url.appending(path: "probe"))
        return try JSONDecoder().decode(Probe.self, from: data)
    }

    /// Waits for the server counters to satisfy `predicate`.
    func wait(
        _ description: String, timeout: Duration = .seconds(5), until predicate: (Probe) -> Bool
    ) async throws -> Probe {
        let deadline = ContinuousClock.now + timeout
        while true {
            let probe = try await probe()
            if predicate(probe) { return probe }
            guard ContinuousClock.now < deadline else { throw GateFailure("\(description) timed out (\(timeout)): \(probe)") }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    /// Releases the first registration held in interactiveRace mode.
    func release() async throws {
        _ = try await URLSession.shared.data(from: url.appending(path: "release"))
    }
}

/// Starts the server and calls `body`. Reaps the process and removes the identity directory on success or failure.
func withFaultServer(_ mode: String, _ body: (FaultServer, URL) async throws -> Void) async throws {
    let binary = try #require(controlFaultsBinary)
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: binary)
    process.arguments = [mode]
    process.standardInput = input
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-faults-\(UUID().uuidString)")
    try process.run()
    defer {
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: directory)
    }
    var firstLine: String?
    for try await line in output.fileHandleForReading.bytes.lines {
        firstLine = line
        break
    }
    let url = try #require(firstLine.flatMap { URL(string: $0) }, "controlfaults did not print an address")
    try await body(FaultServer(url: url), directory)
}

/// Starts the server and calls `body` while running `run()` on a client connected to it.
/// Cancels `run()` afterward and waits for it to finish.
func withFaultClient(
    _ mode: String, authKey: String? = nil, timeouts: ControlClient.Timeouts = .init(), observes: Bool = true,
    _ body: (FaultServer, FaultClient, URL) async throws -> Void
) async throws {
    try await withFaultServer(mode) { server, directory in
        let client = FaultClient(server: server, directory: directory, authKey: authKey, timeouts: timeouts, observes: observes)
        do {
            try await body(server, client, directory)
            await client.stop()
        } catch {
            await client.stop()
            throw error
        }
    }
}

/// Runs `run()` and receives events. Observes only the public API (events and the `run()` result).
struct FaultClient: Sendable {
    let client: ControlClient
    private let running: Task<ControlError?, Never>
    private let observed: AsyncStream<ControlClient.Event>?

    init(server: FaultServer, directory: URL, authKey: String?, timeouts: ControlClient.Timeouts, observes: Bool) {
        let client = ControlClient(
            configuration: .init(serverURL: server.url, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            identityStore: NodeIdentityStore(directory: directory),
            timeouts: timeouts
        )
        self.client = client
        running = Task {
            do throws(ControlError) { try await client.run(); return nil } catch { return error }
        }
        // Moves events into a separate stream. The client stream stays open even if a timeout cancels a wait.
        if observes {
            let (stream, continuation) = AsyncStream.makeStream(of: ControlClient.Event.self)
            observed = stream
            Task {
                for await event in client.events { continuation.yield(event) }
                continuation.finish()
            }
        } else {
            observed = nil
        }
    }

    func next(_ description: String, timeout: Duration = .seconds(5)) async throws -> ControlClient.Event {
        guard let observed else { throw GateFailure("Client without event observation") }
        return try await nextEvent(observed, waitingFor: description, timeout: timeout)
    }

    /// Waits for the next `registered` event. Skips intervening netmap and disconnected events.
    func registered(_ description: String, timeout: Duration = .seconds(5)) async throws -> NodePublicKey {
        let deadline = ContinuousClock.now + timeout
        while true {
            switch try await next(description, timeout: ContinuousClock.now.duration(to: deadline)) {
            case .registered(let key): return key
            case .loginRequired: throw GateFailure("\(description): unexpected loginRequired")
            case .netmap, .disconnected: continue
            }
        }
    }

    private enum Outcome: Sendable {
        case ended(ControlError?)
        case timedOut
    }

    /// Waits for `run()` to finish. Cancels first if `cancelling` is set. Throws a failure if it does not finish.
    func result(timeout: Duration = .seconds(5), cancelling: Bool = false) async throws -> ControlError? {
        if cancelling { running.cancel() }
        let running = running
        let outcome = await withTaskGroup(of: Outcome.self) { group in
            group.addTask { .ended(await running.value) }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return .timedOut
            }
            let first = await group.next() ?? .timedOut
            // The group waits for remaining children before it ends, so on timeout, cancel run() first to release that child.
            if case .timedOut = first { running.cancel() }
            group.cancelAll()
            return first
        }
        guard case .ended(let error) = outcome else { throw GateFailure("run() did not finish within \(timeout)") }
        return error
    }

    /// Cancels `run()` and waits for it to finish.
    func stop() async {
        running.cancel()
        _ = await running.value
    }
}
