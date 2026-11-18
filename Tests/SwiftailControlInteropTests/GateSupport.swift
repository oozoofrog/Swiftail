import Foundation
import SwiftailBase
import SwiftailControl
import Testing

let tailnetBinary = ProcessInfo.processInfo.environment["SWIFTAIL_TAILNET"].flatMap { $0.isEmpty ? nil : $0 }

struct GateFailure: Error, Sendable, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Races events against a deadline. A timeout ends the test, so a canceled subscription is not reused.
func nextEvent<T: Sendable>(
    _ stream: AsyncStream<T>, waitingFor description: String, timeout: Duration = .seconds(20)
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        defer { group.cancelAll() }
        group.addTask {
            for await event in stream { return event }
            throw GateFailure("Event stream ended while waiting for \(description)")
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw GateFailure("\(description) timed out (\(timeout))")
        }
        guard let event = try await group.next() else { throw GateFailure("No event for \(description)") }
        return event
    }
}

/// Keeps private keys, auth keys, and user paths out of the report even if external tool diagnostics contain them.
func redacted(_ text: String) -> String {
    var result = text
    for pattern in [#"(?:privkey|nodekey|discokey|mkey):[0-9a-fA-F]+"#, #"tskey-[A-Za-z0-9_-]+"#,
                    #"/Users/[^\s\"']+"#, #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#] {
        result = result.replacingOccurrences(of: pattern, with: "<redacted>", options: .regularExpression)
    }
    return result
}

/// Observes only public events without accessing internal state or the transport implementation.
struct GateClient: Sendable {
    enum Observation: Sendable {
        case event(ControlClient.Event)
        case failed(ControlError)
        case ended
        case observationEnded
    }

    let client: ControlClient
    private let running: Task<ControlError?, Never>
    private let collecting: Task<Void, Never>
    private let observations: AsyncStream<Observation>
    private let observationContinuation: AsyncStream<Observation>.Continuation

    init(serverURL: URL, directory: URL, authKey: String? = nil) {
        let client = ControlClient(
            configuration: .init(serverURL: serverURL, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            identityStore: NodeIdentityStore(directory: directory)
        )
        self.client = client
        let (stream, continuation) = AsyncStream.makeStream(of: Observation.self)
        observations = stream
        observationContinuation = continuation
        let running = Task<ControlError?, Never> {
            do { try await client.run(); return nil }
            catch let error as ControlError { return error }
            catch { return .connection("Unexpected run error: \(redacted(String(describing: error)))") }
        }
        self.running = running
        collecting = Task {
            for await event in client.events { continuation.yield(.event(event)) }
            if let error = await running.value { continuation.yield(.failed(error)) }
            else { continuation.yield(.ended) }
            continuation.finish()
        }
    }

    func next(_ description: String, timeout: Duration = .seconds(20)) async throws -> Observation {
        try await nextEvent(observations, waitingFor: description, timeout: timeout)
    }

    func registered() async throws -> NodePublicKey {
        switch try await next("Registration complete (server key lookup → upgrade → Noise → HTTP/2).") {
        case .event(.registered(let key)): return key
        case let other: throw unexpected(other, during: "Registration complete")
        }
    }

    func netmap(
        _ description: String = "First netmap", timeout: Duration = .seconds(20),
        matching predicate: @Sendable (Netmap) -> Bool = { _ in true }
    ) async throws -> Netmap {
        let deadline = ContinuousClock.now + timeout
        var received = 0
        while true {
            switch try await next("\(description), \(received) netmaps observed", timeout: ContinuousClock.now.duration(to: deadline)) {
            case .event(.netmap(let map)):
                received += 1
                if predicate(map) { return map }
            case let other: throw unexpected(other, during: description)
            }
        }
    }

    /// KeepAlive is not a public event. Rejects any re-registration, disconnected event, or termination during the observation period.
    func remainsConnected(until deadline: ContinuousClock.Instant) async throws {
        let continuation = observationContinuation
        let timer = Task {
            do {
                try await Task.sleep(until: deadline, clock: .continuous)
                continuation.yield(.observationEnded)
            } catch {}
        }
        defer { timer.cancel() }
        while true {
            switch try await next("125 seconds of stream uptime beyond KeepAlive", timeout: .seconds(140)) {
            case .observationEnded: return
            case .event(.netmap): continue
            case let other: throw unexpected(other, during: "125 seconds of stream uptime")
            }
        }
    }

    func stop() async {
        running.cancel()
        _ = await running.value
        await collecting.value
    }

    private func unexpected(_ observation: Observation, during stage: String) -> GateFailure {
        let actual: String
        switch observation {
        case .event(.loginRequired): actual = "loginRequired"
        case .event(.registered): actual = "Unexpected re-registration"
        case .event(.netmap): actual = "netmap"
        case .event(.disconnected): actual = "disconnected"
        case .failed(let error): actual = redacted(String(describing: error))
        case .ended: actual = "run() ended"
        case .observationEnded: actual = "Observation ended"
        }
        return GateFailure("\(stage): received \(actual) instead of the expected event")
    }
}

/// Removes the identity directory and reaps the Go process on success, failure, or cancellation.
func withTailnet(_ body: (GoTailnet, GoTailnet.Event, URL) async throws -> Void) async throws {
    let tool = GoTailnet()
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m2-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }
    do {
        let ready = try await tool.start()
        try await body(tool, ready, directory)
        await tool.stop()
    } catch {
        await tool.stop()
        throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
    }
}

func withClient(
    ready: GoTailnet.Event, directory: URL, authKey: String? = nil,
    _ body: (GateClient) async throws -> Void
) async throws {
    let url = try #require(ready.controlURL)
    let client = GateClient(serverURL: url, directory: directory, authKey: authKey)
    do {
        try await body(client)
        await client.stop()
    } catch {
        await client.stop()
        throw error
    }
}
