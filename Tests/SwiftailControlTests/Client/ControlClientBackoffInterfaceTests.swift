import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailControl

/// Checks that `setNetworkInterface` during backoff (the retry wait in `run()`) reconnects immediately without waiting.
/// `Tests/SwiftailControlInteropTests/ControlNetworkInterfaceTests.swift` covers reconnecting over a live server connection.
@Suite("Control client: Interface change during backoff", .timeLimit(.minutes(1)))
struct ControlClientBackoffInterfaceTests {
    /// Before the fix, reconnection waited for the backoff to expire (at least 0.72 seconds after the 12th consecutive failure).
    @Test("An interface change during backoff after a failure reconnects immediately without finishing the wait")
    func interfaceChangeInterruptsBackoff() async throws {
        let server = try FailingKeyServer()
        defer { server.close() }
        let interface = try #require(await loopbackInterface(), "No loopback interface")
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-backoff-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let client = ControlClient(
            configuration: .init(serverURL: try #require(URL(string: "http://127.0.0.1:\(try await server.port())")), hostname: "rd-mac-1a2b3c4d"),
            identityStore: NodeIdentityStore(directory: directory)
        )
        let running = Task { try await client.run() }
        defer { running.cancel() }

        // The wait after the nth consecutive failure is n² × 10ms × [0.5, 1.5). After the 12th attempt, the wait is at least 0.72 seconds.
        try await server.waitForAttempts(12, within: .seconds(30))
        let before = server.attempts
        await client.setNetworkInterface(interface)
        let start = ContinuousClock.now
        try await server.waitForAttempts(before + 1, within: .seconds(10))
        let elapsed = ContinuousClock.now - start
        #expect(elapsed < .milliseconds(400), "Waited for the entire backoff: \(elapsed)")
    }
}

private func loopbackInterface() async -> NWInterface? {
    let monitor = NWPathMonitor(requiredInterfaceType: .loopback)
    defer { monitor.cancel() }
    for await path in monitor { return path.availableInterfaces.first }
    return nil
}

/// A loopback server that answers `GET /key` with 500 and closes the connection. Counts accepted connections (one per attempt).
private final class FailingKeyServer: Sendable {
    private final class Counter: Sendable {
        let value = Mutex(0)
    }

    private let listener: NWListener
    private let count = Counter()

    var attempts: Int { count.value.withLock { $0 } }

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [count] connection in
            count.value.withLock { $0 += 1 }
            connection.start(queue: .global())
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
            }
        }
    }

    func port() async throws -> UInt16 {
        let listener = listener
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue {
                        once.withLock { $0.take() }?.resume(returning: port)
                    }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
    }

    func waitForAttempts(_ expected: Int, within duration: Duration) async throws {
        let deadline = ContinuousClock.now + duration
        while attempts < expected {
            guard ContinuousClock.now < deadline else {
                Issue.record("Attempts did not reach \(expected) within \(duration): \(attempts)")
                throw CancellationError()
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    func close() {
        listener.cancel()
    }
}
