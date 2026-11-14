import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailControl

/// 물러나는 동안(`run()`의 재시도 대기)에 `setNetworkInterface`가 오면 기다리지 않고 곧바로 다시 잇는지.
/// 서버가 살아 있는 연결 위의 재연결은 `Tests/SwiftailControlInteropTests/ControlNetworkInterfaceTests.swift`가 본다.
@Suite("제어 클라이언트: 물러나는 중의 인터페이스 변경", .timeLimit(.minutes(1)))
struct ControlClientBackoffInterfaceTests {
    /// 고치기 전에는 대기 시간(연속 12번째 실패 뒤 0.72초 이상)이 끝날 때까지 다시 잇지 않았다.
    @Test("실패해서 물러나는 중에 인터페이스가 바뀌면 대기를 마치지 않고 곧바로 다시 잇는다")
    func interfaceChangeInterruptsBackoff() async throws {
        let server = try FailingKeyServer()
        defer { server.close() }
        let interface = try #require(await loopbackInterface(), "루프백 인터페이스가 없다")
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-backoff-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let client = ControlClient(
            configuration: .init(serverURL: try #require(URL(string: "http://127.0.0.1:\(try await server.port())")), hostname: "rd-mac-1a2b3c4d"),
            identityStore: NodeIdentityStore(directory: directory)
        )
        let running = Task { try await client.run() }
        defer { running.cancel() }

        // 연속 n번째 실패 뒤의 대기는 n² × 10ms × [0.5, 1.5)이다. 12번째 시도 뒤에는 0.72초 이상 기다린다.
        try await server.waitForAttempts(12, within: .seconds(30))
        let before = server.attempts
        await client.setNetworkInterface(interface)
        let start = ContinuousClock.now
        try await server.waitForAttempts(before + 1, within: .seconds(10))
        let elapsed = ContinuousClock.now - start
        #expect(elapsed < .milliseconds(400), "물러나던 대기를 끝까지 기다렸다: \(elapsed)")
    }
}

private func loopbackInterface() async -> NWInterface? {
    let monitor = NWPathMonitor(requiredInterfaceType: .loopback)
    defer { monitor.cancel() }
    for await path in monitor { return path.availableInterfaces.first }
    return nil
}

/// `GET /key`에 500으로 답하고 연결을 닫는 루프백 서버. 연결을 받은 횟수를 센다(시도마다 하나다).
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
                Issue.record("\(duration) 안에 시도가 \(expected)번에 이르지 않았다: \(attempts)")
                throw CancellationError()
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    func close() {
        listener.cancel()
    }
}
