import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailControl

@Suite("소켓의 취소")
struct NetworkSocketTests {
    /// 취소 처리기와 연결 시작의 순서에 따라 드물게(수 %) 끝나지 않던 경로라 여러 번 되풀이한다.
    @Test("이미 취소된 Task에서 연결을 시작하면 곧바로 실패한다")
    func connectInCancelledTask() async throws {
        for _ in 0..<100 {
            let outcome = try await finishes(within: .seconds(2), inCancelledTask: true) {
                do {
                    // 아무도 듣지 않는 포트. 취소가 없어도 거부로 끝나야 하는 연결이다.
                    let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: 1, usesTLS: false)
                    socket.close()
                    return "연결됨"
                } catch {
                    return "실패"
                }
            }
            #expect(outcome == "실패")
            if outcome != "실패" { return }
        }
    }

    @Test("이미 취소된 Task에서 받기를 시작하면 곧바로 실패한다")
    func receiveInCancelledTask() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), usesTLS: false)
        defer { socket.close() }
        let outcome = try await finishes(within: .seconds(3), inCancelledTask: true) {
            do {
                return try await socket.receive() == nil ? "닫힘" : "받음"
            } catch {
                return "실패"
            }
        }
        #expect(outcome == "실패")
    }

    @Test("닫은 소켓에서 받기를 시작하면 곧바로 실패한다")
    func receiveAfterClose() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), usesTLS: false)
        socket.close()
        let outcome = try await finishes(within: .seconds(3)) {
            do {
                return try await socket.receive() == nil ? "닫힘" : "받음"
            } catch {
                return "실패"
            }
        }
        #expect(outcome != "받음")
    }
}

/// `operation`이 `duration` 안에 끝나는지 본다. 끝나지 않으면 시험 실패로 던진다.
/// 끝나지 않는 continuation은 취소해도 풀리지 않으므로, 그 Task는 기다리지 않고 남긴다(시험 프로세스가 끝나면 사라진다).
/// `inCancelledTask`면 Task를 취소한 뒤에 `operation`을 시작한다.
private func finishes(
    within duration: Duration,
    inCancelledTask: Bool = false,
    _ operation: @escaping @Sendable () async -> String
) async throws -> String {
    let (stream, continuation) = AsyncStream.makeStream(of: String?.self)
    let work = Task {
        if inCancelledTask {
            // 취소될 때까지 기다린다. 깨어난 뒤에도 Task는 취소된 상태다.
            try? await Task.sleep(for: .seconds(3_600))
        }
        continuation.yield(await operation())
    }
    if inCancelledTask { work.cancel() }
    let timer = Task {
        try? await Task.sleep(for: duration)
        continuation.yield(nil)
    }
    defer {
        work.cancel()
        timer.cancel()
    }
    for await result in stream {
        guard let result else {
            Issue.record("\(duration) 안에 끝나지 않았다")
            return "끝나지 않음"
        }
        return result
    }
    return "끝나지 않음"
}

/// 루프백에서 연결을 받아 쥐고만 있는 리스너. 아무것도 보내지 않는다.
private final class LoopbackListener: Sendable {
    private let listener: NWListener
    private let accepted = Accepted()

    private final class Accepted: Sendable {
        let connections = Mutex<[NWConnection]>([])
    }

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [accepted] connection in
            connection.start(queue: .global())
            accepted.connections.withLock { $0.append(connection) }
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

    func close() {
        listener.cancel()
        accepted.connections.withLock { connections in
            for connection in connections { connection.cancel() }
            connections = []
        }
    }
}
