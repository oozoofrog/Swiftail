import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailIO

@Suite("소켓의 취소")
struct NetworkSocketTests {
    /// 취소 처리기와 연결 시작의 순서에 따라 드물게(수 %) 끝나지 않던 경로라 여러 번 되풀이한다.
    @Test("이미 취소된 Task에서 연결을 시작하면 곧바로 실패한다")
    func connectInCancelledTask() async throws {
        for _ in 0..<100 {
            let outcome = try await finishes(within: .seconds(2), inCancelledTask: true) {
                do {
                    // 아무도 듣지 않는 포트. 취소가 없어도 거부로 끝나야 하는 연결이다.
                    let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: 1, tls: .none)
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
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
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
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
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

    /// 고치기 전에는 보내기가 기다리지 않아 `NWConnection`의 버퍼가 끝없이 자랐다(256MiB를 보내자 RSS가 수백 MB).
    @Test("읽지 않는 상대에게 write는 막히고, 막히기 전까지 받아 간 양은 상한이 있다")
    func writeBlocksWhenPeerDoesNotRead() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
        defer { socket.close() }
        let chunk = [UInt8](repeating: 0xA5, count: 64 << 10)
        let attemptLimit = 256 << 20
        var accepted = 0
        var blocked = false
        while accepted < attemptLimit {
            do {
                try await withTimeout(.milliseconds(500)) { await socket.write(chunk) }
                accepted += chunk.count
            } catch {
                blocked = true
                break
            }
        }
        #expect(blocked)
        // 루프백의 커널 버퍼(보내는 쪽과 받는 쪽)만큼은 들어간다. 그보다 훨씬 큰 32MiB를 넘지 않는다.
        #expect(accepted < 32 << 20)
    }

    @Test("버린 소켓은 연결을 닫는다")
    func droppedSocketCloses() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        var socket: NetworkSocket? = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
        #expect(socket != nil)
        let accepted = try await listener.firstConnection()
        socket = nil
        let outcome = try await finishes(within: .seconds(3)) {
            await Self.waitUntilClosed(accepted) ? "닫힘" : "받음"
        }
        #expect(outcome == "닫힘")
    }

    // MARK: 인터페이스 묶기

    @Test("루프백 인터페이스로 묶어도 루프백 서버에 붙는다")
    func connectBoundToLoopbackInterface() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let loopback = try #require(await currentInterfaces(of: .loopback).first, "루프백 인터페이스가 없다")
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none, interface: loopback)
        defer { socket.close() }
        _ = try await listener.firstConnection()
    }

    /// 묶은 인터페이스가 실제로 쓰인다는 증거다. 묶이지 않았다면 루프백 서버에 붙었을 것이다.
    @Test("맞지 않는 인터페이스로 묶으면 루프백 서버에 붙지 못한다")
    func connectBoundToWrongInterfaceFails() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let other = try #require(await currentInterfaces(of: nil).first { $0.type != .loopback }, "루프백이 아닌 인터페이스가 없다")
        let port = try await listener.port()
        let outcome = try await finishes(within: .seconds(10)) {
            do {
                let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: port, tls: .none, interface: other)
                socket.close()
                return "연결됨"
            } catch {
                return "실패"
            }
        }
        #expect(outcome == "실패")
    }

    @Test("루프백 목적지는 묶을 인터페이스를 거르고, 그 밖의 목적지는 그대로 둔다")
    func bindableInterfaceSkipsLoopbackDestinations() async throws {
        let interface = try #require(await currentInterfaces(of: .loopback).first, "루프백 인터페이스가 없다")
        for host in ["127.0.0.1", "127.1.2.3", "::1", "localhost", "LOCALHOST", "localhost6", "ip6-loopback", "ip6-localhost"] {
            #expect(NetworkSocket.bindableInterface(interface, forHost: host) == nil, "\(host)")
        }
        for host in ["192.0.2.1", "128.0.0.1", "126.255.255.255", "127.0.0", "127.0.0.1.5", "2001:db8::1", "controlplane.example.test", ""] {
            #expect(NetworkSocket.bindableInterface(interface, forHost: host) == interface, "\(host)")
        }
        #expect(NetworkSocket.bindableInterface(nil, forHost: "192.0.2.1") == nil)
    }

    /// 상대가 닫을 때까지 읽는다. 닫혔거나 실패했으면 true, 바이트가 오면 false.
    private static func waitUntilClosed(_ connection: NWConnection) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { data, _, isComplete, error in
                continuation.resume(returning: (data?.isEmpty ?? true) && (isComplete || error != nil))
            }
        }
    }
}

/// 지금 경로의 인터페이스. `type`이 nil이면 기본 경로의 것이고, 아니면 그 종류의 것이다.
private func currentInterfaces(of type: NWInterface.InterfaceType?) async -> [NWInterface] {
    let monitor = type.map { NWPathMonitor(requiredInterfaceType: $0) } ?? NWPathMonitor()
    defer { monitor.cancel() }
    for await path in monitor {
        return path.availableInterfaces
    }
    return []
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

    /// 처음 받아들인 연결. 아직 없으면 올 때까지 기다린다.
    func firstConnection() async throws -> NWConnection {
        for _ in 0..<300 {
            if let first = accepted.connections.withLock({ $0.first }) { return first }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw CancellationError()
    }

    func close() {
        listener.cancel()
        accepted.connections.withLock { connections in
            for connection in connections { connection.cancel() }
            connections = []
        }
    }
}
