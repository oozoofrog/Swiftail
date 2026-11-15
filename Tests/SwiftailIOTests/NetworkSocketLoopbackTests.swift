import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailIO

/// 루프백 다리가 쓰는 소켓 보탬(계약 `docs/contracts/SwiftailHost.md` 8절, 동작 B4·B5·B6, 첫 사용처 검토 결과 7).
///
/// 상대는 시험 안의 평문 `NWListener`다. 상대가 본 끝이 "깨끗한 EOF"(오류 없이 `isComplete`)인지 오류인지를 견준다.
@Suite("소켓의 루프백 보탬", .timeLimit(.minutes(1)))
struct NetworkSocketLoopbackTests {
    @Test("준비된 소켓의 localPort는 리스너가 본 출발 포트다")
    func localPortMatchesListenerView() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        for _ in 0..<5 {
            let socket = try await NetworkSocket.connectLoopback(port: server.port)
            defer { socket.close() }
            let accepted = try await server.next()
            let localPort = try #require(socket.localPort)
            #expect(localPort != 0)
            #expect(accepted.remotePort == localPort)
        }
    }

    @Test("finishWriting 뒤 상대는 깨끗한 EOF를 보고, 반대 방향은 계속 간다")
    func finishWritingHalfCloses() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.close() }
        let accepted = try await server.next()

        #expect(await socket.writeAccepted(Array("request".utf8)))
        socket.finishWriting()
        #expect(await accepted.readToEnd() == .end(Array("request".utf8)))

        // FIN을 받은 쪽이 응답을 보낸다.
        let response = [UInt8](repeating: 0x5A, count: 300_000)
        try await accepted.send(response, final: true)
        var received: [UInt8] = []
        while let chunk = try await socket.receive() { received += chunk }
        #expect(received == response)
    }

    /// `NWConnection`은 마지막 바이트와 끝을 한 번에 알리고, 그 뒤의 받기는 `ENODATA` 오류로 끝낸다. 고치기 전에는
    /// 정상 닫기가 `readFailed`로 보였다.
    @Test("끝(FIN)이 마지막 바이트와 함께 와도 그 뒤의 receive는 nil이다")
    func endArrivingWithLastBytes() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.close() }
        let peer = try await server.next()
        try await peer.send([1, 2, 3], final: true)
        // 바이트와 FIN이 다 도착한 뒤에 받는다.
        try await Task.sleep(for: .milliseconds(100))
        #expect(try await socket.receive() == [1, 2, 3])
        #expect(try await socket.receive() == nil)
        #expect(try await socket.receive() == nil)
    }

    /// 시험 도우미(`PeerConnection.read`)의 시험. 고치기 전에는 마지막 바이트와 함께 온 끝을 놓쳐 다음 받기가 `ENODATA`로
    /// 실패했고, 부하에서 다리 시험이 흔들렸다.
    @Test("시험 서버: 끝(FIN)이 마지막 바이트와 함께 와도 readToEnd는 깨끗한 EOF로 끝난다")
    func peerSeesEndArrivingWithLastBytes() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.close() }
        let peer = try await server.next()
        #expect(await socket.writeAccepted([1, 2, 3]))
        socket.finishWriting()
        // 바이트와 FIN이 다 도착한 뒤에 받는다.
        try await Task.sleep(for: .milliseconds(100))
        #expect(await peer.readToEnd() == .end([1, 2, 3]))
    }

    @Test("abort는 상대에게 오류(RST)로 보이고, close는 깨끗한 EOF로 보인다")
    func abortResetsAndCloseFinishes() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }

        let aborted = try await NetworkSocket.connectLoopback(port: server.port)
        let abortedPeer = try await server.next()
        #expect(await aborted.writeAccepted([1, 2, 3]))
        // 상대가 앞의 바이트를 받은 뒤에 끊는다(받기 전에 끊으면 바이트가 버려질 수 있다).
        #expect(await abortedPeer.read() == .bytes([1, 2, 3]))
        aborted.abort()
        // forceCancel이 RST를 낸다: 상대의 읽기가 ECONNRESET으로 끝난다(2026-11 macOS에서 확인).
        guard case .failed(_, let error) = await abortedPeer.readToEnd() else {
            Issue.record("abort 뒤 상대의 읽기가 오류로 끝나지 않았다")
            return
        }
        #expect(error.contains("Connection reset"), "\(error)")

        let closed = try await NetworkSocket.connectLoopback(port: server.port)
        let closedPeer = try await server.next()
        #expect(await closed.writeAccepted([4, 5, 6]))
        closed.close()
        #expect(await closedPeer.readToEnd() == .end([4, 5, 6]))
    }

    @Test("기다리던 receive의 Task가 취소되어도 루프백 소켓은 닫히지 않는다")
    func cancelledReceiveKeepsConnection() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.abort() }
        let peer = try await server.next()
        let reader = Task { () -> String in
            do { return try await socket.receive() == nil ? "닫힘" : "받음" } catch { return "실패" }
        }
        try await Task.sleep(for: .milliseconds(50))
        reader.cancel()
        #expect(await reader.value == "실패")
        // 상대에게 끝이 오지 않는다. 쓰기는 여전히 간다.
        #expect(await socket.writeAccepted([7]))
        #expect(await peer.read(within: .milliseconds(300)) == .bytes([7]))
        #expect(await peer.read(within: .milliseconds(200)) == nil)
    }

    @Test("포트 0과 듣는 쪽이 없는 포트는 connectFailed다")
    func connectFailures() async throws {
        await #expect(throws: SocketError.connectFailed("포트가 잘못되었다")) {
            _ = try await NetworkSocket.connectLoopback(port: 0)
        }
        let closedPort = try await PlainLoopbackServer.unusedPort()
        do {
            let socket = try await NetworkSocket.connectLoopback(port: closedPort)
            socket.close()
            Issue.record("듣는 쪽이 없는 포트에 붙었다")
        } catch {
            guard case .connectFailed = error else {
                Issue.record("connectFailed가 아니다: \(error)")
                return
            }
        }
    }
}

// MARK: 시험 서버

/// 시험 안의 평문 루프백 리스너(`127.0.0.1`, 포트는 시스템이 고른다). 받은 연결을 차례로 내준다.
final class PlainLoopbackServer: Sendable {
    let port: UInt16
    private let listener: NWListener
    private let accepted: AsyncStream<NWConnection>
    private let all = Mutex<[NWConnection]>([])

    private init(listener: NWListener, port: UInt16, accepted: AsyncStream<NWConnection>) {
        self.listener = listener
        self.port = port
        self.accepted = accepted
    }

    static func start() async throws -> PlainLoopbackServer {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        listener.newConnectionHandler = { connection in sink.yield(connection) }
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: DispatchQueue(label: "test.listener"))
        }
        return PlainLoopbackServer(listener: listener, port: port, accepted: accepted)
    }

    /// 잠깐 열었다 닫은 포트. 곧바로 다른 것이 차지하지 않는 한 듣는 쪽이 없다.
    static func unusedPort() async throws -> UInt16 {
        let server = try await start()
        server.close()
        try await Task.sleep(for: .milliseconds(50))
        return server.port
    }

    /// 다음으로 받은 연결. 준비될 때까지 기다린다.
    func next() async throws -> PeerConnection {
        for await connection in accepted {
            all.withLock { $0.append(connection) }
            return try await PeerConnection.start(connection)
        }
        throw CancellationError()
    }

    func close() {
        listener.cancel()
        all.withLock { connections in
            for connection in connections { connection.cancel() }
            connections = []
        }
    }
}

/// 리스너가 받은 연결 하나.
struct PeerConnection: Sendable {
    /// 한 번의 받기 결과.
    enum Received: Equatable, Sendable {
        case bytes([UInt8])
        /// 오류 없이 끝났다(FIN). 그 전까지 받은 바이트.
        case end([UInt8])
        /// 오류로 끝났다(RST 등). 그 전까지 받은 바이트 수.
        case failed(received: Int, error: String)
    }

    /// 상대의 끝(FIN)이 마지막 바이트와 함께 왔다. `NWConnection`은 끝을 한 번만 알리고 그 뒤의 받기를 `ENODATA`로
    /// 끝내므로, 그 바이트를 돌려준 뒤의 `read()`는 이것을 보고 `.end`를 돌려준다.
    private final class EndSeen: Sendable {
        let value = Mutex(false)
    }

    let connection: NWConnection
    /// 상대(다리 쪽 소켓)의 출발 포트.
    let remotePort: UInt16
    private let endSeen = EndSeen()

    /// 연결을 시작하고 준비될 때까지 기다린다. 기다리던 Task가 취소되면 연결을 닫는다(기다림이 오류로 풀린다).
    static func start(_ connection: NWConnection) async throws -> PeerConnection {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let once = Mutex<CheckedContinuation<Void, any Error>?>(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.withLock { $0.take() }?.resume()
                    case .failed(let error): once.withLock { $0.take() }?.resume(throwing: error)
                    case .cancelled: once.withLock { $0.take() }?.resume(throwing: CancellationError())
                    default: break
                    }
                }
                connection.start(queue: DispatchQueue(label: "test.peer"))
            }
        } onCancel: {
            connection.cancel()
        }
        guard case .hostPort(_, let port) = connection.endpoint else { throw CancellationError() }
        return PeerConnection(connection: connection, remotePort: port.rawValue)
    }

    /// 한 번 받는다. 끝이면 `.end([])`. 기다리던 Task가 취소되면 연결을 닫는다(받기가 오류로 풀린다).
    func read() async -> Received {
        if endSeen.value.withLock({ $0 }) { return .end([]) }
        let endSeen = endSeen
        let connection = connection
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Received, Never>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, isComplete, error in
                    if let data, !data.isEmpty {
                        if isComplete { endSeen.value.withLock { $0 = true } }
                        continuation.resume(returning: .bytes([UInt8](data)))
                    } else if let error {
                        continuation.resume(returning: .failed(received: 0, error: "\(error)"))
                    } else if isComplete {
                        continuation.resume(returning: .end([]))
                    } else {
                        continuation.resume(returning: .bytes([]))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    /// `duration` 안에 한 번 받는다. 그 안에 아무것도 오지 않으면 nil. 걸어 둔 받기는 남는다(다음 바이트를 가져간다).
    func read(within duration: Duration) async -> Received? {
        let (stream, sink) = AsyncStream.makeStream(of: Received?.self)
        // 받기를 맡은 Task는 취소하지 않는다(취소하면 연결이 닫힌다).
        Task { sink.yield(await read()) }
        let timer = Task {
            try? await Task.sleep(for: duration)
            sink.yield(nil)
        }
        defer { timer.cancel() }
        for await result in stream { return result }
        return nil
    }

    /// 끝날 때까지 받는다.
    func readToEnd() async -> Received {
        var received: [UInt8] = []
        while true {
            switch await read() {
            case .bytes(let bytes): received += bytes
            case .end: return .end(received)
            case .failed(_, let error): return .failed(received: received.count, error: error)
            }
        }
    }

    /// 보내고 네트워크 스택이 받아 갈 때까지 기다린다. `final`이면 쓰기 방향을 닫는다(FIN).
    func send(_ bytes: [UInt8], final: Bool) async throws {
        let connection = connection
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                connection.send(
                    content: Data(bytes), contentContext: final ? .finalMessage : .defaultMessage, isComplete: true,
                    completion: .contentProcessed { error in
                        if let error { continuation.resume(throwing: error) } else { continuation.resume() }
                    })
            }
        } onCancel: {
            connection.cancel()
        }
    }
}
