// 시험 안의 루프백 리스너. `Tests/SwiftailIOTests/NetworkSocketLoopbackTests.swift`의 것에 다리의 프로토콜과 TLS를 넣을 수
// 있게 한 것이다(시험 타깃끼리는 코드를 나눌 수 없다). 다리의 루프백 쪽 상대로 쓴다.

import Foundation
import Network
import Synchronization
@testable import SwiftailLoopback

/// 시험 안의 루프백 리스너(`127.0.0.1`, 포트는 시스템이 고른다). 받은 연결을 차례로 내준다.
///
/// `bridge`를 주면 그 다리의 프로토콜을 스택의 끝(TLS 아래)에 넣는다. 첫 사용처의 서버가 하는 그대로다.
final class PlainLoopbackServer: Sendable {
    let port: UInt16
    private let listener: NWListener
    private let accepted: AsyncStream<NWConnection>
    private let all = Mutex<[NWConnection]>([])
    private let acceptCount: AcceptCount

    /// 리스너가 받은 연결 수. `next()`로 꺼내지 않은 것도 센다.
    var acceptedCount: Int { acceptCount.value.withLock { $0 } }

    private final class AcceptCount: Sendable {
        let value = Mutex(0)
    }

    private init(listener: NWListener, port: UInt16, accepted: AsyncStream<NWConnection>, acceptCount: AcceptCount) {
        self.listener = listener
        self.port = port
        self.accepted = accepted
        self.acceptCount = acceptCount
    }

    static func start(admittingFor bridge: LoopbackBridge? = nil, tls: NWProtocolTLS.Options? = nil) async throws -> PlainLoopbackServer {
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        if let bridge {
            parameters.defaultProtocolStack.applicationProtocols.append(bridge.makeListenerProtocolOptions())
        }
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        let acceptCount = AcceptCount()
        listener.newConnectionHandler = { connection in
            acceptCount.value.withLock { $0 += 1 }
            sink.yield(connection)
        }
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
        return PlainLoopbackServer(listener: listener, port: port, accepted: accepted, acceptCount: acceptCount)
    }

    /// 잠깐 열었다 닫은 포트. 곧바로 다른 것이 차지하지 않는 한 듣는 쪽이 없다.
    static func unusedPort() async throws -> UInt16 {
        let server = try await start()
        server.close()
        try await Task.sleep(for: .milliseconds(50))
        return server.port
    }

    /// 다음으로 받은 연결. 준비될 때까지 기다린다. 준비되지 않고 끝나면 던진다.
    func next() async throws -> PeerConnection {
        switch await nextOutcome() {
        case .ready(let peer): return peer
        case .failed(let error): throw PeerConnection.NotReady(description: error)
        }
    }

    /// 다음으로 받은 연결이 준비되었는가, 준비되지 않고 끝났는가.
    func nextOutcome() async -> PeerConnection.Outcome {
        guard let connection = await nextConnection() else { return .failed("리스너가 닫혔다") }
        return await PeerConnection.start(connection)
    }

    /// 다음으로 받은 연결을 시작하지 않고 내준다(서버가 `newConnectionHandler`에서 받은 그대로).
    func nextConnection() async -> NWConnection? {
        for await connection in accepted {
            all.withLock { $0.append(connection) }
            return connection
        }
        return nil
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

    /// 받은 연결을 시작한 결과.
    enum Outcome: Sendable {
        case ready(PeerConnection)
        /// 준비되지 않고 끝났다. 그 까닭.
        case failed(String)
    }

    struct NotReady: Error, CustomStringConvertible {
        var description: String
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

    /// 연결을 시작하고 준비되거나 끝날 때까지 기다린다. 기다리던 Task가 취소되면 연결을 닫는다.
    static func start(_ connection: NWConnection) async -> Outcome {
        let (states, sink) = AsyncStream.makeStream(of: Outcome?.self)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard case .hostPort(_, let port) = connection.endpoint else {
                    sink.yield(.failed("끝점이 없다"))
                    return
                }
                sink.yield(.ready(PeerConnection(connection: connection, remotePort: port.rawValue)))
            case .failed(let error): sink.yield(.failed("\(error)"))
            case .cancelled: sink.yield(.failed("취소됨"))
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "test.peer"))
        return await withTaskCancellationHandler {
            for await outcome in states { if let outcome { return outcome } }
            return .failed("취소됨")
        } onCancel: {
            connection.cancel()
        }
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
