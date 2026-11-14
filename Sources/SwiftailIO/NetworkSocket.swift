import Foundation
import Network
import Synchronization

/// TCP(또는 TLS) 연결 하나를 async 바이트 스트림으로 감싼다.
///
/// 제어 서버(`SwiftailControl`)와 DERP 서버(`SwiftailDERP`)가 함께 쓴다. 실패는 `SocketError`로 내고,
/// 부르는 쪽이 자기 오류 타입으로 옮긴다.
///
/// Network 프레임워크의 `NWConnection`은 콜백으로 결과를 알린다. 콜백을 continuation으로 바꾸는 곳은 이 파일뿐이다.
/// 지키는 것:
///
/// - continuation은 정확히 한 번 재개한다. 상태 콜백은 여러 번 오므로 `ResumeOnce`로 첫 결과만 넘긴다.
/// - 기다리던 Task가 취소되면 continuation을 곧바로 오류로 풀고 연결을 닫는다. 이미 취소된 Task에서 부르면
///   취소 처리기가 continuation보다 먼저 돌므로, 그 결과를 `ResumeOnce`에 담아 두었다가 continuation을 다는
///   즉시 넘긴다(취소된 `NWConnection`의 콜백이 오리라고 기대하지 않는다).
/// - 보내기는 기다리지 않는다. `NWConnection`이 부른 순서대로 내보내므로 Noise 레코드의 순서(nonce 순서)가
///   지켜진다. 보내기 실패는 연결을 실패 상태로 만들고, 그 사실은 다음 `receive()`가 알린다.
///
/// 바이트의 경계는 뜻이 없다. TCP 조각을 그대로 돌려주고 레코드·프레임은 위 계층이 모은다.
package final class NetworkSocket: Sendable {
    private static let maximumReadSize = 64 << 10

    private let connection: NWConnection

    private init(connection: NWConnection) {
        self.connection = connection
    }

    /// 연결이 준비될 때까지 기다린다.
    package static func connect(host: String, port: UInt16, tls: TLS) async throws(SocketError) -> NetworkSocket {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw .connectFailed("포트가 잘못되었다")
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 10
        // ALPN은 비워 둔다. HTTP/2로 협상되면 HTTP/1.1 업그레이드를 할 수 없다(노트 control-transport 4.4).
        let parameters = NWParameters(tls: tls.options, tcp: tcp)
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let socket = NetworkSocket(connection: connection)
        let once = ResumeOnce<Void>()
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    guard once.install(continuation) else { return }
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            once.resume(with: .success(()))
                        case .waiting(let error), .failed(let error):
                            // 연결 거부 같은 실패에서 NWConnection은 waiting으로 머물며 다시 시도한다.
                            // 다시 시도는 위 계층의 물러나기가 맡으므로 여기서 실패로 끝낸다.
                            once.resume(with: .failure(SocketError.connectFailed("연결하지 못했다: \(error)")))
                        case .cancelled:
                            once.resume(with: .failure(SocketError.connectFailed("연결이 취소되었다")))
                        default:
                            break
                        }
                    }
                    connection.start(queue: DispatchQueue(label: "Swiftail.NetworkSocket"))
                }
            } onCancel: {
                once.resume(with: .failure(SocketError.connectFailed("연결이 취소되었다")))
                connection.cancel()
            }
        } catch {
            connection.cancel()
            throw error as? SocketError ?? .connectFailed("연결하지 못했다")
        }
        return socket
    }

    /// 바이트를 보낸다. 기다리지 않는다(형식 설명 참고).
    package func send(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in })
    }

    /// 도착한 바이트를 받는다. 상대가 연결을 닫았으면 nil.
    package func receive() async throws(SocketError) -> [UInt8]? {
        let connection = connection
        let once = ResumeOnce<[UInt8]?>()
        do {
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8]?, any Error>) in
                    guard once.install(continuation) else { return }
                    connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maximumReadSize) { data, _, isComplete, error in
                        if let data, !data.isEmpty {
                            once.resume(with: .success([UInt8](data)))
                        } else if let error {
                            once.resume(with: .failure(SocketError.readFailed("읽기 실패: \(error)")))
                        } else if isComplete {
                            once.resume(with: .success(nil))
                        } else {
                            once.resume(with: .success([]))
                        }
                    }
                }
            } onCancel: {
                once.resume(with: .failure(SocketError.readFailed("읽기가 취소되었다")))
                connection.cancel()
            }
        } catch {
            throw error as? SocketError ?? .readFailed("읽기 실패")
        }
    }

    /// 연결을 닫는다. 걸려 있던 `receive()`는 오류로 끝난다. 여러 번 불러도 된다.
    package func close() {
        connection.cancel()
    }
}

/// continuation을 정확히 한 번 재개하게 하는 상자. 콜백이 여러 번 와도 첫 결과만 넘긴다.
///
/// 결과가 continuation보다 먼저 올 수 있다(이미 취소된 Task에서는 취소 처리기가 본문보다 먼저 돈다).
/// 그때는 결과를 쥐고 있다가 `install`에서 넘긴다.
private final class ResumeOnce<Value: Sendable>: Sendable {
    private enum State {
        case empty
        case waiting(CheckedContinuation<Value, any Error>)
        case early(Result<Value, any Error>)
        case resumed
    }

    private let state = Mutex(State.empty)

    /// continuation을 단다. 결과가 이미 와서 곧바로 재개했으면 false다. 그때는 콜백을 걸지 않는다.
    func install(_ continuation: CheckedContinuation<Value, any Error>) -> Bool {
        let early: Result<Value, any Error>? = state.withLock { state in
            switch state {
            case .early(let result):
                state = .resumed
                return result
            case .empty:
                state = .waiting(continuation)
                return nil
            case .waiting, .resumed:
                return nil
            }
        }
        guard let early else { return true }
        continuation.resume(with: early)
        return false
    }

    func resume(with result: Result<Value, any Error>) {
        let waiting: CheckedContinuation<Value, any Error>? = state.withLock { state in
            switch state {
            case .waiting(let continuation):
                state = .resumed
                return continuation
            case .empty:
                state = .early(result)
                return nil
            case .early, .resumed:
                return nil
            }
        }
        waiting?.resume(with: result)
    }
}
