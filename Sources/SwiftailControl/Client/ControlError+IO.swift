import SwiftailIO

// `SwiftailIO`의 오류를 제어 클라이언트의 오류로 옮긴다. 소켓과 타임아웃의 실패는 모두 물러났다가 다시 시도할
// 연결 실패(`ControlError.connection`)다.

extension ControlError {
    init(_ error: SocketError) {
        switch error {
        case .connectFailed(let message), .readFailed(let message), .bindFailed(let message), .sendFailed(let message):
            self = .connection(message)
        }
    }
}

extension NetworkSocket {
    /// 제어 서버에 연결한다. TLS면 시스템 인증서 검증으로 `host`를 확인한다.
    static func connect(to endpoint: ControlEndpoint) async throws(ControlError) -> NetworkSocket {
        let tls: TLS = endpoint.usesTLS ? .system(serverName: endpoint.host) : .none
        do {
            return try await connect(host: endpoint.host, port: endpoint.port, tls: tls)
        } catch {
            throw ControlError(error)
        }
    }

    /// 도착한 바이트를 받는다. 상대가 연결을 닫았으면 nil.
    func receiveBytes() async throws(ControlError) -> [UInt8]? {
        do {
            return try await receive()
        } catch {
            throw ControlError(error)
        }
    }
}

/// `SwiftailIO.withTimeout`에 기한을 넘기면 `ControlError.connection`을 던지게 한 것.
func withControlTimeout<Result: Sendable>(
    _ duration: Duration,
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    do {
        return try await withTimeout(duration, operation)
    } catch is TimeoutError {
        throw ControlError.connection("\(duration) 안에 끝나지 않았다")
    }
}
