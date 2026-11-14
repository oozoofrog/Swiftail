import CryptoKit
import Foundation
import SwiftailBase
import SwiftailHTTP2
import SwiftailIO

/// 제어 서버와의 연결 하나: 소켓 위에 HTTP/1.1 업그레이드 → Noise → (early payload) → HTTP/2.
///
/// 각 계층은 자기 경계를 자기 상태 기계에서 모은다. TCP 조각은 `ControlSession`이 Noise 레코드로,
/// 레코드의 평문은 `EarlyPayloadParser`를 거쳐 `HTTP2ClientConnection`이 프레임으로 모은다. 맵 프레임은 그 위의
/// 응답 본문에서 `MapResponseFramer`가 모은다(`ControlClient`). 이 actor는 바이트를 옮기기만 한다.
///
/// 연결 하나에 요청 여럿(등록, 상태 올리기, 맵 스트림)을 다중화한다. 응답은 스트림마다
/// `AsyncThrowingStream`으로 흘려보내고, 읽기 루프(`readLoop`)가 소켓에서 받아 나눠 준다.
/// 수명은 `withConnection`의 범위와 같다. 범위를 벗어나면 읽기 루프를 취소하고 소켓을 닫는다.
///
/// `docs/protocol-notes/control-transport.md` 4.2, 4.4, 4.7, 6.3.
actor ControlConnection {
    /// 응답 스트림에 흘러오는 것.
    enum ResponsePart: Sendable {
        case head(status: Int, headers: [HeaderField])
        case data([UInt8])
    }

    typealias ResponseParts = AsyncThrowingStream<ResponsePart, any Error>

    /// 업그레이드부터 Noise response까지의 제한 시간. Go는 dial 5초와 핸드셰이크 5초를 쓴다.
    static let handshakeTimeout = Duration.seconds(10)

    nonisolated let authority: String
    private let socket: NetworkSocket
    private var session: ControlSession
    private var earlyPayload: EarlyPayloadParser? = EarlyPayloadParser()
    private var http2 = HTTP2ClientConnection()
    private var streams: [HTTP2StreamID: ResponseParts.Continuation] = [:]
    private var failure: ControlError?

    private init(socket: NetworkSocket, session: ControlSession, authority: String) {
        self.socket = socket
        self.session = session
        self.authority = authority
    }

    /// 연결을 맺고 `body`를 부른다. `body`가 돌아오거나 던지면, 또는 연결이 끊기면 연결을 닫는다.
    /// 연결이 끊기면 걸려 있던 응답 스트림은 모두 `ControlError.connection`으로 끝난다.
    static func withConnection<Result: Sendable>(
        to endpoint: ControlEndpoint,
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        _ body: @escaping @Sendable (ControlConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await withControlTimeout(handshakeTimeout) {
            try await open(endpoint, machineKey: machineKey, serverKey: serverKey)
        }
        defer { connection.close() }
        return try await withThrowingTaskGroup(of: Outcome<Result>.self) { group in
            defer { group.cancelAll() }
            group.addTask {
                do throws(ControlError) {
                    try await connection.readLoop()
                    return .readEnded(.connection("연결이 끝났다"))
                } catch {
                    return .readEnded(error)
                }
            }
            group.addTask { .finished(try await body(connection)) }

            // 연결이 끊겨도 곧바로 그 오류를 던지지 않는다. 서버가 응답을 보내자마자 닫으면, `body`가 이미 받은
            // 응답으로 낼 결론(등록 거절처럼 다시 시도해도 소용없는 오류)을 연결 오류가 앞질러 재시도로 바꾼다.
            // 끊기면 걸려 있던 응답 스트림이 모두 끝나므로 `body`는 곧 끝난다. 연결과 무관하게 잠든 `body`를
            // 한없이 기다리지 않게 유예만 둔다.
            var readFailure: ControlError?
            while let outcome = try await group.next() {
                switch outcome {
                case .finished(let result):
                    return result
                case .readEnded(let error):
                    readFailure = error
                    group.addTask {
                        try await Task.sleep(for: bodyGracePeriod, clock: .continuous)
                        return .graceExpired
                    }
                case .graceExpired:
                    throw readFailure ?? ControlError.connection("연결이 끝났다")
                }
            }
            throw readFailure ?? ControlError.connection("연결이 끝났다")
        }
    }

    /// 연결이 끊긴 뒤 `body`가 스스로 끝나기를 기다려 주는 시간.
    private static var bodyGracePeriod: Duration { .seconds(1) }

    private enum Outcome<Result: Sendable>: Sendable {
        case finished(Result)
        case readEnded(ControlError)
        case graceExpired
    }

    /// 업그레이드와 Noise 핸드셰이크를 마친 연결을 만든다. HTTP/2 프리페이스는 곧바로 보낸다
    /// (early payload를 기다리지 않는다. Go도 그렇다).
    private static func open(
        _ endpoint: ControlEndpoint,
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey
    ) async throws(ControlError) -> ControlConnection {
        let socket = try await NetworkSocket.connect(to: endpoint)
        do throws(ControlError) {
            var handshake = try transport { () throws(ControlTransportError) in
                try ControlHandshake(machineKey: machineKey, serverKey: serverKey)
            }
            socket.send(UpgradeRequest.bytes(host: endpoint.hostHeader, initiation: handshake.initiation))

            var upgrade = UpgradeResponseParser()
            var afterHead: [UInt8]?
            while afterHead == nil {
                guard let bytes = try await socket.receiveBytes() else {
                    throw .connection("업그레이드 응답 전에 서버가 연결을 닫았다")
                }
                afterHead = try transport { () throws(ControlTransportError) in try upgrade.receive(bytes) }
            }
            var pending = afterHead ?? []
            while true {
                let bytes = pending
                if let (session, remainder) = try transport({ () throws(ControlTransportError) in try handshake.receive(bytes) }) {
                    let connection = ControlConnection(socket: socket, session: session, authority: endpoint.authority)
                    try await connection.start(with: remainder)
                    return connection
                }
                // 서버는 핸드셰이크가 실패하면 error 메시지 없이 연결을 닫는다(노트 4.4의 3.6).
                guard let next = try await socket.receiveBytes() else {
                    throw .connection("Noise 핸드셰이크 중에 서버가 연결을 닫았다")
                }
                pending = next
            }
        } catch {
            socket.close()
            throw error
        }
    }

    private func start(with remainder: [UInt8]) throws(ControlError) {
        try flush()
        if !remainder.isEmpty { try process(sealed: remainder) }
    }

    /// 연결을 닫는다. 읽기 루프와 걸려 있던 응답 스트림은 오류로 끝난다.
    nonisolated func close() {
        socket.close()
    }

    // MARK: 요청

    /// 요청을 시작하고 응답 스트림을 돌려준다. 스트림의 첫 부분은 `head`다.
    /// 받는 쪽이 스트림을 버리면 다음 수신 때 RST_STREAM으로 그 요청을 취소한다.
    func send(_ request: HTTP2ClientConnection.Request, body: [UInt8]?) throws(ControlError) -> ResponseParts {
        if let failure { throw failure }
        let id: HTTP2StreamID
        do {
            id = try http2.startRequest(request, body: body)
        } catch {
            throw .connection("HTTP/2 요청을 시작하지 못했다: \(error)")
        }
        let (stream, continuation) = ResponseParts.makeStream()
        streams[id] = continuation
        try flush()
        return stream
    }

    // MARK: 읽기

    /// 소켓에서 받아 각 응답 스트림에 나눠 준다. 연결이 끝나면 모든 스트림을 그 오류로 끝내고 던진다.
    private func readLoop() async throws(ControlError) {
        do throws(ControlError) {
            while true {
                guard let bytes = try await socket.receiveBytes() else {
                    throw .connection("서버가 연결을 닫았다")
                }
                try process(sealed: bytes)
            }
        } catch {
            fail(error)
            throw error
        }
    }

    private func process(sealed bytes: [UInt8]) throws(ControlError) {
        var plaintext = try transport { () throws(ControlTransportError) in try session.receive(bytes) }
        if var parser = earlyPayload {
            let input = plaintext
            guard let (_, remainder) = try transport({ () throws(ControlTransportError) in try parser.receive(input) }) else {
                earlyPayload = parser
                return
            }
            // M2는 nodeKeyChallenge를 쓰지 않는다. 걸러 내기만 한다.
            earlyPayload = nil
            plaintext = remainder
        }
        guard !plaintext.isEmpty else { return }

        let events: [HTTP2ClientConnection.Event]
        do {
            events = try http2.receive(plaintext)
        } catch {
            try? flush()   // 남은 GOAWAY를 보내 둔다.
            throw .connection("HTTP/2 연결 오류: \(error)")
        }
        for event in events {
            dispatch(event)
        }
        try flush()
    }

    private func dispatch(_ event: HTTP2ClientConnection.Event) {
        switch event {
        case let .responseHead(id, status, headers):
            deliver(.head(status: status, headers: headers), to: id)
        case let .responseData(id, bytes):
            deliver(.data(bytes), to: id)
        case let .streamClosed(id, resetCode):
            if let resetCode {
                streams.removeValue(forKey: id)?.finish(throwing: ControlError.connection("서버가 스트림을 끊었다(RST_STREAM \(resetCode))"))
            } else {
                streams.removeValue(forKey: id)?.finish()
            }
        case let .goAway(lastStreamID, code):
            for id in streams.keys where id.rawValue > lastStreamID.rawValue {
                streams.removeValue(forKey: id)?.finish(throwing: ControlError.connection("서버가 GOAWAY(\(code))로 요청을 거절했다"))
            }
        }
    }

    private func deliver(_ part: ResponsePart, to id: HTTP2StreamID) {
        guard let continuation = streams[id] else { return }
        if case .terminated = continuation.yield(part) {
            // 받는 쪽이 사라졌다. 서버가 더 보내지 않게 스트림을 취소한다.
            streams[id] = nil
            http2.cancel(id)
        }
    }

    /// HTTP/2가 내보낼 바이트를 레코드로 봉해 보낸다.
    private func flush() throws(ControlError) {
        let outbound = http2.takeOutboundBytes()
        guard !outbound.isEmpty else { return }
        let sealed = try transport { () throws(ControlTransportError) in try session.seal(outbound) }
        socket.send(sealed)
    }

    private func fail(_ error: ControlError) {
        failure = failure ?? error
        for continuation in streams.values {
            continuation.finish(throwing: error)
        }
        streams = [:]
        socket.close()
    }
}

/// 전송 계층 상태 기계의 오류를 연결 오류로 옮긴다. 업그레이드 거절은 HTTP 상태로 드러낸다.
private func transport<T>(_ operation: () throws(ControlTransportError) -> T) throws(ControlError) -> T {
    do {
        return try operation()
    } catch .upgradeRejected(let status) {
        throw .http(status: status)
    } catch {
        throw .connection("제어 전송 오류: \(error)")
    }
}
