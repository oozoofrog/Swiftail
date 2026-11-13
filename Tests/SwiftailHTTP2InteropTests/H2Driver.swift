import Foundation
import Network
import SwiftailHTTP2

/// 상태 기계에는 공개 API로만 접근한다. TCP 수신 콜백은 처리 후 다음 수신을 걸어 순서를 지킨다.
actor H2Driver {
    struct Response: Sendable {
        var status: Int?
        var headers: [HeaderField] = []
        var body: [UInt8] = []
        var closed = false
        var resetCode: UInt32?
    }

    struct RecordedFrame: Sendable {
        let type: UInt8
        let flags: UInt8
        let length: Int
        let stream: UInt32
        let prefix: [UInt8]
        var description: String {
            "type=\(type) flags=0x\(String(flags, radix: 16)) len=\(length) stream=\(stream) prefix=\(prefix.map { String(format: "%02x", $0) }.joined())"
        }
    }

    /// 진단용 파서는 프레임을 해석하거나 구현에 전달할 바이트를 바꾸지 않는다.
    private struct Recorder {
        var pending: [UInt8] = []
        var frames: [RecordedFrame] = []

        mutating func append(_ bytes: [UInt8]) {
            pending += bytes
            var offset = 0
            while pending.count - offset >= 9 {
                let length = Int(pending[offset]) << 16 | Int(pending[offset + 1]) << 8 | Int(pending[offset + 2])
                guard pending.count - offset >= 9 + length else { break }
                let stream = pending[(offset + 5)..<(offset + 9)].reduce(UInt32(0)) { $0 << 8 | UInt32($1) } & 0x7fff_ffff
                frames.append(RecordedFrame(type: pending[offset + 3], flags: pending[offset + 4], length: length,
                                            stream: stream, prefix: Array(pending[(offset + 9)..<(offset + 9 + min(length, 16))])))
                offset += 9 + length
            }
            pending.removeFirst(offset)
        }
    }

    private let socket: NWConnection
    private let fragmentSize: Int?
    private var connection = HTTP2ClientConnection()
    private var responses: [HTTP2StreamID: Response] = [:]
    private var incoming = Recorder()
    private var outgoing = Recorder()
    private var history: [String] = []
    private var ready = false
    private var stopped = false
    private var eof = false
    private var sentPreface = false
    private var failure: H2InteropFailure?
    private var goAway: (lastStreamID: HTTP2StreamID, code: UInt32)?

    init(port: UInt16, fragmentSize: Int? = nil) throws {
        guard let port = NWEndpoint.Port(rawValue: port), fragmentSize.map({ $0 > 0 }) ?? true else {
            throw H2InteropFailure("잘못된 TCP 포트 또는 분할 크기")
        }
        socket = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
        self.fragmentSize = fragmentSize
    }

    func start() async throws {
        socket.stateUpdateHandler = { [weak self] state in
            Task { await self?.stateChanged(state) }
        }
        socket.start(queue: DispatchQueue(label: "swiftail.h2interop"))
        try await wait("TCP 준비", timeout: .seconds(15)) { $0.ready }
        flush()
        readNext()
        try await wait("서버 SETTINGS", timeout: .seconds(15)) { driver in
            driver.incoming.frames.contains { $0.type == 4 && $0.flags & 1 == 0 }
        }
    }

    private func stateChanged(_ state: NWConnection.State) {
        guard !stopped else { return }
        switch state {
        case .ready: ready = true
        case .failed(let error): failure = H2InteropFailure("TCP 실패: \(error)")
        case .cancelled: eof = true
        default: break
        }
    }

    func request(_ path: String, method: String = "GET", body: [UInt8]? = nil) throws -> HTTP2StreamID {
        if let failure { throw failure }
        let id = try connection.startRequest(.init(method: method, path: path, authority: "tail0001.test"), body: body)
        responses[id] = Response()
        flush()
        return id
    }

    func cancel(_ stream: HTTP2StreamID) {
        connection.cancel(stream)
        flush()
    }

    private func flush() {
        let bytes = connection.takeOutboundBytes()
        guard !bytes.isEmpty, !stopped else { return }
        // init이 준비한 프리페이스 24바이트는 프레임이 아니다.
        record(sentPreface ? bytes : Array(bytes.dropFirst(24)), incoming: false)
        sentPreface = true
        socket.send(content: Data(bytes), completion: .contentProcessed { [weak self] error in
            if let error { Task { await self?.sendFailed(error) } }
        })
    }

    private func sendFailed(_ error: NWError) {
        if !stopped { failure = H2InteropFailure("TCP 쓰기 실패: \(error)") }
    }

    private func readNext() {
        guard !stopped, !eof else { return }
        // Network 콜백을 actor로 옮기는 최소 경계다. 다음 읽기는 이 조각 처리 뒤에만 시작한다.
        socket.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, complete, error in
            Task { await self?.received(data, complete: complete, error: error) }
        }
    }

    private func received(_ data: Data?, complete: Bool, error: NWError?) {
        guard !stopped else { return }
        if let data, !data.isEmpty {
            let bytes = Array(data)
            record(bytes, incoming: true)
            let size = fragmentSize ?? bytes.count
            do {
                for offset in stride(from: 0, to: bytes.count, by: size) {
                    let events = try connection.receive(Array(bytes[offset..<min(offset + size, bytes.count)]))
                    for event in events {
                        switch event {
                        case .responseHead(let id, let status, let headers):
                            responses[id, default: Response()].status = status
                            responses[id, default: Response()].headers = headers
                        case .responseData(let id, let bytes): responses[id, default: Response()].body += bytes
                        case .streamClosed(let id, let code):
                            responses[id, default: Response()].closed = true
                            responses[id, default: Response()].resetCode = code
                        case .goAway(let lastStreamID, let code): goAway = (lastStreamID, code)
                        }
                    }
                    flush()
                }
            } catch {
                failure = H2InteropFailure("receive 실패: \(error)")
                flush()
            }
        }
        if let error { failure = H2InteropFailure("TCP 읽기 실패: \(error)") }
        eof = complete || error != nil
        if failure == nil { readNext() }
    }

    private func record(_ bytes: [UInt8], incoming isIncoming: Bool) {
        let previous = isIncoming ? incoming.frames.count : outgoing.frames.count
        if isIncoming { incoming.append(bytes) } else { outgoing.append(bytes) }
        let frames = isIncoming ? incoming.frames : outgoing.frames
        history += frames.dropFirst(previous).map { "\(isIncoming ? "수신" : "송신") \($0.description)" }
    }

    private func wait(_ description: String, timeout: Duration, until predicate: (isolated H2Driver) -> Bool) async throws {
        let deadline = ContinuousClock.now + timeout
        while true {
            try Task.checkCancellation()
            if let failure { throw failure }
            if predicate(self) { return }
            if eof { throw H2InteropFailure("\(description) 전에 TCP EOF") }
            guard ContinuousClock.now < deadline else {
                throw H2InteropFailure("\(description) 제한 시간 \(timeout) 초과")
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    func head(_ id: HTTP2StreamID, timeout: Duration = .seconds(30)) async throws -> Response {
        try await wait("스트림 \(id.rawValue) 응답 머리", timeout: timeout) {
            $0.responses[id]?.status != nil || $0.responses[id]?.closed == true
        }
        guard let response = responses[id], response.status != nil else { throw H2InteropFailure("응답 머리 없이 스트림 종료") }
        return response
    }

    func data(_ id: HTTP2StreamID, count: Int, timeout: Duration = .seconds(60)) async throws -> Response {
        try await wait("스트림 \(id.rawValue) 본문 \(count)바이트", timeout: timeout) {
            ($0.responses[id]?.body.count ?? 0) >= count || $0.responses[id]?.closed == true
        }
        guard let response = responses[id], response.body.count >= count else { throw H2InteropFailure("본문 \(count)바이트 전에 스트림 종료") }
        return response
    }

    func closed(_ id: HTTP2StreamID, timeout: Duration = .seconds(60)) async throws -> Response {
        try await wait("스트림 \(id.rawValue) 종료", timeout: timeout) { $0.responses[id]?.closed == true }
        guard let response = responses[id] else { throw H2InteropFailure("종료 사건의 스트림 없음") }
        return response
    }

    func serverGoAway() async throws -> (lastStreamID: HTTP2StreamID, code: UInt32) {
        try await wait("서버 GOAWAY", timeout: .seconds(30)) { $0.goAway != nil }
        guard let goAway else { throw H2InteropFailure("GOAWAY 사건 없음") }
        return goAway
    }

    func receivedFrames() -> [RecordedFrame] { incoming.frames }

    func diagnostics() -> String {
        let lines = history.count > 100 ? Array(history.prefix(16)) + ["중간 프레임 생략"] + Array(history.suffix(84)) : history
        let states = responses.sorted { $0.key.rawValue < $1.key.rawValue }.map {
            "스트림 \($0.key.rawValue): status=\($0.value.status.map(String.init) ?? "없음") body=\($0.value.body.count) closed=\($0.value.closed) reset=\($0.value.resetCode.map(String.init) ?? "없음")"
        }
        return (lines + states).joined(separator: "\n")
    }

    func stop() {
        stopped = true
        socket.stateUpdateHandler = nil
        socket.cancel()
    }
}

/// 성공·실패·취소 모두 소켓과 자식 프로세스를 닫고, 실패에는 Go 로그와 프레임 순서를 붙인다.
func withH2Server(fragmentSize: Int? = nil, _ operation: @Sendable (H2Driver, GoH2Server) async throws -> Void) async throws {
    let server = GoH2Server()
    var driver: H2Driver?
    do {
        let port = try await server.start()
        let connected = try H2Driver(port: port, fragmentSize: fragmentSize)
        driver = connected
        try await connected.start()
        try await operation(connected, server)
        await connected.stop()
        await server.stop()
    } catch {
        let frames = await driver?.diagnostics() ?? "연결 전 실패"
        await driver?.stop()
        await server.stop()
        let log = await server.diagnostics()
        throw H2InteropFailure("\(error)\n\(frames)\n\(log)")
    }
}
