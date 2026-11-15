// 관문 (가) 8~10의 시험 전용 HTTP/1.1 서버(계약 `docs/contracts/SwiftailHost.md` 7절, 동작 B7, 첫 사용처 검토 결과 7·8·11).
//
// 첫 사용처의 호스트를 흉내 내는 최소한이다: 페어링, 설치 세션, 매니페스트, IPA. 호스트의 로직(페어링 코드, 세션의
// 수명, 게시본 검사)은 재현하지 않는다(계약 7절 "RemoteDebug e2e 재현의 범위").

import CryptoKit
import Foundation
import Network
import Security
import SwiftailCertificates
import SwiftailLoopback
import Synchronization

/// 설치 세션 표. 리스너가 바뀌어도(갱신) 세션은 남으므로 서버들이 함께 쓴다.
final class HostSessions: Sendable {
    struct Session: Sendable {
        let token: String
        let stableID: String
    }

    private let sessions = Mutex<[Session]>([])

    /// 낸 세션들. 시험이 다음 요청의 토큰을 꺼낸다(`peerHTTP`는 응답 본문을 돌려주지 않는다).
    var issued: [Session] { sessions.withLock { $0 } }

    func issue(for stableID: String) -> String {
        var generator = SystemRandomNumberGenerator()
        let token = (0..<32).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max, using: &generator)) }.joined()
        sessions.withLock { $0.append(Session(token: token, stableID: stableID)) }
        return token
    }

    /// 토큰에 묶인 노드. 토큰은 비밀이므로 모든 세션과 상수 시간으로 견준다(AGENTS.md).
    func stableID(forToken token: String) -> String? {
        let candidate = Array(token.utf8)
        var found: String?
        for session in issued {
            let expected = Array(session.token.utf8)
            var difference = candidate.count ^ expected.count
            for index in 0..<expected.count {
                difference |= Int(expected[index] ^ (index < candidate.count ? candidate[index] : 0))
            }
            if difference == 0 { found = session.stableID }
        }
        return found
    }
}

/// IPA를 보내다 정한 바이트에서 멈춰 둔다. 큰 전송이 "도는 중"인 때를 시험이 확실히 잡게 한다(항목 6·10).
final class TransferHold: Sendable {
    private struct State {
        var reached = false
        var released = false
        var waiters: [CheckedContinuation<Void, Never>] = []
    }

    let threshold: UInt64
    private let state = Mutex(State())

    init(afterBytes threshold: UInt64) { self.threshold = threshold }

    var isReached: Bool { state.withLock { $0.reached } }

    func release() {
        let waiters = state.withLock { state -> [CheckedContinuation<Void, Never>] in
            state.released = true
            defer { state.waiters = [] }
            return state.waiters
        }
        for waiter in waiters { waiter.resume() }
    }

    /// 보낸 양이 문턱을 넘었으면 풀릴 때까지 기다린다. 한 전송만 멈춘다(처음 넘은 것).
    func pass(sent: UInt64) async {
        guard sent >= threshold else { return }
        await withCheckedContinuation { continuation in
            let resumeNow = state.withLock { state -> Bool in
                if state.released || state.reached { return true }
                state.reached = true
                state.waiters.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }
}

/// IPA 바이트열: 씨앗의 LCG64 바이트열(`NetstackStream`) 앞 1,048,573바이트(소수)를 되풀이한 것. 100MiB를 메모리에 쥐지
/// 않고, 디버그 빌드에서도 바이트마다 만들지 않아 처리량이 생성에 묶이지 않는다. 주기가 2의 거듭제곱이 아니어서 MiB 단위로
/// 어긋난 Range(예: 두 반쪽을 바꿔 보냄)도 해시가 다르다.
struct IPAContent: Sendable {
    static let period = 1_048_573
    /// 한 번에 꺼내는 최대 바이트. 표는 주기 뒤에 이만큼을 더 붙여 꺼낼 때 감싸지 않는다.
    static let maximumChunk = 65_536
    private let table: [UInt8]

    init(seed: UInt64) {
        var stream = NetstackStream(seed: seed)
        let cycle = stream.bytes(Self.period)
        table = cycle + cycle.prefix(Self.maximumChunk)
    }

    func bytes(at offset: UInt64, count: Int) -> [UInt8] {
        precondition(count <= Self.maximumChunk)
        let start = Int(offset % UInt64(Self.period))
        return Array(table[start..<(start + count)])
    }

    /// `offset`부터 `length`바이트의 SHA-256(소문자 hex).
    func digest(offset: UInt64, length: UInt64) -> String {
        var hash = SHA256()
        var done: UInt64 = 0
        while done < length {
            let count = Int(min(UInt64(Self.maximumChunk), length - done))
            hash.update(data: Data(bytes(at: offset + done, count: count)))
            done += UInt64(count)
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

/// 시험 전용 최소 HTTP/1.1 서버. `127.0.0.1`의 `NWListener`(포트는 시스템이 고른다)이고 연결마다 요청 하나만 받는다.
///
/// 받은 연결이 `.ready`가 되면(TLS 핸드셰이크 끝) **첫 수신 전에** `bridge.origin(forLoopbackSourcePort:)`를 묻고, nil이면
/// 끊는다(동작 B7, 첫 사용처 검토 결과 8). 평문 모드는 첫 바이트를 받은 뒤에 묻는다.
///
/// 경로: `POST /pair`(상대의 `stableID`·`computedName`), `POST /sessions`(그 `stableID`에 묶인 토큰),
/// `GET /manifest?token=…`, `GET /ipa?token=…`(`Range: bytes=a-b`). 토큰의 노드가 연결의 `Origin.peer.stableID`와 다르면 403.
final class MinimalHTTPServer: Sendable {
    enum Mode: Sendable { case tls, plain }

    /// 연결 하나가 겪은 것. 시험이 서버 쪽에서 본 끊김을 읽는다.
    struct ConnectionRecord: Sendable {
        var sourcePort: UInt16 = 0
        /// 다리의 표에서 찾은 상대. nil이면 표에 없어 끊은 연결이다.
        var stableID: String?
        var rejected = false
        /// `GET /ipa` 같은 요청 줄의 앞 두 낱말.
        var request: String?
        var status: Int?
        var bodyBytesSent: UInt64 = 0
        /// 응답을 보내다 난 오류(`posix(ECONNRESET)` 꼴).
        var sendError: String?
        /// 요청을 읽은 뒤 걸어 둔 받기가 어떻게 끝났는가: `eof`(오류 없는 끝), `error(…)`.
        var receiveEnd: String?
        /// `.ready` 전에 끝났으면 그 까닭, 뒤에 `.failed`가 오면 그 오류.
        var stateError: String?
    }

    /// 요청 머리의 한도.
    static let maximumHeadByteCount = 16_384
    /// 요청 본문의 한도(첫 사용처 검토 결과 11: 시험 서버도 본문 상한을 둔다).
    static let maximumBodyByteCount = 65_536

    let port: UInt16
    let label: String
    let mode: Mode
    private let listener: NWListener
    private let bridge: LoopbackBridge
    private let sessions: HostSessions
    private let domain: String
    private let ipa: IPAContent
    private let ipaLength: UInt64
    private let hold: TransferHold?
    private let state = Mutex(State())

    private struct State {
        var records: [ConnectionLog] = []
        var connections: [NWConnection] = []
    }

    private final class ConnectionLog: Sendable {
        let value = Mutex(ConnectionRecord())
        func update(_ body: (inout ConnectionRecord) -> Void) { value.withLock { body(&$0) } }
        var snapshot: ConnectionRecord { value.withLock { $0 } }
    }

    var records: [ConnectionRecord] { state.withLock { $0.records.map(\.snapshot) } }

    private init(port: UInt16, label: String, mode: Mode, listener: NWListener, bridge: LoopbackBridge,
                 sessions: HostSessions, domain: String, ipaSeed: UInt64, ipaLength: UInt64, hold: TransferHold?) {
        (self.port, self.label, self.mode, self.listener, self.bridge) = (port, label, mode, listener, bridge)
        (self.sessions, self.domain, self.ipaLength, self.hold) = (sessions, domain, ipaLength, hold)
        ipa = IPAContent(seed: ipaSeed)
    }

    /// 리스너를 띄운다. TLS 모드는 `certificate`의 사슬과 키로 신원을 만든다(`makeIdentity(_:)`).
    static func start(
        _ mode: Mode, certificate: TailnetCertificate?, label: String, bridge: LoopbackBridge, sessions: HostSessions,
        domain: String, ipaSeed: UInt64, ipaLength: UInt64, hold: TransferHold? = nil
    ) async throws -> MinimalHTTPServer {
        let parameters: NWParameters
        switch mode {
        case .plain:
            parameters = .tcp
        case .tls:
            let tls = NWProtocolTLS.Options()
            let options = tls.securityProtocolOptions
            sec_protocol_options_set_local_identity(options, try makeIdentity(try requireValue(certificate, "TLS 모드에는 인증서가 필요함")))
            sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
            sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
            parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        }
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        listener.newConnectionHandler = { sink.yield($0) }
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                case .cancelled:
                    once.withLock { $0.take() }?.resume(throwing: CancellationError())
                default:
                    break
                }
            }
            listener.start(queue: DispatchQueue(label: "test.http.listener"))
        }
        let server = MinimalHTTPServer(port: port, label: label, mode: mode, listener: listener, bridge: bridge,
                                       sessions: sessions, domain: domain, ipaSeed: ipaSeed, ipaLength: ipaLength, hold: hold)
        Task {
            for await connection in accepted { server.accept(connection) }
        }
        return server
    }

    /// 새 연결만 받지 않는다. 이미 받은 연결은 끝까지 간다(첫 사용처 검토 결과 3: 갱신 뒤의 옛 리스너).
    func stopAccepting() { listener.cancel() }

    func close() {
        listener.cancel()
        let connections = state.withLock { state -> [NWConnection] in
            defer { state.connections = [] }
            return state.connections
        }
        for connection in connections { connection.cancel() }
    }

    // MARK: - 신원(계약 6절의 조각. 키체인을 쓰지 않는다)

    /// `TailnetCertificate` → TLS 신원. 키는 `SecKeyCreateWithData`(키체인 없이 메모리의 키), 신원은 `SecIdentityCreate`,
    /// 중간 인증서는 `sec_identity_create_with_certificates`로 싣는다. 넘기는 배열은 leaf를 뺀 나머지 사슬이다.
    static func makeIdentity(_ certificate: TailnetCertificate) throws -> sec_identity_t {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let key = SecKeyCreateWithData(Data(certificate.privateKey.x963Representation) as CFData,
                                             attributes as CFDictionary, nil) else {
            throw GateFailure("SecKeyCreateWithData가 P-256 개인 키를 만들지 못함")
        }
        let certificates = try certificate.chain.map { der -> SecCertificate in
            guard let value = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
                throw GateFailure("SecCertificateCreateWithData 실패")
            }
            return value
        }
        guard let leaf = certificates.first, let identity = SecIdentityCreate(nil, leaf, key) else {
            throw GateFailure("SecIdentityCreate가 nil(키와 leaf가 맞지 않음)")
        }
        // 배열에는 leaf 뒤의 사슬만 넣는다. leaf까지 넣으면 서버가 leaf를 두 번 보낸다(관문에서 확인: 사슬 2장에 3장).
        guard let value = sec_identity_create_with_certificates(identity, Array(certificates.dropFirst()) as CFArray) else {
            throw GateFailure("sec_identity_create_with_certificates가 nil")
        }
        return value
    }

    // MARK: - 응답 본문(시험이 같은 함수로 기대 해시를 만든다)

    static func pairBody(stableID: String, computedName: String) -> [UInt8] {
        Array(#"{"stableID":"\#(stableID)","computedName":"\#(computedName)"}"#.utf8)
    }

    static func sessionBody(token: String) -> [UInt8] { Array(#"{"token":"\#(token)"}"#.utf8) }

    static func manifestBody(domain: String, token: String) -> [UInt8] {
        Array("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict>\
        <key>kind</key><string>software-package</string>\
        <key>url</key><string>https://\(domain)/ipa?token=\(token)</string>\
        </dict></array></dict></array></dict></plist>

        """.utf8)
    }

    // MARK: - 연결

    private func accept(_ connection: NWConnection) {
        let log = ConnectionLog()
        state.withLock {
            $0.connections.append(connection)
            $0.records.append(log)
        }
        Task { await self.serve(connection, log: log) }
    }

    private func serve(_ connection: NWConnection, log: ConnectionLog) async {
        if let failure = await Self.ready(connection, log: log) {
            log.update { $0.stateError = failure }
            connection.cancel()
            return
        }
        guard case .hostPort(_, let sourcePort) = connection.endpoint else {
            connection.cancel()
            return
        }
        log.update { $0.sourcePort = sourcePort.rawValue }
        var buffer: [UInt8] = []
        if mode == .plain {
            // 평문 리스너는 첫 바이트를 받은 뒤에 묻는다(동작 B7).
            guard case .bytes(let first) = await Self.receive(connection), !first.isEmpty else {
                connection.cancel()
                return
            }
            buffer = first
        }
        guard let origin = bridge.origin(forLoopbackSourcePort: sourcePort.rawValue) else {
            log.update { $0.rejected = true }
            connection.cancel()
            return
        }
        log.update { $0.stableID = origin.peer.stableID }

        let request: Request
        switch await Self.readRequest(connection, buffer: buffer) {
        case .request(let value):
            request = value
        case .malformed:
            await respond(connection, log: log, status: 400, body: [])
            return
        case .closed:
            connection.cancel()
            return
        }
        log.update { $0.request = "\(request.method) \(request.path)" }
        // 요청 뒤의 받기: 상대가 어떻게 끝내는지(깨끗한 EOF인지 오류인지)를 적는다(첫 사용처 검토 결과 7).
        Task {
            while true {
                switch await Self.receive(connection) {
                case .bytes: continue
                case .end: log.update { $0.receiveEnd = "eof" }
                case .failed(let error): log.update { $0.receiveEnd = "error(\(error))" }
                }
                return
            }
        }
        await route(request, origin: origin, connection: connection, log: log)
    }

    private func route(_ request: Request, origin: LoopbackBridge.Origin, connection: NWConnection, log: ConnectionLog) async {
        let token = request.query["token"]
        switch (request.method, request.path) {
        case ("POST", "/pair"):
            await respond(connection, log: log, status: 200, contentType: "application/json",
                          body: Self.pairBody(stableID: origin.peer.stableID, computedName: origin.peer.computedName))
        case ("POST", "/sessions"):
            let token = sessions.issue(for: origin.peer.stableID)
            await respond(connection, log: log, status: 200, contentType: "application/json", body: Self.sessionBody(token: token))
        case ("GET", "/manifest"):
            guard let token, sessions.stableID(forToken: token) == origin.peer.stableID else {
                return await respond(connection, log: log, status: 403, body: [])
            }
            await respond(connection, log: log, status: 200, contentType: "text/xml", body: Self.manifestBody(domain: domain, token: token))
        case ("GET", "/ipa"):
            guard let token, sessions.stableID(forToken: token) == origin.peer.stableID else {
                return await respond(connection, log: log, status: 403, body: [])
            }
            await sendIPA(connection, log: log, range: request.headers["range"])
        case (_, "/pair"), (_, "/sessions"), (_, "/manifest"), (_, "/ipa"):
            await respond(connection, log: log, status: 405, body: [])
        default:
            await respond(connection, log: log, status: 404, body: [])
        }
    }

    private func sendIPA(_ connection: NWConnection, log: ConnectionLog, range: String?) async {
        var start: UInt64 = 0
        var end = ipaLength - 1
        var status = 200
        var extra: [(String, String)] = [("Accept-Ranges", "bytes")]
        if let range {
            guard let parsed = Self.parseRange(range, length: ipaLength) else {
                return await respond(connection, log: log, status: 416, headers: [("Content-Range", "bytes */\(ipaLength)")], body: [])
            }
            (start, end) = parsed
            status = 206
            extra.append(("Content-Range", "bytes \(start)-\(end)/\(ipaLength)"))
        }
        let length = end - start + 1
        log.update { $0.status = status }
        let head = Self.head(status: status, label: label, contentType: "application/octet-stream", length: length, extra: extra)
        if let error = await Self.send(connection, head) { return await fail(connection, log: log, error: error) }
        var sent: UInt64 = 0
        while sent < length {
            let chunk = ipa.bytes(at: start + sent, count: Int(min(UInt64(IPAContent.maximumChunk), length - sent)))
            if let error = await Self.send(connection, chunk) { return await fail(connection, log: log, error: error) }
            sent += UInt64(chunk.count)
            log.update { $0.bodyBytesSent = sent }
            await hold?.pass(sent: sent)
        }
        await finish(connection, log: log)
    }

    /// 보내다 실패했다. 걸어 둔 받기가 끝을 적을 틈을 잠깐 준 뒤 연결을 버린다.
    private func fail(_ connection: NWConnection, log: ConnectionLog, error: String) async {
        log.update { $0.sendError = error }
        for _ in 0..<40 where log.snapshot.receiveEnd == nil { try? await Task.sleep(for: .milliseconds(50)) }
        connection.cancel()
    }

    private func respond(_ connection: NWConnection, log: ConnectionLog, status: Int, contentType: String? = nil,
                         headers: [(String, String)] = [], body: [UInt8]) async {
        log.update { $0.status = status }
        let head = Self.head(status: status, label: label, contentType: contentType, length: UInt64(body.count), extra: headers)
        if let error = await Self.send(connection, head + body) { return await fail(connection, log: log, error: error) }
        log.update { $0.bodyBytesSent = UInt64(body.count) }
        await finish(connection, log: log)
    }

    /// 쓰기를 닫고(TLS는 close_notify) 상대가 닫기를 5초까지 기다린 뒤 연결을 놓는다.
    private func finish(_ connection: NWConnection, log: ConnectionLog) async {
        if let error = await Self.send(connection, [], final: true) { return await fail(connection, log: log, error: error) }
        for _ in 0..<100 where log.snapshot.receiveEnd == nil { try? await Task.sleep(for: .milliseconds(50)) }
        connection.cancel()
    }

    private static func head(status: Int, label: String, contentType: String?, length: UInt64, extra: [(String, String)]) -> [UInt8] {
        let reasons = [200: "OK", 206: "Partial Content", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                       405: "Method Not Allowed", 416: "Range Not Satisfiable"]
        var lines = ["HTTP/1.1 \(status) \(reasons[status] ?? "Error")", "Content-Length: \(length)", "Connection: close",
                     "Swiftail-Listener: \(label)"]
        if let contentType { lines.append("Content-Type: \(contentType)") }
        lines += extra.map { "\($0.0): \($0.1)" }
        return Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    /// `bytes=a-b`, `bytes=a-` 하나만 받는다.
    static func parseRange(_ value: String, length: UInt64) -> (UInt64, UInt64)? {
        guard value.hasPrefix("bytes=") else { return nil }
        let parts = value.dropFirst(6).split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let start = UInt64(parts[0]) else { return nil }
        let end = parts[1].isEmpty ? length - 1 : UInt64(parts[1])
        guard let end, start <= end, end < length else { return nil }
        return (start, end)
    }

    // MARK: - 요청 읽기

    struct Request: Sendable {
        let method: String
        let path: String
        let query: [String: String]
        /// 이름은 소문자.
        let headers: [String: String]
    }

    private enum ReadResult { case request(Request), malformed, closed }

    private static func readRequest(_ connection: NWConnection, buffer initial: [UInt8]) async -> ReadResult {
        var buffer = initial
        let terminator: [UInt8] = [13, 10, 13, 10]
        var headEnd: Int?
        while true {
            if buffer.count >= 4 {
                headEnd = (0...(buffer.count - 4)).first { buffer[$0..<($0 + 4)].elementsEqual(terminator) }
            }
            if headEnd != nil { break }
            guard buffer.count <= maximumHeadByteCount else { return .malformed }
            guard case .bytes(let more) = await receive(connection) else { return .closed }
            buffer += more
        }
        guard let headEnd, headEnd + 4 <= maximumHeadByteCount else { return .malformed }
        let lines = String(decoding: buffer[..<headEnd], as: UTF8.self).components(separatedBy: "\r\n")
        let requestLine = lines[0].split(separator: " ", omittingEmptySubsequences: false)
        guard requestLine.count == 3, requestLine[2] == "HTTP/1.1",
              let components = URLComponents(string: String(requestLine[1])), requestLine[1].hasPrefix("/") else {
            return .malformed
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { return .malformed }
            let name = line[..<colon].lowercased()
            guard !name.isEmpty, !name.contains(" ") else { return .malformed }
            headers[name] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard headers["transfer-encoding"] == nil else { return .malformed }
        var length = 0
        if let value = headers["content-length"] {
            guard let parsed = Int(value), parsed >= 0, parsed <= maximumBodyByteCount else { return .malformed }
            length = parsed
        }
        var body = buffer.count - (headEnd + 4)
        while body < length {
            guard case .bytes(let more) = await receive(connection) else { return .closed }
            body += more.count
        }
        let query = Dictionary((components.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { first, _ in first })
        return .request(Request(method: String(requestLine[0]), path: components.path, query: query, headers: headers))
    }

    // MARK: - NWConnection의 비동기 감싸개

    enum Received: Sendable { case bytes([UInt8]), end, failed(String) }

    /// `.ready`까지 기다린다. 실패하면 그 까닭. 준비된 뒤의 `.failed`도 기록에 남긴다.
    private static func ready(_ connection: NWConnection, log: ConnectionLog) async -> String? {
        await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let once = Mutex<CheckedContinuation<String?, Never>?>(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: once.withLock { $0.take() }?.resume(returning: nil)
                case .failed(let error):
                    let text = describe(error)
                    if let waiting = once.withLock({ $0.take() }) { waiting.resume(returning: text) }
                    else { log.update { $0.stateError = text } }
                case .cancelled: once.withLock { $0.take() }?.resume(returning: "cancelled")
                default: break
                }
            }
            connection.start(queue: DispatchQueue(label: "test.http.connection"))
        }
    }

    static func receive(_ connection: NWConnection) async -> Received {
        await withCheckedContinuation { (continuation: CheckedContinuation<Received, Never>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
                if let data, !data.isEmpty { continuation.resume(returning: .bytes([UInt8](data))) }
                else if let error { continuation.resume(returning: .failed(describe(error))) }
                else if isComplete { continuation.resume(returning: .end) }
                else { continuation.resume(returning: .bytes([])) }
            }
        }
    }

    /// 보내고 네트워크 스택이 받아 갈 때까지 기다린다. 실패하면 그 오류. `final`이면 쓰기 방향을 닫는다.
    static func send(_ connection: NWConnection, _ bytes: [UInt8], final: Bool = false) async -> String? {
        await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            connection.send(content: bytes.isEmpty ? nil : Data(bytes), contentContext: final ? .finalMessage : .defaultMessage,
                            isComplete: true, completion: .contentProcessed { error in
                continuation.resume(returning: error.map(describe))
            })
        }
    }

    static func describe(_ error: NWError) -> String {
        switch error {
        case .posix(let code): "posix(\(code))"
        case .tls(let status): "tls(\(status))"
        case .dns(let code): "dns(\(code))"
        default: "\(error)"
        }
    }
}

/// `#require`는 시험 함수 밖의 동기 도우미에서 쓰기 번거로워, 없는 값을 관문 실패로 바꾸는 작은 도우미를 둔다.
func requireValue<T>(_ value: T?, _ description: String = "값이 없음") throws -> T {
    guard let value else { throw GateFailure(description) }
    return value
}
