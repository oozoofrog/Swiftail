// Test-only HTTP/1.1 server for gate (a) 8–10 (`docs/contracts/SwiftailHost.md` contract §7, behavior B7, first adopter review findings 7, 8, and 11).
//
// Implements the minimum needed to mimic the first adopter's host: pairing, install sessions, manifest, and IPA. It does not reproduce the host's logic for pairing codes,
// session lifetime, or published build checks (contract §7, "Scope of RemoteDebug E2E Reproduction").

import CryptoKit
import Foundation
import Network
import Security
import SwiftailCertificates
import SwiftailLoopback
import Synchronization

/// Install session table shared by servers so sessions survive a listener change (renewal).
final class HostSessions: Sendable {
    struct Session: Sendable {
        let token: String
        let stableID: String
    }

    private let sessions = Mutex<[Session]>([])

    /// Issued sessions. The test retrieves the token for the next request (`peerHTTP` does not return the response body).
    var issued: [Session] { sessions.withLock { $0 } }

    func issue(for stableID: String) -> String {
        var generator = SystemRandomNumberGenerator()
        let token = (0..<32).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max, using: &generator)) }.joined()
        sessions.withLock { $0.append(Session(token: token, stableID: stableID)) }
        return token
    }

    /// Finds the node bound to the token. The token is secret, so it is compared against every session in constant time (AGENTS.md).
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

/// Pauses an IPA transfer after a specified number of bytes so the test can reliably catch a large transfer in progress (items 6 and 10).
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

    /// Waits for release once the sent byte count exceeds the threshold. Pauses only one transfer, the first to cross it.
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

/// IPA byte sequence formed by repeating the first 1,048,573 bytes (a prime) of the seed's LCG64 stream (`NetstackStream`). This avoids holding 100MiB in memory
/// or generating bytes one at a time even in debug builds, so generation does not limit throughput. The period is not a power of two, so MiB-aligned
/// shifts in a Range (such as sending the two halves in reverse order) also yield different hashes.
struct IPAContent: Sendable {
    static let period = 1_048_573
    /// Maximum bytes returned at once. The table extends this far past the period so reads do not have to wrap.
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

    /// SHA-256 of `length` bytes starting at `offset` (lowercase hex).
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

/// Minimal test-only HTTP/1.1 server. Uses an `NWListener` on `127.0.0.1` (the system chooses the port) and accepts one request per connection.
///
/// Installs the bridge's options at the end of the listener's protocol stack (below TLS). The framer validates the one-time token the bridge sent at the start
/// of the connection. Connections without a token cannot become `.ready`. When an accepted connection is `.ready`, call `bridge.origin(of:)` exactly once
/// and disconnect if it returns nil (behavior B7). Plaintext mode behaves the same way.
///
/// Routes: `POST /pair` (the peer's `stableID` and `computedName`), `POST /sessions` (a token bound to that `stableID`),
/// `GET /manifest?token=…`, and `GET /ipa?token=…` (`Range: bytes=a-b`). Returns 403 when the token's node differs from the connection's `Origin.peer.stableID`.
final class MinimalHTTPServer: Sendable {
    enum Mode: Sendable { case tls, plain }

    /// What happened on one connection. The test reads the disconnect as seen by the server.
    struct ConnectionRecord: Sendable {
        var sourcePort: UInt16 = 0
        /// The peer reported by the bridge. A nil value means no identity was obtained for the connection.
        var stableID: String?
        var rejected = false
        /// The first two words of a request line, such as `GET /ipa`.
        var request: String?
        var status: Int?
        var bodyBytesSent: UInt64 = 0
        /// An error while sending the response (in the form `posix(ECONNRESET)`).
        var sendError: String?
        /// How the receive started after reading the request ended: `eof` (no error) or `error(…)`.
        var receiveEnd: String?
        /// Why the connection ended before `.ready`, or the error if `.failed` arrived afterward.
        var stateError: String?
    }

    /// Request header limit.
    static let maximumHeadByteCount = 16_384
    /// Request body limit (first adopter review finding 11: the test server also caps the body).
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

    /// Starts the listener. TLS mode creates an identity from the `certificate` chain and key (`makeIdentity(_:)`).
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
            sec_protocol_options_set_local_identity(options, try makeIdentity(try requireValue(certificate, "TLS mode requires a certificate")))
            sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
            sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
            parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        }
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        // Always install it at the end (below TLS, immediately above TCP).
        parameters.defaultProtocolStack.applicationProtocols.append(bridge.makeListenerProtocolOptions())
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

    /// Stops accepting new connections. Already accepted connections run to completion (first adopter review finding 3: the old listener after renewal).
    func stopAccepting() { listener.cancel() }

    func close() {
        listener.cancel()
        let connections = state.withLock { state -> [NWConnection] in
            defer { state.connections = [] }
            return state.connections
        }
        for connection in connections { connection.cancel() }
    }

    // MARK: - Identity (snippet from contract §6, without using the keychain)

    /// Converts a `TailnetCertificate` into a TLS identity. Uses `SecKeyCreateWithData` for the in-memory key without the keychain, `SecIdentityCreate` for the identity,
    /// and `sec_identity_create_with_certificates` to include intermediates. The array contains the rest of the chain with the leaf excluded.
    static func makeIdentity(_ certificate: TailnetCertificate) throws -> sec_identity_t {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let key = SecKeyCreateWithData(Data(certificate.privateKey.x963Representation) as CFData,
                                             attributes as CFDictionary, nil) else {
            throw GateFailure("SecKeyCreateWithData could not create a P-256 private key")
        }
        let certificates = try certificate.chain.map { der -> SecCertificate in
            guard let value = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
                throw GateFailure("SecCertificateCreateWithData failed")
            }
            return value
        }
        guard let leaf = certificates.first, let identity = SecIdentityCreate(nil, leaf, key) else {
            throw GateFailure("SecIdentityCreate returned nil (key and leaf do not match)")
        }
        // Include only the chain after the leaf in the array. Including the leaf makes the server send it twice (verified in the gate: 3 certificates for a 2-certificate chain).
        guard let value = sec_identity_create_with_certificates(identity, Array(certificates.dropFirst()) as CFArray) else {
            throw GateFailure("sec_identity_create_with_certificates returned nil")
        }
        return value
    }

    // MARK: - Response bodies (tests use the same functions to compute expected hashes)

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

    // MARK: - Connection

    private func accept(_ connection: NWConnection) {
        let log = ConnectionLog()
        state.withLock {
            $0.connections.append(connection)
            $0.records.append(log)
        }
        Task {
            await self.serve(connection, log: log)
            // Release completed connections. For a connection that ends before readiness, `cancel()` alone does not close its socket. The socket closes when `NWConnection`
            // is released (retaining it keeps the peer that dialed without a token from seeing the end and leaves the server's descriptor open).
            self.state.withLock { $0.connections.removeAll { $0 === connection } }
        }
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
        let buffer: [UInt8] = []
        guard let origin = bridge.origin(of: connection) else {
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
        // Receive after the request to record how the peer ends the connection (clean EOF or error), per first adopter review finding 7.
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

    /// Handles a send failure. Briefly gives the pending receive time to record how it ended, then drops the connection.
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

    /// Closes the write direction (TLS close_notify), waits up to 5 seconds for the peer to close, then releases the connection.
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

    /// Accepts only a single `bytes=a-b` or `bytes=a-`.
    static func parseRange(_ value: String, length: UInt64) -> (UInt64, UInt64)? {
        guard value.hasPrefix("bytes=") else { return nil }
        let parts = value.dropFirst(6).split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let start = UInt64(parts[0]) else { return nil }
        let end = parts[1].isEmpty ? length - 1 : UInt64(parts[1])
        guard let end, start <= end, end < length else { return nil }
        return (start, end)
    }

    // MARK: - Request reading

    struct Request: Sendable {
        let method: String
        let path: String
        let query: [String: String]
        /// Names are lowercase.
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

    // MARK: - Asynchronous NWConnection wrappers

    enum Received: Sendable { case bytes([UInt8]), end, failed(String) }

    /// Waits for `.ready`. Returns the reason on failure. Also records `.failed` after readiness.
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

    /// Sends and waits for the network stack to accept the bytes. Returns the error on failure. Closes the write direction if `final` is true.
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

/// Converts a missing value into a gate failure so synchronous helpers outside test functions do not have to use `#require`.
func requireValue<T>(_ value: T?, _ description: String = "Missing value") throws -> T {
    guard let value else { throw GateFailure(description) }
    return value
}
