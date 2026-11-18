// `URLSessionACMETransport`를 루프백의 작은 평문 HTTP/1.1 서버(시험 안의 `NWListener`)로 본다: 요청 머리와 본문의
// 전달, 응답 머리, 본문 한도, 요청 기한, 리다이렉트를 따르지 않음, 평문 길의 제한. 실제 인터넷에는 나가지 않는다.

import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailCertificates

@Suite("URLSession ACME 전송", .serialized)
struct URLSessionACMETransportTests {
    @Test("POST의 머리와 본문을 보내고 응답의 상태·머리·본문을 돌려준다")
    func postRoundTrip() async throws {
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "201 Created", headers: [
                ("Replay-Nonce", "oFvnlFP1wIhRlYS2jTaXbA"), ("Location", "https://acme.invalid/order/1"),
                ("Content-Type", "application/json"),
            ], body: Array(#"{"status":"pending"}"#.utf8))
        }
        defer { server.close() }
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        let body = Array(#"{"protected":"e30","payload":"","signature":"AA"}"#.utf8)
        let response = try await transport.send(ACMEHTTPRequest(
            method: .post, url: server.url("/new-order"), body: body, accept: "application/pem-certificate-chain"
        ))
        #expect(response.status == 201)
        #expect(response.firstHeader(named: "replay-nonce") == "oFvnlFP1wIhRlYS2jTaXbA")
        #expect(response.firstHeader(named: "LOCATION") == "https://acme.invalid/order/1")
        #expect(response.body == Array(#"{"status":"pending"}"#.utf8))

        let request = try #require(server.requests.first)
        #expect(request.line == "POST /new-order HTTP/1.1")
        #expect(request.header("user-agent") == "Swiftail/0.1.1")
        #expect(request.header("content-type") == "application/jose+json")
        #expect(request.header("accept") == "application/pem-certificate-chain")
        #expect(request.header("cookie") == nil)
        #expect(request.body == body)
    }

    @Test("HEAD와 GET은 본문 없이 보낸다")
    func headAndGet() async throws {
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "200 OK", headers: [("Replay-Nonce", "abc")], body: [])
        }
        defer { server.close() }
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        let head = try await transport.send(ACMEHTTPRequest(method: .head, url: server.url("/new-nonce"), body: []))
        #expect(head.status == 200)
        #expect(head.firstHeader(named: "Replay-Nonce") == "abc")
        _ = try await transport.send(ACMEHTTPRequest(method: .get, url: server.url("/directory"), body: []))
        #expect(server.requests.map(\.line) == ["HEAD /new-nonce HTTP/1.1", "GET /directory HTTP/1.1"])
        #expect(server.requests.allSatisfy { $0.body.isEmpty && $0.header("content-type") == nil })
    }

    @Test("본문 한도까지는 받고 넘으면 responseTooLarge")
    func bodyLimit() async throws {
        let size = Mutex(1000)
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "200 OK", headers: [], body: [UInt8](repeating: 0x41, count: size.withLock { $0 }))
        }
        defer { server.close() }
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true, maximumBodyByteCount: 1000)
        let exact = try await transport.send(ACMEHTTPRequest(method: .get, url: server.url("/a"), body: []))
        #expect(exact.body.count == 1000)

        size.withLock { $0 = 1001 }
        await #expect(throws: ACMETransportError.responseTooLarge) {
            _ = try await transport.send(ACMEHTTPRequest(method: .get, url: server.url("/b"), body: []))
        }
    }

    @Test("기본 본문 한도는 256KiB다")
    func defaultBodyLimit() async throws {
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "200 OK", headers: [], body: [UInt8](repeating: 0x41, count: 256 * 1024 + 1))
        }
        defer { server.close() }
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        await #expect(throws: ACMETransportError.responseTooLarge) {
            _ = try await transport.send(ACMEHTTPRequest(method: .get, url: server.url("/chain"), body: []))
        }
    }

    @Test("요청 하나의 기한을 넘으면 timedOut")
    func requestTimeout() async throws {
        let server = try await LoopbackHTTPServer { _ in nil }
        defer { server.close() }
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true, requestTimeout: 0.5)
        let started = ContinuousClock.now
        await #expect(throws: ACMETransportError.timedOut) {
            _ = try await transport.send(ACMEHTTPRequest(method: .get, url: server.url("/slow"), body: []))
        }
        #expect(ContinuousClock.now - started < .seconds(10))
    }

    @Test("리다이렉트를 따르지 않고 3xx를 그대로 돌려준다")
    func noRedirect() async throws {
        let target = Mutex("")
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "302 Found", headers: [("Location", target.withLock { $0 })], body: [])
        }
        defer { server.close() }
        target.withLock { $0 = server.url("/elsewhere") }
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        let response = try await transport.send(ACMEHTTPRequest(method: .post, url: server.url("/new-order"), body: [1]))
        #expect(response.status == 302)
        #expect(server.requests.map(\.line) == ["POST /new-order HTTP/1.1"])
    }

    @Test("평문 http는 시험용 길의 루프백 호스트에만 보낸다")
    func plaintextOnlyOnLoopback() async throws {
        let production = URLSessionACMETransport()
        await #expect(throws: ACMETransportError.invalidURL) {
            _ = try await production.send(ACMEHTTPRequest(method: .get, url: "http://127.0.0.1:9/directory", body: []))
        }
        let testing = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        for url in ["http://acme.invalid/directory", "ftp://127.0.0.1/x", "not a url"] {
            await #expect(throws: ACMETransportError.invalidURL) {
                _ = try await testing.send(ACMEHTTPRequest(method: .get, url: url, body: []))
            }
        }
    }

    @Test("듣는 쪽이 없으면 network")
    func connectionRefused() async throws {
        let port = try await LoopbackHTTPServer.unusedPort()
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        await #expect(throws: ACMETransportError.network) {
            _ = try await transport.send(ACMEHTTPRequest(method: .get, url: "http://127.0.0.1:\(port)/directory", body: []))
        }
    }
}

/// 루프백의 최소 HTTP/1.1 서버. 연결마다 요청 하나를 읽고 `respond`가 준 바이트를 보낸 뒤 닫는다. nil이면 답하지 않는다.
private final class LoopbackHTTPServer: Sendable {
    struct Request: Sendable {
        var line: String
        var headers: [(String, String)]
        var body: [UInt8]

        func header(_ name: String) -> String? {
            headers.first { $0.0.lowercased() == name }?.1
        }
    }

    private let listener: NWListener
    private let port: UInt16
    private final class State: Sendable {
        let value = Mutex<(requests: [Request], connections: [NWConnection])>(([], []))
    }

    private let state = State()

    var requests: [Request] { state.value.withLock { $0.requests } }

    func url(_ path: String) -> String { "http://127.0.0.1:\(port)\(path)" }

    init(respond: @escaping @Sendable (Request) -> [UInt8]?) async throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener
        let state = state
        listener.newConnectionHandler = { connection in
            state.value.withLock { $0.connections.append(connection) }
            connection.start(queue: .global())
            Self.read(connection, buffer: []) { request in
                state.value.withLock { $0.requests.append(request) }
                guard let response = respond(request) else { return }
                connection.send(content: Data(response), completion: .contentProcessed { _ in
                    connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                })
            }
        }
        port = try await Self.start(listener)
    }

    func close() {
        listener.cancel()
        state.value.withLock { state in
            for connection in state.connections { connection.cancel() }
            state.connections = []
        }
    }

    static func response(status: String, headers: [(String, String)], body: [UInt8]) -> [UInt8] {
        var head = "HTTP/1.1 \(status)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n"
        for (name, value) in headers { head += "\(name): \(value)\r\n" }
        return Array((head + "\r\n").utf8) + body
    }

    /// 잠깐 열었다 닫은 포트. 그 뒤로 듣는 쪽이 없다.
    static func unusedPort() async throws -> UInt16 {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { $0.cancel() }
        let port = try await start(listener)
        listener.cancel()
        return port
    }

    private static func start(_ listener: NWListener) async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
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
            listener.start(queue: .global())
        }
    }

    /// 머리 끝(`\r\n\r\n`)과 `Content-Length`만큼의 본문을 읽는다.
    private static func read(_ connection: NWConnection, buffer: [UInt8], then handle: @escaping @Sendable (Request) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, error in
            var buffer = buffer
            if let data { buffer.append(contentsOf: data) }
            if let request = parse(buffer) {
                handle(request)
            } else if error == nil, !isComplete {
                read(connection, buffer: buffer, then: handle)
            }
        }
    }

    private static func parse(_ buffer: [UInt8]) -> Request? {
        let separator = Array("\r\n\r\n".utf8)
        guard let end = (0...max(0, buffer.count - separator.count)).first(where: { buffer[$0...].starts(with: separator) }),
              buffer.count >= separator.count
        else { return nil }
        let lines = String(decoding: buffer[..<end], as: UTF8.self).components(separatedBy: "\r\n")
        let headers = lines.dropFirst().compactMap { line -> (String, String)? in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            return (String(line[..<colon]), line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
        }
        let length = headers.first { $0.0.lowercased() == "content-length" }.flatMap { Int($0.1) } ?? 0
        let body = Array(buffer[(end + separator.count)...])
        guard body.count >= length else { return nil }
        return Request(line: lines.first ?? "", headers: headers, body: Array(body.prefix(length)))
    }
}
