// Tests `URLSessionACMETransport` against a small plaintext HTTP/1.1 loopback server (an in-test `NWListener`) for delivery of request headers
// and bodies, response headers, body limits, request deadlines, redirects left unfollowed, and restrictions on the plaintext path. The tests never reach the real internet.

import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailCertificates

@Suite("URLSession ACME transport", .serialized)
struct URLSessionACMETransportTests {
    @Test("Sends POST headers and body and returns the response status, headers, and body")
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

    @Test("Sends HEAD and GET without a body")
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

    @Test("Accepts a body up to the limit and returns responseTooLarge above it")
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

    @Test("The default body limit is 256KiB")
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

    @Test("Returns timedOut if a request exceeds its deadline")
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

    @Test("Returns the original 3xx without following redirects")
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

    @Test("Sends plaintext http only to loopback hosts on the test path")
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

    @Test("Returns network when nothing is listening")
    func connectionRefused() async throws {
        let port = try await LoopbackHTTPServer.unusedPort()
        let transport = URLSessionACMETransport(trustAnchors: nil, allowsLoopbackHTTP: true)
        await #expect(throws: ACMETransportError.network) {
            _ = try await transport.send(ACMEHTTPRequest(method: .get, url: "http://127.0.0.1:\(port)/directory", body: []))
        }
    }
}

/// A minimal loopback HTTP/1.1 server. Reads one request per connection, sends the bytes from `respond`, and closes. A nil value sends no response.
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

    /// A port that was opened briefly and then closed, with nothing listening afterward.
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

    /// Reads through the end of the headers (`\r\n\r\n`) and reads the body for `Content-Length` bytes.
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
