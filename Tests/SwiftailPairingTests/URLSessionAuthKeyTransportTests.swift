// Tests `URLSessionAuthKeyTransport` against a small plaintext HTTP/1.1 loopback server (an in-test `NWListener`, contract K5) for on-wire
// headers and bodies, redirects left unfollowed, the body limit, and cancellation. The tests never reach the real internet.
// The server is a reduced copy of the one in `Tests/SwiftailCertificatesTests/ACME/URLSessionACMETransportTests.swift` because the test targets
// cannot share it.

import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailPairing

@Suite("URLSession auth key transport", .serialized)
struct URLSessionAuthKeyTransportTests {
    @Test("On the wire, issue sends POST requests with Authorization, Content-Type, and a body, and without cookies")
    func wireShape() async throws {
        let server = try await LoopbackHTTPServer { request in
            if request.line.hasPrefix("POST /api/v2/oauth/token ") {
                // Reject the header method and accept only the body method.
                guard request.header("authorization") == nil else {
                    return LoopbackHTTPServer.response(status: "401 Unauthorized", headers: [], body: Array(#"{"error":"invalid_client"}"#.utf8))
                }
                return LoopbackHTTPServer.response(status: "200 OK", headers: [("Set-Cookie", "s=EXAMPLE")],
                    body: Array(#"{"access_token":"tskey-api-EXAMPLE-token","token_type":"Bearer"}"#.utf8))
            }
            return LoopbackHTTPServer.response(status: "200 OK", headers: [],
                body: Array(#"{"key":"tskey-auth-EXAMPLE","expires":"2026-01-01T00:10:00Z"}"#.utf8))
        }
        defer { server.close() }
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: Example.url(server.url("")))
        let issued = try await issuer.issue(lifetime: .seconds(600))
        #expect(issued.key == Example.key)

        let requests = server.requests
        try #require(requests.count == 3)
        #expect(requests[0].line == "POST /api/v2/oauth/token HTTP/1.1")
        #expect(requests[0].header("authorization") == Example.basic)
        #expect(requests[0].header("content-type") == "application/x-www-form-urlencoded")
        #expect(requests[0].body == Array("grant_type=client_credentials".utf8))
        #expect(requests[1].line == "POST /api/v2/oauth/token HTTP/1.1")
        #expect(requests[1].header("authorization") == nil)
        #expect(requests[1].header("content-type") == "application/x-www-form-urlencoded")
        #expect(requests[1].body == Array(Example.parametersForm.utf8))
        #expect(requests[2].line == "POST /api/v2/tailnet/-/keys HTTP/1.1")
        #expect(requests[2].header("authorization") == "Bearer tskey-api-EXAMPLE-token")
        #expect(requests[2].header("content-type") == "application/json")
        #expect(requests.allSatisfy { $0.header("cookie") == nil })
    }

    @Test("Returns 3xx without following redirects")
    func noRedirect() async throws {
        let target = Mutex("")
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "307 Temporary Redirect", headers: [("Location", target.withLock { $0 })], body: [])
        }
        defer { server.close() }
        target.withLock { $0 = server.url("/elsewhere") }
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: Example.url(server.url("")))
        await #expect(throws: AuthKeyIssueError.http(status: 307)) { try await issuer.issue(lifetime: .seconds(60)) }
        // Only the two token requests, one using the header and one using the body, are sent. Neither goes to the redirect target (/elsewhere).
        #expect(server.requests.map(\.line) == ["POST /api/v2/oauth/token HTTP/1.1", "POST /api/v2/oauth/token HTTP/1.1"])
    }

    @Test("Accepts a body up to 64KiB and returns invalidResponse above the limit")
    func bodyLimit() async throws {
        let size = Mutex(64 * 1024)
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "200 OK", headers: [], body: [UInt8](repeating: 0x41, count: size.withLock { $0 }))
        }
        defer { server.close() }
        let transport = URLSessionAuthKeyTransport()
        let request = try AuthKeyHTTPRequest(url: Example.url(server.url("/a")), authorization: "Bearer x", contentType: "application/json", body: [])
        let exact = try await transport.send(request)
        #expect(exact.body.count == 64 * 1024)

        size.withLock { $0 = 64 * 1024 + 1 }
        await #expect(throws: AuthKeyIssueError.invalidResponse) { _ = try await transport.send(request) }
    }

    @Test("Returns network when nothing is listening")
    func connectionRefused() async throws {
        let port = try await LoopbackHTTPServer.unusedPort()
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: Example.url("http://127.0.0.1:\(port)"))
        await #expect(throws: AuthKeyIssueError.network) { try await issuer.issue(lifetime: .seconds(60)) }
    }

    @Test("Canceling the Task returns cancelled")
    func cancellation() async throws {
        let server = try await LoopbackHTTPServer { _ in nil }
        defer { server.close() }
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: Example.url(server.url("")))
        let task = Task { try await issuer.issue(lifetime: .seconds(60)) }
        while server.requests.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        task.cancel()
        await #expect(throws: AuthKeyIssueError.cancelled) { _ = try await task.value }
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
        port = try await Self.start(listener) { [state] connection in
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
        let port = try await start(listener) { $0.cancel() }
        listener.cancel()
        return port
    }

    private static func start(
        _ listener: NWListener, accept: @escaping @Sendable (NWConnection) -> Void
    ) async throws -> UInt16 {
        listener.newConnectionHandler = accept
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
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
        guard buffer.count >= separator.count,
              let end = (0...(buffer.count - separator.count)).first(where: { buffer[$0...].starts(with: separator) })
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
