// `URLSessionAuthKeyTransport`를 루프백의 작은 평문 HTTP/1.1 서버(시험 안의 `NWListener`)로 본다(계약 K5): 선 위의
// 머리와 본문, 리다이렉트를 따르지 않음, 본문 한도, 취소. 실제 인터넷에는 나가지 않는다.
// 서버는 `Tests/SwiftailCertificatesTests/ACME/URLSessionACMETransportTests.swift`의 것을 줄여 옮겼다(시험 타깃끼리
// 나눠 쓸 수 없다).

import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailPairing

@Suite("URLSession 인증 키 전송", .serialized)
struct URLSessionAuthKeyTransportTests {
    @Test("issue의 요청들이 선 위에서 POST·Authorization·Content-Type·본문을 싣고 쿠키는 없다")
    func wireShape() async throws {
        let server = try await LoopbackHTTPServer { request in
            if request.line.hasPrefix("POST /api/v2/oauth/token ") {
                // 머리 방식은 거절하고 본문 방식만 받는다.
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

    @Test("리다이렉트를 따르지 않고 3xx를 돌려준다")
    func noRedirect() async throws {
        let target = Mutex("")
        let server = try await LoopbackHTTPServer { _ in
            LoopbackHTTPServer.response(status: "307 Temporary Redirect", headers: [("Location", target.withLock { $0 })], body: [])
        }
        defer { server.close() }
        target.withLock { $0 = server.url("/elsewhere") }
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: Example.url(server.url("")))
        await #expect(throws: AuthKeyIssueError.http(status: 307)) { try await issuer.issue(lifetime: .seconds(60)) }
        // 머리 방식과 본문 방식의 토큰 요청 둘뿐이고, 리다이렉트 대상(/elsewhere)에는 가지 않는다.
        #expect(server.requests.map(\.line) == ["POST /api/v2/oauth/token HTTP/1.1", "POST /api/v2/oauth/token HTTP/1.1"])
    }

    @Test("본문은 64KiB까지 받고 넘으면 invalidResponse")
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

    @Test("듣는 쪽이 없으면 network")
    func connectionRefused() async throws {
        let port = try await LoopbackHTTPServer.unusedPort()
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: Example.url("http://127.0.0.1:\(port)"))
        await #expect(throws: AuthKeyIssueError.network) { try await issuer.issue(lifetime: .seconds(60)) }
    }

    @Test("Task를 취소하면 cancelled")
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

    /// 잠깐 열었다 닫은 포트. 그 뒤로 듣는 쪽이 없다.
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
