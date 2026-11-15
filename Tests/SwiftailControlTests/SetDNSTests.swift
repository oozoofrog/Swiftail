// `ControlClient.setDNS(name:value:)`: 계약 `docs/contracts/SwiftailHost.md` 동작 D, 단위 시험 2.
// 가짜 제어 서버(`SetDNSFakeControlServer`)와 실제 연결(업그레이드 → Noise → HTTP/2)로 돈다.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl

@Suite("제어 클라이언트: set-dns", .timeLimit(.minutes(1)))
struct SetDNSTests {
    static let name = "_acme-challenge.rd-mac-1a2b3c4d.tail0001.ts.net"
    /// DNS-01 TXT 값의 모양(따옴표 없는 base64url 43자). 시험용 고정 값이다.
    static let value = "Zm9vYmFyLWFjbWUtY2hhbGxlbmdlLXZhbHVlLTEyMzQ"

    /// 가짜 서버와 클라이언트를 띄우고 `body`를 돌린다. 클라이언트의 `run()`은 끝나면 취소한다.
    private func withClient<T>(
        timeouts: ControlClient.Timeouts = ControlClient.Timeouts(),
        storedIdentity: NodeIdentity? = nil,
        prepare: (SetDNSFakeControlServer) -> Void = { _ in },
        _ body: (ControlClient, SetDNSFakeControlServer) async throws -> T
    ) async throws -> T {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        prepare(server)
        let url = try await server.start()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-setdns-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = NodeIdentityStore(directory: directory)
        if let storedIdentity { try store.save(storedIdentity) }
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d"), identityStore: store, timeouts: timeouts
        )
        let running = Task { try await client.run() }
        defer { running.cancel() }
        return try await body(client, server)
    }

    /// 맵 스트림이 열릴 때까지 기다린다(등록과 상태 올리기를 마친 뒤다).
    private func waitForMapStream(_ server: SetDNSFakeControlServer) async throws {
        try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
    }

    private func setDNSError(_ client: ControlClient, name: String = Self.name, value: String = Self.value) async -> ControlError? {
        do throws(ControlError) {
            try await client.setDNS(name: name, value: value)
            return nil
        } catch {
            return error
        }
    }

    // MARK: 요청

    @Test("맵 롱폴이 걸린 연결 위의 새 스트림으로 POST /machine/set-dns를 보내고, 맵 스트림은 그대로 열려 있다")
    func requestOverOpenConnection() async throws {
        try await withClient { client, server in
            try await waitForMapStream(server)
            let mapStream = try #require(server.openMapStreams.first)
            try await client.setDNS(name: Self.name, value: Self.value)

            let request = try #require(server.setDNSRequests.first)
            #expect(server.setDNSRequests.count == 1)
            #expect(request.method == "POST")
            #expect(request.path == "/machine/set-dns")
            #expect(request.connection == Int(mapStream[0]), "맵 스트림과 다른 연결로 보냈다")
            #expect(request.stream != mapStream[1])
            #expect(server.openMapStreams.contains(mapStream), "set-dns가 맵 스트림을 끊었다")
            // 다시 잇지 않았다.
            #expect(server.keyRequests == 1)
        }
    }

    @Test("요청의 머리와 본문: Content-Type, Ts-Lb, Version 148, NodeKey, Name, Type TXT, 따옴표 없는 Value")
    func requestHeadersAndBody() async throws {
        try await withClient { client, server in
            try await waitForMapStream(server)
            try await client.setDNS(name: Self.name, value: Self.value)

            let request = try #require(server.setDNSRequests.first)
            let register = try #require(server.requests.first { $0.path == "/machine/register" })
            let registered = try #require(register.header("ts-lb"))
            #expect(request.header("content-type") == "application/json")
            #expect(request.header("ts-lb") == registered)

            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            #expect(Set(object.keys) == ["Version", "NodeKey", "Name", "Type", "Value"])
            #expect(object["Version"] as? Int == 148)
            #expect(object["NodeKey"] as? String == registered)
            #expect(object["Name"] as? String == Self.name)
            #expect(object["Type"] as? String == "TXT")
            #expect(object["Value"] as? String == Self.value)
            #expect(Self.value.utf8.count == 43)
        }
    }

    // MARK: 응답

    @Test("200과 JSON 객체면 성공이다", arguments: ["{}", #"{"Unknown":1}"#, " { } "])
    func successfulObject(_ body: String) async throws {
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: Array(body.utf8))) }) { client, server in
            try await waitForMapStream(server)
            try await client.setDNS(name: Self.name, value: Self.value)
        }
    }

    @Test("200이어도 본문이 JSON 객체가 아니면 실패다(Go는 null을 받는다)", arguments: ["", "null", "[]", #""x""#, "1", "{", "{} {}"])
    func nonObjectBody(_ body: String) async throws {
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: Array(body.utf8))) }) { client, server in
            try await waitForMapStream(server)
            guard case .connection? = await setDNSError(client) else {
                Issue.record("객체가 아닌 본문 \(body.debugDescription)을 받아들였다")
                return
            }
        }
    }

    @Test("200이 아니면 상태 코드를 싣고, 서버의 본문(이름이 든 것)은 오류에 싣지 않는다", arguments: [400, 403, 404, 429, 500, 503])
    func rejected(_ status: Int) async throws {
        let echoed = Array("record \(Self.name) = \(Self.value) refused".utf8)
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: status, body: echoed)) }) { client, server in
            try await waitForMapStream(server)
            let error = await setDNSError(client)
            guard case .http(status)? = error else {
                Issue.record("상태 \(status)가 http(status:)로 오지 않았다: \(String(describing: error))")
                return
            }
            Self.expectNoSecrets(in: error)
        }
    }

    @Test("200 본문은 4KiB까지 받고, 넘으면 실패다")
    func responseLimit() async throws {
        // `{"a":"…"}`를 정확히 4,096바이트로 채운다.
        let exact = Array(#"{"a":""#.utf8) + [UInt8](repeating: UInt8(ascii: "x"), count: 4096 - 8) + Array(#""}"#.utf8)
        #expect(exact.count == ControlClient.maximumSetDNSResponseSize)
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: exact)) }) { client, server in
            try await waitForMapStream(server)
            try await client.setDNS(name: Self.name, value: Self.value)
        }

        let over = Array(#"{"a":""#.utf8) + [UInt8](repeating: UInt8(ascii: "x"), count: 4096 - 7) + Array(#""}"#.utf8)
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: over)) }) { client, server in
            try await waitForMapStream(server)
            guard case .connection? = await setDNSError(client) else {
                Issue.record("4KiB를 넘는 본문을 받아들였다")
                return
            }
        }
    }

    // MARK: 기한과 연결

    @Test("서버가 답하지 않으면 기한에 connection으로 끝나고, 이름과 값은 오류에 없다")
    func noAnswer() async throws {
        var timeouts = ControlClient.Timeouts()
        timeouts.setDNS = .seconds(1)
        try await withClient(timeouts: timeouts, prepare: { $0.setSetDNSReply(.never) }) { client, server in
            try await waitForMapStream(server)
            let start = ContinuousClock.now
            let error = await setDNSError(client)
            let elapsed = ContinuousClock.now - start
            guard case .connection? = error else {
                Issue.record("답 없는 서버가 connection으로 끝나지 않았다: \(String(describing: error))")
                return
            }
            #expect(elapsed >= .milliseconds(900) && elapsed < .seconds(5), "기한이 맞지 않는다: \(elapsed)")
            #expect(server.setDNSRequests.count == 1)
            Self.expectNoSecrets(in: error)
        }
    }

    @Test("등록한 신원이 있고 연결이 아직 없으면 설 때까지 기다렸다가 보낸다")
    func waitsForConnection() async throws {
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        try await withClient(storedIdentity: identity, prepare: { $0.setAcceptsConnections(false) }) { client, server in
            // 첫 /key 시도가 왔으면 run()은 저장된 신원을 읽었다.
            try await server.wait("연결 시도가 오지 않았다") { $0.keyRequests >= 1 }
            async let sent: ControlError? = setDNSError(client)
            try await Task.sleep(for: .milliseconds(300))
            #expect(server.setDNSRequests.isEmpty)
            server.setAcceptsConnections(true)
            let error = await sent
            #expect(error == nil, "연결이 선 뒤에도 실패했다: \(String(describing: error))")
            let request = try #require(server.setDNSRequests.first)
            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            #expect(object["NodeKey"] as? String == identity.nodePublicKey?.description)
        }
    }

    @Test("연결이 기한 안에 서지 않으면 connection으로 끝나고 요청은 나가지 않는다")
    func connectionNeverComes() async throws {
        var timeouts = ControlClient.Timeouts()
        timeouts.setDNS = .seconds(1)
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        try await withClient(timeouts: timeouts, storedIdentity: identity, prepare: { $0.setAcceptsConnections(false) }) { client, server in
            try await server.wait("연결 시도가 오지 않았다") { $0.keyRequests >= 1 }
            let start = ContinuousClock.now
            let error = await setDNSError(client)
            let elapsed = ContinuousClock.now - start
            guard case .connection? = error else {
                Issue.record("연결 없는 기한이 connection으로 끝나지 않았다: \(String(describing: error))")
                return
            }
            #expect(elapsed >= .milliseconds(900) && elapsed < .seconds(5), "기한이 맞지 않는다: \(elapsed)")
            #expect(server.setDNSRequests.isEmpty)
        }
    }

    @Test("등록 전(node 키 없음)이면 기다리지 않고 곧바로 실패한다")
    func beforeRegistration() async throws {
        try await withClient(prepare: { $0.setAcceptsConnections(false) }) { client, server in
            try await server.wait("연결 시도가 오지 않았다") { $0.keyRequests >= 1 }
            let start = ContinuousClock.now
            guard case .connection? = await setDNSError(client) else {
                Issue.record("등록 전의 set-dns가 connection으로 끝나지 않았다")
                return
            }
            #expect(ContinuousClock.now - start < .seconds(1), "등록 전인데 기다렸다")
            #expect(server.setDNSRequests.isEmpty)
        }
    }

    @Test("이름이나 값이 비면 invalidConfiguration이고 요청은 나가지 않는다", arguments: [("", "v"), ("n", "")])
    func emptyArguments(_ arguments: (String, String)) async throws {
        try await withClient { client, server in
            try await waitForMapStream(server)
            guard case .invalidConfiguration? = await setDNSError(client, name: arguments.0, value: arguments.1) else {
                Issue.record("빈 인자를 받아들였다")
                return
            }
            #expect(server.setDNSRequests.isEmpty)
        }
    }

    /// 오류의 문자열(연관 값 포함)에 레코드 이름·도메인·값이 없다(계약 동작 K2·K3).
    private static func expectNoSecrets(in error: ControlError?, sourceLocation: SourceLocation = #_sourceLocation) {
        let text = String(describing: error) + String(reflecting: error)
        for secret in [name, "tail0001", value] {
            #expect(!text.contains(secret), "오류 문자열에 \(secret)가 남았다: \(text)", sourceLocation: sourceLocation)
        }
    }
}
