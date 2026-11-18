// `ControlClient.logOut()`: 계약 `docs/contracts/SwiftailHost.md` "로그아웃" 동작 O, 시험 "단위".
// 가짜 제어 서버(`SetDNSFakeControlServer`)와 실제 연결(업그레이드 → Noise → HTTP/2)로 돈다. `run()`은 부르지 않는다.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl

@Suite("제어 클라이언트: 로그아웃", .timeLimit(.minutes(1)))
struct LogoutTests {
    /// 시험용 가짜 인증 키. 로그아웃 요청에 실리지 않아야 한다.
    static let authKey = "tskey-auth-fake0001"

    /// 가짜 서버와 (저장된 신원이 있으면 그것을 쓰는) 클라이언트를 만들어 `body`를 돌린다.
    private func withClient<T>(
        storedIdentity: NodeIdentity?,
        timeouts: ControlClient.Timeouts = ControlClient.Timeouts(),
        prepare: (SetDNSFakeControlServer) -> Void = { _ in },
        _ body: (ControlClient, SetDNSFakeControlServer, NodeIdentityStore) async throws -> T
    ) async throws -> T {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        prepare(server)
        let url = try await server.start()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-logout-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = NodeIdentityStore(directory: directory)
        if let storedIdentity { try store.save(storedIdentity) }
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: Self.authKey),
            identityStore: store,
            timeouts: timeouts
        )
        return try await body(client, server, store)
    }

    private func logOutError(_ client: ControlClient) async -> ControlError? {
        do throws(ControlError) {
            try await client.logOut()
            return nil
        } catch {
            return error
        }
    }

    private static func registeredIdentity() -> NodeIdentity {
        NodeIdentity(machineKey: .init(), nodeKey: .init())
    }

    // MARK: 요청

    @Test("요청: 저장된 node 키 그대로, Expiry는 1970-01-01T00:02:03Z, 인증 키·Followup·OldNodeKey·서명 없음, 신원 파일은 그대로")
    func requestShape() async throws {
        let identity = Self.registeredIdentity()
        let nodeKey = try #require(identity.nodePublicKey)
        try await withClient(storedIdentity: identity) { client, server, store in
            try await client.logOut()

            #expect(server.keyRequests == 1)
            #expect(server.requests.count == 1, "로그아웃은 요청 하나다")
            let request = try #require(server.requests.first)
            #expect(request.method == "POST")
            #expect(request.path == "/machine/register")
            #expect(request.header("ts-lb") == nodeKey.description)

            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            #expect(Set(object.keys) == ["Version", "NodeKey", "OldNodeKey", "NLKey", "Expiry", "Followup", "Hostinfo", "NodeKeySignature"],
                    "Auth·Ephemeral이 없어야 한다")
            #expect(object["Version"] as? Int == 148)
            #expect(object["NodeKey"] as? String == nodeKey.description, "새 node 키를 만들지 않는다")
            #expect(object["OldNodeKey"] as? String == NodePublicKey.zero.description)
            #expect(object["NLKey"] as? String == identity.lockPublicKey.description)
            #expect(object["Expiry"] as? String == "1970-01-01T00:02:03Z", "Go time.Unix(123, 0)의 JSON")
            #expect(object["Followup"] as? String == "")
            #expect(object["NodeKeySignature"] is NSNull)
            let hostinfo = try #require(object["Hostinfo"] as? [String: Any])
            #expect(hostinfo["Hostname"] as? String == "rd-mac-1a2b3c4d")
            #expect(!String(decoding: request.body, as: UTF8.self).contains(Self.authKey))

            let stored = try #require(try store.load())
            #expect(stored.nodePublicKey == nodeKey, "신원 파일의 node 키가 바뀌지 않는다")
            #expect(stored.machinePublicKey == identity.machinePublicKey)
            #expect(stored.lockPublicKey == identity.lockPublicKey)
        }
    }

    @Test("신원 파일이 없거나 node 키가 없으면 서버에 아무것도 보내지 않고, 파일도 만들지 않는다")
    func noIdentity() async throws {
        try await withClient(storedIdentity: nil) { client, server, store in
            try await client.logOut()
            #expect(server.keyRequests == 0)
            #expect(server.requests.isEmpty)
            #expect(try store.load() == nil, "신원 파일을 만들지 않는다")
        }
        try await withClient(storedIdentity: NodeIdentity()) { client, server, _ in
            try await client.logOut()
            #expect(server.keyRequests == 0)
            #expect(server.requests.isEmpty)
        }
    }

    // MARK: 응답

    @Test("응답의 Error는 registrationRejected이고, 다시 시도하지 않는다")
    func rejected() async throws {
        try await withClient(storedIdentity: Self.registeredIdentity(), prepare: {
            $0.enqueueRegisterReply(#"{"Error":"logout denied"}"#)
        }) { client, server, _ in
            guard case .registrationRejected(let message)? = await logOutError(client) else {
                Issue.record("registrationRejected가 아니다")
                return
            }
            #expect(message == "logout denied")
            #expect(server.requests.count == 1)
        }
    }

    @Test("NodeKeyExpired·AuthURL·NodeKeySignature가 와도 성공이고 따르지 않는다(요청 하나, 키 그대로)", arguments: [
        #"{"NodeKeyExpired":true}"#,
        #"{"AuthURL":"https://login.example.test/a/0001"}"#,
        #"{"NodeKeySignature":"AAEC"}"#,
        #"{}"#,
    ])
    func otherResponsesSucceed(_ reply: String) async throws {
        let identity = Self.registeredIdentity()
        try await withClient(storedIdentity: identity, prepare: { $0.enqueueRegisterReply(reply) }) { client, server, store in
            try await client.logOut()
            #expect(server.requests.count == 1)
            #expect(try store.load()?.nodePublicKey == identity.nodePublicKey)
        }
    }

    @Test("서버가 답하지 않으면 기한에 connection으로 끝난다")
    func deadline() async throws {
        // 기한에는 키 조회와 Noise 연결도 들어간다. 운영 기한을 써서 요청을 받은 뒤 답을 기다리는 경우를 확인한다.
        let limit = ControlClient.Timeouts().logout
        try await withClient(storedIdentity: Self.registeredIdentity(), prepare: {
            $0.setRegisterNeverAnswers(true)
        }) { client, server, _ in
            let start = ContinuousClock.now
            async let result = logOutError(client)
            try await server.wait("로그아웃 요청이 도착하지 않았다", within: limit) {
                $0.requests.contains { $0.path == "/machine/register" }
            }
            guard case .connection(let message)? = await result else {
                Issue.record("connection이 아니다")
                return
            }
            #expect(message == "로그아웃이 \(limit) 안에 끝나지 않았다")
            #expect(start.duration(to: .now) >= limit)
            #expect(server.requests.map(\.path) == ["/machine/register"], "요청을 다시 보내지 않는다")
        }
    }

    @Test("기본 기한은 10초다")
    func defaultDeadline() {
        #expect(ControlClient.Timeouts().logout == .seconds(10))
    }

    @Test("서버 키를 받지 못하면 실패로 끝나고 다시 시도하지 않는다")
    func connectionFailureIsNotRetried() async throws {
        try await withClient(storedIdentity: Self.registeredIdentity(), prepare: { $0.setAcceptsConnections(false) }) { client, server, _ in
            let error = await logOutError(client)
            #expect(error != nil)
            #expect(server.keyRequests == 1)
            #expect(server.requests.isEmpty)
        }
    }
}
