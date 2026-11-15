// `ControlClient.logOut()`의 독립 검토가 보탠 시험. 계약 `docs/contracts/SwiftailHost.md` "로그아웃" 동작 O.
// `LogoutTests`가 보지 않는 곳을 본다: 응답 전 단계(`/key`, 업그레이드)에서 멈춘 서버의 기한, 도중 취소, 깨진 신원 파일,
// 신원 파일이 바이트까지 그대로인지, 거절 메시지의 인증 키 가림, 큰 응답, 그리고 로그아웃한 키로 다시 `run()`했을 때
// 운영 서버에서 일어날 법한 흐름(만료 → 새 키 등록에 로그인 요구).

import CryptoKit
import Foundation
import Network
import Synchronization
import Testing

import SwiftailBase
@testable import SwiftailControl

/// 받기만 하고 답하지 않는 서버. `answersKey`면 `GET /key`에는 답하고 그 뒤(업그레이드)에서 멈춘다.
private final class StallingServer: Sendable {
    private struct State {
        var connections: [NWConnection] = []
        var opened = 0
        /// 상대가 닫았거나 끊긴 연결 수.
        var closed = 0
    }

    private let listener: NWListener
    private let state = Mutex(State())
    private let answersKey: Bool

    init(answersKey: Bool) throws {
        self.answersKey = answersKey
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.state.withLock {
                $0.connections.append(connection)
                $0.opened += 1
            }
            connection.start(queue: .global())
            self.read(connection, received: [])
        }
    }

    var opened: Int { state.withLock { $0.opened } }
    var closed: Int { state.withLock { $0.closed } }

    private func read(_ connection: NWConnection, received: [UInt8]) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if isComplete || error != nil {
                self.state.withLock { $0.closed += 1 }
                connection.cancel()
                return
            }
            let received = received + [UInt8](data ?? Data())
            if self.answersKey, String(decoding: received, as: UTF8.self).hasPrefix("GET /key"),
               String(decoding: received, as: UTF8.self).contains("\r\n\r\n") {
                let key = MachinePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
                let body = #"{"publicKey":"\#(key)"}"#
                let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
                self.state.withLock { $0.closed += 1 }
                return
            }
            self.read(connection, received: received)
        }
    }

    func start() async throws -> URL {
        let listener = listener
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
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
        return try #require(URL(string: "http://127.0.0.1:\(port)"))
    }

    func close() {
        listener.cancel()
        for connection in state.withLock({ $0.connections }) { connection.cancel() }
    }
}

@Suite("제어 클라이언트: 로그아웃(검토)", .timeLimit(.minutes(1)))
struct LogoutReviewTests {
    static let authKey = "tskey-auth-fake0001"

    private static func temporaryStore() -> (NodeIdentityStore, URL) {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-logout-review-\(UUID().uuidString)")
        return (NodeIdentityStore(directory: directory), directory)
    }

    private static func registeredIdentity() -> NodeIdentity {
        NodeIdentity(machineKey: .init(), nodeKey: .init())
    }

    private func logOutError(_ client: ControlClient) async -> ControlError? {
        do throws(ControlError) {
            try await client.logOut()
            return nil
        } catch {
            return error
        }
    }

    private func waitUntil(_ what: String, within duration: Duration = .seconds(5), _ condition: () -> Bool) async {
        let deadline = ContinuousClock.now + duration
        while !condition() {
            guard ContinuousClock.now < deadline else {
                Issue.record("\(duration) 안에 \(what)")
                return
            }
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    // MARK: 기한 (동작 O5)

    @Test("서버가 /key나 업그레이드에서 멈춰도 기한에 connection으로 끝나고 연결이 남지 않는다", arguments: [false, true])
    func deadlineBeforeRegister(answersKey: Bool) async throws {
        let server = try StallingServer(answersKey: answersKey)
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        var timeouts = ControlClient.Timeouts()
        timeouts.logout = .milliseconds(500)
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store, timeouts: timeouts
        )

        let start = ContinuousClock.now
        guard case .connection? = await logOutError(client) else {
            Issue.record("connection이 아니다")
            return
        }
        let elapsed = ContinuousClock.now - start
        #expect(elapsed >= .milliseconds(500) && elapsed < .seconds(3), "기한에 끝나야 한다: \(elapsed)")
        let expected = answersKey ? 2 : 1
        #expect(server.opened == expected)
        await waitUntil("클라이언트가 연결을 닫는다") { server.closed == server.opened }
    }

    @Test("도중에 취소하면 곧 connection으로 끝나고 신원 파일은 그대로다")
    func cancellation() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.setRegisterNeverAnswers(true)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let before = try Data(contentsOf: store.fileURL)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        let task = Task { await logOutError(client) }
        try await server.wait("로그아웃 요청이 온다") { $0.requests.count == 1 }
        let start = ContinuousClock.now
        task.cancel()
        guard case .connection? = await task.value else {
            Issue.record("connection이 아니다")
            return
        }
        #expect(ContinuousClock.now - start < .seconds(3), "기본 기한(10초)을 기다리지 않는다")
        #expect(try Data(contentsOf: store.fileURL) == before)
    }

    // MARK: 로컬 파일 (동작 O6)

    @Test("성공한 로그아웃은 신원 파일을 바이트까지 그대로 두고, 디렉터리에 다른 파일을 만들지 않는다")
    func identityFileUntouched() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let before = try Data(contentsOf: store.fileURL)
        let modified = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.modificationDate] as? Date
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        try await client.logOut()

        #expect(server.requests.count == 1)
        #expect(try Data(contentsOf: store.fileURL) == before)
        #expect(try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.modificationDate] as? Date == modified)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [store.fileURL.lastPathComponent])
    }

    @Test("NL 키가 없는 옛 신원 파일: 요청은 가고(NLKey는 0이 아님) 파일에 NL 키를 써넣지 않는다")
    func oldIdentityFileWithoutLockKey() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        // 저장된 파일에서 NLKey만 뺀다.
        var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: store.fileURL)) as? [String: Any])
        #expect(object.removeValue(forKey: "NLKey") != nil)
        let old = try JSONSerialization.data(withJSONObject: object)
        try old.write(to: store.fileURL)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        try await client.logOut()

        let request = try #require(server.requests.first)
        let body = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
        #expect(body["NLKey"] as? String != NLPublicKey.zero.description)
        #expect(try Data(contentsOf: store.fileURL) == old)
    }

    @Test("신원 파일이 깨졌으면 storage이고, 서버에 아무것도 보내지 않으며 파일을 고치지 않는다")
    func corruptedIdentity() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let garbage = Data("{not json".utf8)
        try garbage.write(to: store.fileURL)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        guard case .storage? = await logOutError(client) else {
            Issue.record("storage가 아니다")
            return
        }
        #expect(server.keyRequests == 0)
        #expect(server.requests.isEmpty)
        #expect(try Data(contentsOf: store.fileURL) == garbage)
    }

    // MARK: 오류 (동작 O4·O7)

    @Test("/key가 200이 아니면 http(status:)다")
    func keyStatus() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.setAcceptsConnections(false)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)
        guard case .http(status: 500)? = await logOutError(client) else {
            Issue.record("http(500)이 아니다")
            return
        }
    }

    @Test("거절 메시지에서 인증 키(원문과 --TL 앞부분)를 가리고 200자로 자른다. 오류 문자열에 키가 없다")
    func rejectionHidesSecrets() async throws {
        let wrapped = Self.authKey + "--TL0001-fakefakefake"
        let identity = Self.registeredIdentity()
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.enqueueRegisterReply(#"{"Error":"bad key \#(wrapped) and \#(Self.authKey) \#(String(repeating: "x", count: 400))"}"#)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(identity)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: wrapped), identityStore: store)

        let error = try #require(await logOutError(client))
        guard case .registrationRejected(let message) = error else {
            Issue.record("registrationRejected가 아니다: \(error)")
            return
        }
        #expect(message.count <= ControlClient.maximumRejectionLength + 1)
        let text = String(describing: error) + String(reflecting: error)
        #expect(!text.contains(Self.authKey))
        #expect(!text.contains("--TL"))
        #expect(!text.contains(try #require(identity.nodePublicKey).description))
        // 요청에도 인증 키가 없다(감싼 키여도).
        let body = String(decoding: try #require(server.requests.first).body, as: UTF8.self)
        #expect(!body.contains("tskey-") && !body.contains("--TL"))
    }

    @Test("1MiB를 넘는 응답은 connection으로 끝난다")
    func oversizedResponse() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.enqueueRegisterReply(#"{"Error":"\#(String(repeating: "x", count: (1 << 20) + 16))"}"#)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)
        guard case .connection? = await logOutError(client) else {
            Issue.record("connection이 아니다")
            return
        }
        #expect(server.requests.count == 1)
    }

    // MARK: 로그아웃한 키로 다시 run() (계약 "시험과 관문"의 운영 서버 쪽 짐작)

    /// 운영 서버에서 일어날 법한 흐름: 저장된(로그아웃한) 키의 등록에 `NodeKeyExpired`, 새 키의 등록에 `AuthURL`(로그인 요구),
    /// 로그인 뒤 Followup에 성공. testcontrol 사본처럼 만료 시각을 새 키로 옮기지 않는 서버다.
    @Test("로그아웃한 키로 다시 run(): 만료 → 새 키(OldNodeKey = 옛 키)로 등록 → loginRequired → Followup → 새 키 저장", arguments: [nil, authKey])
    func runAfterLogout(authKey: String?) async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let authURL = "https://login.example.test/a/0001"
        server.enqueueRegisterReply(#"{"NodeKeyExpired":true}"#)
        server.enqueueRegisterReply(#"{"AuthURL":"\#(authURL)"}"#)
        server.enqueueRegisterReply(#"{"MachineAuthorized":true}"#)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        let identity = Self.registeredIdentity()
        let oldKey = try #require(identity.nodePublicKey)
        try store.save(identity)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: authKey), identityStore: store)

        let run = Task { () -> ControlError? in
            do throws(ControlError) {
                try await client.run()
                return nil
            } catch {
                return error
            }
        }
        defer { run.cancel() }
        var loginURL: URL?
        var registered: NodePublicKey?
        for await event in client.events {
            if case .loginRequired(let url) = event { loginURL = url }
            if case .registered(let key) = event {
                registered = key
                break
            }
        }

        let registers = server.requests.filter { $0.path == "/machine/register" }
        let bodies = try registers.map { try #require(try JSONSerialization.jsonObject(with: Data($0.body)) as? [String: Any]) }
        try #require(bodies.count == 3)
        #expect(bodies[0]["NodeKey"] as? String == oldKey.description)
        #expect(bodies[0]["Auth"] == nil, "저장된 키의 등록에는 인증 키를 싣지 않는다")
        let newKey = try #require(bodies[1]["NodeKey"] as? String)
        #expect(newKey != oldKey.description)
        #expect(bodies[1]["OldNodeKey"] as? String == oldKey.description)
        #expect((bodies[1]["Auth"] != nil) == (authKey != nil))
        #expect(bodies[1]["Followup"] as? String == "")
        #expect(bodies[2]["NodeKey"] as? String == newKey)
        #expect(bodies[2]["Followup"] as? String == authURL)
        #expect(bodies.allSatisfy { $0["Expiry"] as? String == "0001-01-01T00:00:00Z" }, "등록에는 Expiry가 없다")
        #expect(loginURL?.absoluteString == authURL)
        #expect(registered?.description == newKey)
        #expect(try store.load()?.nodePublicKey?.description == newKey)

        run.cancel()
        #expect(await run.value == nil, "run()은 nodeKeyExpired로 끝나지 않는다")
    }
}
