import Foundation
import Testing

@testable import SwiftailControl

let controlFaultsBinary = ProcessInfo.processInfo.environment["SWIFTAIL_CONTROLFAULTS"].flatMap { $0.isEmpty ? nil : $0 }

/// 일부러 어긋나게 구는 제어 서버(`Tools/interop/cmd/controlfaults`)를 상대로 한 회귀 시험.
/// 클라이언트의 안쪽 상태는 보지 않고, 서버가 센 요청 수·사건·`run()`의 결과·신원 파일로 확인한다.
@Suite("제어 클라이언트: 어긋난 서버", .enabled(if: controlFaultsBinary != nil,
    "SWIFTAIL_CONTROLFAULTS가 없어 건너뜁니다"), .timeLimit(.minutes(2)))
struct ControlFaultsTests {
    @Test("상태 올리기에 서버가 답하지 않으면 기한 뒤 다시 연결한다")
    func statusUploadWithoutResponse() async throws {
        let timeouts = ControlClient.Timeouts(request: .seconds(1), followup: .seconds(1))
        try await withFaultClient("initialUploadHang", timeouts: timeouts) { server, client, _ in
            _ = try await server.wait("기한 뒤 두 번째 연결의 상태 올리기", timeout: .seconds(10)) {
                $0.connections >= 2 && $0.maps >= 2
            }
        }
    }

    @Test("등록 도중에 요청한 대화형 로그인은 그 등록이 끝난 뒤 새 키로 다시 등록한다")
    func interactiveLoginDuringRegistration() async throws {
        try await withFaultClient("interactiveRace") { server, client, _ in
            _ = try await server.wait("붙잡힌 첫 등록") { $0.registers == 1 }
            await client.client.startInteractiveLogin()
            try await server.release()
            let first = try await client.registered("첫 등록 완료")
            let second = try await client.registered("대화형 로그인의 새 등록")
            #expect(first != second, "대화형 로그인은 새 node 키로 등록한다")
            let probe = try await server.probe()
            #expect(probe.registers == 2)
            #expect(probe.nodeKeys == 2)
        }
    }

    @Test("Followup 도중 끊겨도 같은 후보 키와 Followup URL로 로그인을 이어서 기다린다")
    func followupSurvivesReconnect() async throws {
        try await withFaultClient("followupReconnect") { server, client, directory in
            var loginRequests = 0
            var registered: NodePublicKey?
            while registered == nil {
                switch try await client.next("loginRequired 뒤 등록 완료") {
                case .loginRequired: loginRequests += 1
                case .registered(let key): registered = key
                case .netmap, .disconnected: throw GateFailure("등록 전에 맵 사건이 왔다")
                }
            }
            #expect(loginRequests == 1, "사용자는 로그인 URL 하나만 받아야 한다")
            let probe = try await server.probe()
            #expect(probe.connections == 2)
            #expect(probe.followups == 2, "다시 연결한 뒤의 등록도 Followup이어야 한다")
            #expect(probe.nodeKeys == 1, "다시 연결해도 후보 키를 바꾸지 않는다")
            #expect(try NodeIdentityStore(directory: directory).load()?.nodePublicKey == registered)
        }
    }

    @Test("새 맵이 오지 않아도 self 키의 만료 시각이 지나면 새 키로 다시 등록한다")
    func selfKeyExpiresWithoutNewMap() async throws {
        try await withFaultClient("expiryTimer") { _, client, _ in
            let first = try await client.registered("첫 등록")
            let second = try await client.registered("만료 뒤 새 등록", timeout: .seconds(10))
            #expect(first != second)
        }
    }

    @Test("새 키로 다시 등록해도 만료면 nodeKeyExpired로 끝난다")
    func alwaysExpired() async throws {
        try await withFaultClient("alwaysExpired") { server, client, _ in
            let error = try await client.result(timeout: .seconds(10))
            guard case .nodeKeyExpired? = error else {
                Issue.record("nodeKeyExpired가 아니다: \(String(describing: error))")
                return
            }
            #expect(try await server.probe().registers == 2, "만료 뒤 새 키로 한 번만 다시 등록한다")
        }
    }

    @Test("소비하지 않은 사건은 가장 새 것 64개만 남는다")
    func eventBufferKeepsNewest() async throws {
        try await withFaultClient("manyMaps", observes: false) { server, client, _ in
            // 두 번째 맵 스트림 요청이 왔으면 첫 스트림의 응답 200개와 disconnected를 이미 냈다.
            _ = try await server.wait("두 번째 맵 스트림", timeout: .seconds(10)) { $0.maps >= 4 }
            _ = try await client.result(cancelling: true)
            var events: [ControlClient.Event] = []
            for await event in client.client.events { events.append(event) }
            #expect(events.count == 64)
            guard events.count >= 2, case .disconnected = events[events.count - 1],
                  case .netmap(let last) = events[events.count - 2] else {
                Issue.record("마지막 두 사건이 netmap, disconnected가 아니다")
                return
            }
            #expect(last.domain == "d199")
        }
    }

    @Test("거절 메시지가 되풀이한 인증 키는 오류에 남지 않는다")
    func rejectionHidesEchoedAuthKey() async throws {
        let controlValue = "tskey-auth-" + UUID().uuidString
        try await withFaultClient("authEcho", authKey: controlValue + "--TLsynthetic-material") { _, client, _ in
            let error = try await client.result(timeout: .seconds(10))
            guard case .registrationRejected(let message)? = error else {
                Issue.record("registrationRejected가 아니다")
                return
            }
            #expect(message.hasPrefix("invalid authkey: "))
            var dumped = ""
            dump(error, to: &dumped)
            for rendered in [message, dumped, String(describing: error)] {
                #expect(!rendered.contains(controlValue))
                #expect(!rendered.contains("synthetic-material"))
            }
        }
    }
}

// MARK: - 도구 실행

/// controlfaults 프로세스 하나. 표준 출력의 첫 줄이 서버 URL이고, 표준 입력을 닫으면 끝난다.
struct FaultServer: Sendable {
    struct Probe: Decodable, Sendable {
        var connections: Int
        var registers: Int
        var followups: Int
        var maps: Int
        var nodeKeys: Int
    }

    let url: URL

    func probe() async throws -> Probe {
        let (data, _) = try await URLSession.shared.data(from: url.appending(path: "probe"))
        return try JSONDecoder().decode(Probe.self, from: data)
    }

    /// 서버가 센 값이 `predicate`를 만족할 때까지 기다린다.
    func wait(
        _ description: String, timeout: Duration = .seconds(5), until predicate: (Probe) -> Bool
    ) async throws -> Probe {
        let deadline = ContinuousClock.now + timeout
        while true {
            let probe = try await probe()
            if predicate(probe) { return probe }
            guard ContinuousClock.now < deadline else { throw GateFailure("\(description) 제한 시간 초과 (\(timeout)): \(probe)") }
            try await Task.sleep(for: .milliseconds(20))
        }
    }

    /// interactiveRace 모드에서 붙잡은 첫 등록을 놓아 준다.
    func release() async throws {
        _ = try await URLSession.shared.data(from: url.appending(path: "release"))
    }
}

/// 서버를 띄우고 `body`를 부른다. 성공·실패 모두 프로세스와 신원 디렉터리를 회수한다.
func withFaultServer(_ mode: String, _ body: (FaultServer, URL) async throws -> Void) async throws {
    let binary = try #require(controlFaultsBinary)
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: binary)
    process.arguments = [mode]
    process.standardInput = input
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-faults-\(UUID().uuidString)")
    try process.run()
    defer {
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: directory)
    }
    var firstLine: String?
    for try await line in output.fileHandleForReading.bytes.lines {
        firstLine = line
        break
    }
    let url = try #require(firstLine.flatMap { URL(string: $0) }, "controlfaults가 주소를 출력하지 않았다")
    try await body(FaultServer(url: url), directory)
}

/// 서버를 띄우고 그 서버에 붙는 클라이언트의 `run()`을 돌린 채 `body`를 부른다.
/// 끝나면 `run()`을 취소하고 끝나기를 기다린다.
func withFaultClient(
    _ mode: String, authKey: String? = nil, timeouts: ControlClient.Timeouts = .init(), observes: Bool = true,
    _ body: (FaultServer, FaultClient, URL) async throws -> Void
) async throws {
    try await withFaultServer(mode) { server, directory in
        let client = FaultClient(server: server, directory: directory, authKey: authKey, timeouts: timeouts, observes: observes)
        do {
            try await body(server, client, directory)
            await client.stop()
        } catch {
            await client.stop()
            throw error
        }
    }
}

/// `run()`을 돌리고 사건을 받는다. 공개 API(사건, `run()`의 결과)만 본다.
struct FaultClient: Sendable {
    let client: ControlClient
    private let running: Task<ControlError?, Never>
    private let observed: AsyncStream<ControlClient.Event>?

    init(server: FaultServer, directory: URL, authKey: String?, timeouts: ControlClient.Timeouts, observes: Bool) {
        let client = ControlClient(
            configuration: .init(serverURL: server.url, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            identityStore: NodeIdentityStore(directory: directory),
            timeouts: timeouts
        )
        self.client = client
        running = Task {
            do throws(ControlError) { try await client.run(); return nil } catch { return error }
        }
        // 사건을 다른 흐름으로 옮겨 둔다. 기다림이 시간 초과로 취소되어도 클라이언트의 흐름은 끝나지 않는다.
        if observes {
            let (stream, continuation) = AsyncStream.makeStream(of: ControlClient.Event.self)
            observed = stream
            Task {
                for await event in client.events { continuation.yield(event) }
                continuation.finish()
            }
        } else {
            observed = nil
        }
    }

    func next(_ description: String, timeout: Duration = .seconds(5)) async throws -> ControlClient.Event {
        guard let observed else { throw GateFailure("사건을 관측하지 않는 클라이언트") }
        return try await nextEvent(observed, waitingFor: description, timeout: timeout)
    }

    /// 다음 `registered`까지 기다린다. 그 사이의 netmap·disconnected는 건너뛴다.
    func registered(_ description: String, timeout: Duration = .seconds(5)) async throws -> NodePublicKey {
        let deadline = ContinuousClock.now + timeout
        while true {
            switch try await next(description, timeout: ContinuousClock.now.duration(to: deadline)) {
            case .registered(let key): return key
            case .loginRequired: throw GateFailure("\(description): 예상하지 않은 loginRequired")
            case .netmap, .disconnected: continue
            }
        }
    }

    private enum Outcome: Sendable {
        case ended(ControlError?)
        case timedOut
    }

    /// `run()`이 끝나기를 기다린다. `cancelling`이면 먼저 취소한다. 끝나지 않으면 실패로 던진다.
    func result(timeout: Duration = .seconds(5), cancelling: Bool = false) async throws -> ControlError? {
        if cancelling { running.cancel() }
        let running = running
        let outcome = await withTaskGroup(of: Outcome.self) { group in
            group.addTask { .ended(await running.value) }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return .timedOut
            }
            let first = await group.next() ?? .timedOut
            // 그룹은 남은 자식을 기다리고 끝나므로, 시간 초과면 run()부터 취소해 그 자식을 풀어 준다.
            if case .timedOut = first { running.cancel() }
            group.cancelAll()
            return first
        }
        guard case .ended(let error) = outcome else { throw GateFailure("run()이 \(timeout) 안에 끝나지 않았다") }
        return error
    }

    /// `run()`을 취소하고 끝나기를 기다린다.
    func stop() async {
        running.cancel()
        _ = await running.value
    }
}
