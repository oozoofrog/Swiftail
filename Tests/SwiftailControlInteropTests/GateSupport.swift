import Foundation
import SwiftailBase
import SwiftailControl
import Testing

let tailnetBinary = ProcessInfo.processInfo.environment["SWIFTAIL_TAILNET"].flatMap { $0.isEmpty ? nil : $0 }

struct GateFailure: Error, Sendable, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// 사건과 마감 시각을 경쟁시킨다. 시간 초과는 시험을 끝내므로 취소된 구독을 재사용하지 않는다.
func nextEvent<T: Sendable>(
    _ stream: AsyncStream<T>, waitingFor description: String, timeout: Duration = .seconds(20)
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        defer { group.cancelAll() }
        group.addTask {
            for await event in stream { return event }
            throw GateFailure("\(description) 대기 중 사건 흐름 종료")
        }
        group.addTask {
            try await Task.sleep(for: timeout)
            throw GateFailure("\(description) 제한 시간 초과 (\(timeout))")
        }
        guard let event = try await group.next() else { throw GateFailure("\(description) 사건 없음") }
        return event
    }
}

/// 개인 키·인증 키·사용자 경로가 외부 도구의 진단에 섞여도 보고에 남기지 않는다.
func redacted(_ text: String) -> String {
    var result = text
    for pattern in [#"(?:privkey|nodekey|discokey|mkey):[0-9a-fA-F]+"#, #"tskey-[A-Za-z0-9_-]+"#,
                    #"/Users/[^\s\"']+"#, #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#] {
        result = result.replacingOccurrences(of: pattern, with: "<가림>", options: .regularExpression)
    }
    return result
}

/// 공개 사건만 관측한다. 내부 상태·전송 구현에는 접근하지 않는다.
struct GateClient: Sendable {
    enum Observation: Sendable {
        case event(ControlClient.Event)
        case failed(ControlError)
        case ended
        case observationEnded
    }

    let client: ControlClient
    private let running: Task<ControlError?, Never>
    private let collecting: Task<Void, Never>
    private let observations: AsyncStream<Observation>
    private let observationContinuation: AsyncStream<Observation>.Continuation

    init(serverURL: URL, directory: URL, authKey: String? = nil) {
        let client = ControlClient(
            configuration: .init(serverURL: serverURL, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            identityStore: NodeIdentityStore(directory: directory)
        )
        self.client = client
        let (stream, continuation) = AsyncStream.makeStream(of: Observation.self)
        observations = stream
        observationContinuation = continuation
        let running = Task<ControlError?, Never> {
            do { try await client.run(); return nil }
            catch let error as ControlError { return error }
            catch { return .connection("예상하지 않은 run 오류: \(redacted(String(describing: error)))") }
        }
        self.running = running
        collecting = Task {
            for await event in client.events { continuation.yield(.event(event)) }
            if let error = await running.value { continuation.yield(.failed(error)) }
            else { continuation.yield(.ended) }
            continuation.finish()
        }
    }

    func next(_ description: String, timeout: Duration = .seconds(20)) async throws -> Observation {
        try await nextEvent(observations, waitingFor: description, timeout: timeout)
    }

    func registered() async throws -> NodePublicKey {
        switch try await next("등록 완료(서버 키 조회 → 업그레이드 → Noise → HTTP/2)") {
        case .event(.registered(let key)): return key
        case let other: throw unexpected(other, during: "등록 완료")
        }
    }

    func netmap(
        _ description: String = "첫 netmap", timeout: Duration = .seconds(20),
        matching predicate: @Sendable (Netmap) -> Bool = { _ in true }
    ) async throws -> Netmap {
        let deadline = ContinuousClock.now + timeout
        var received = 0
        while true {
            switch try await next("\(description), 관측 netmap \(received)개", timeout: ContinuousClock.now.duration(to: deadline)) {
            case .event(.netmap(let map)):
                received += 1
                if predicate(map) { return map }
            case let other: throw unexpected(other, during: description)
            }
        }
    }

    /// KeepAlive는 공개 사건이 아니다. 관측 시간 내 재등록·disconnected·종료를 모두 거부한다.
    func remainsConnected(until deadline: ContinuousClock.Instant) async throws {
        let continuation = observationContinuation
        let timer = Task {
            do {
                try await Task.sleep(until: deadline, clock: .continuous)
                continuation.yield(.observationEnded)
            } catch {}
        }
        defer { timer.cancel() }
        while true {
            switch try await next("KeepAlive를 넘긴 125초 스트림 유지", timeout: .seconds(140)) {
            case .observationEnded: return
            case .event(.netmap): continue
            case let other: throw unexpected(other, during: "125초 스트림 유지")
            }
        }
    }

    func stop() async {
        running.cancel()
        _ = await running.value
        await collecting.value
    }

    private func unexpected(_ observation: Observation, during stage: String) -> GateFailure {
        let actual: String
        switch observation {
        case .event(.loginRequired): actual = "loginRequired"
        case .event(.registered): actual = "예상하지 않은 재등록"
        case .event(.netmap): actual = "netmap"
        case .event(.disconnected): actual = "disconnected"
        case .failed(let error): actual = redacted(String(describing: error))
        case .ended: actual = "run() 종료"
        case .observationEnded: actual = "관측 종료"
        }
        return GateFailure("\(stage): 기대한 사건 대신 \(actual)")
    }
}

/// 성공·실패·취소 모두 신원 디렉터리와 Go 프로세스를 회수한다.
func withTailnet(_ body: (GoTailnet, GoTailnet.Event, URL) async throws -> Void) async throws {
    let tool = GoTailnet()
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m2-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }
    do {
        let ready = try await tool.start()
        try await body(tool, ready, directory)
        await tool.stop()
    } catch {
        await tool.stop()
        throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
    }
}

func withClient(
    ready: GoTailnet.Event, directory: URL, authKey: String? = nil,
    _ body: (GateClient) async throws -> Void
) async throws {
    let url = try #require(ready.controlURL)
    let client = GateClient(serverURL: url, directory: directory, authKey: authKey)
    do {
        try await body(client)
        await client.stop()
    } catch {
        await client.stop()
        throw error
    }
}
