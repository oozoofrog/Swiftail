import Darwin
import Foundation

/// tailnet JSON 줄 규약의 필요한 필드만 해석한다(Tools/interop/README.md).
actor GoTailnet {
    struct Transfer: Decodable, Sendable {
        let transferID: Int
        let name: String
        let remote: String
        let sent: UInt64
        let sentSHA256: String
        let received: UInt64
        let receivedSHA256: String
        let elapsedMs: Int64
        let error: String
        let state: String
    }

    struct Event: Decodable, Sendable {
        struct Node: Decodable, Sendable {
            let nodeKey: String
            let addresses: [String]
            let name: String?
            let curAddr: String?
            let relay: String?
            let endpoints: [String]?
            let active: Bool?
            let lastWrite: String?
        }
        let event: String
        let id: Int?
        let controlURL: URL?
        let nodeKey: String?
        let addresses: [String]?
        let nodes: [Node]?
        let peers: [Node]?
        let message: String?
        let sent: Bool?
        let attempted: Bool?
        let error: String?
        let fqdn: String?
        let selfAddrs: [String]?
        let enabled: Bool?
        let servicePackets: Int?
        let observedPackets: Int?
        let controlConnections: Int?
        let derpConnections: Int?
        let stunRequests: Int?
        let transferID: Int?
        let transfers: [Transfer]?
        // M7 호스트 관문 명령(README "M7 호스트 관문 명령").
        let name: String?
        let directoryURL: String?
        let rootPEM: String?
        let requests: [SetDNSRequest]?
        let stableID: String?
        let nodeName: String?
        let computedName: String?
        let loginName: String?
        let status: Int?
        let headers: [String: [String]]?
        let bodyLength: UInt64?
        let bodySHA256: String?
        let elapsedMs: Int64?
        let stopped: Bool?
    }

    struct SetDNSRequest: Decodable, Sendable {
        let name: String
        let type: String
        let value: String
    }

    struct Command: Encodable, Sendable {
        var id = 0
        let cmd: String
        var name: String? = nil
        var nodeKey: String? = nil
        var response: MapInjection? = nil
        var to: String? = nil
        var port: UInt16? = nil
        var proto: String? = nil
        var payload: String? = nil
        var enabled: Bool? = nil
        var requireAuth: Bool? = nil
        var authURL: URL? = nil
        var send: UInt64? = nil
        var seed: UInt64? = nil
        var timeoutSec: Int? = nil
        var nonceReject: Int? = nil
        var authzReuse: Int? = nil
        var domains: [String]? = nil
        var count: Int? = nil
        var status: Int? = nil
        var wrongTXT: Bool? = nil
        var url: String? = nil
        var method: String? = nil
        var range: String? = nil
        var rootPEM: String? = nil
        var stop: Bool? = nil
    }

    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let errors = Pipe()
    private let events: AsyncStream<Event>
    private let continuation: AsyncStream<Event>.Continuation
    private let exits: AsyncStream<Int32>
    private let exitContinuation: AsyncStream<Int32>.Continuation
    private var readers: [Task<Void, Never>] = []
    private var pending = Data()
    private var log = Data()
    private var failure: GateFailure?
    private var nextID = 0
    private var started = false
    private var stopped = false
    private var commandTail: Task<Void, Never>?
    /// 응답을 기다리지 않고 보낸 명령(`peerHTTP`)의 id. 그 응답은 다른 명령의 응답보다 늦게 올 수 있다.
    private var background: Set<Int> = []
    /// 다른 명령을 기다리다 먼저 받은 `background` 명령의 응답.
    private var early: [Int: Event] = [:]

    init(temporaryDirectory: URL) {
        var environment = ProcessInfo.processInfo.environment
        // 강제 종료 때도 바깥 정리가 Go 피어의 상태 디렉터리를 함께 회수한다.
        environment["TMPDIR"] = temporaryDirectory.path
        process.environment = environment
        (events, continuation) = AsyncStream.makeStream(of: Event.self)
        (exits, exitContinuation) = AsyncStream.makeStream(of: Int32.self)
    }

    func start() async throws -> Event {
        guard let binary = tailnetBinary else { throw GateFailure("SWIFTAIL_TAILNET가 없음") }
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        // 종료 중 명령 쓰기가 SIGPIPE로 시험 프로세스까지 죽이지 않게 한다.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw GateFailure("tailnet 입력 F_SETNOSIGPIPE 실패 (errno \(errno))")
        }
        let exitContinuation = exitContinuation
        let continuation = continuation
        process.terminationHandler = { process in
            exitContinuation.yield(process.terminationStatus)
            exitContinuation.finish()
            continuation.finish()
        }
        for (handle, isLog) in [(output.fileHandleForReading, false), (errors.fileHandleForReading, true)] {
            let stream = Self.read(handle)
            readers.append(Task { [weak self] in
                for await data in stream { await self?.accept(data, isLog: isLog) }
                if !isLog { await self?.finishOutput() }
            })
        }
        try process.run()
        started = true
        return try await event("ready", timeout: .seconds(15))
    }

    private static func read(_ handle: FileHandle) -> AsyncStream<Data> {
        AsyncStream { continuation in
            handle.readabilityHandler = { file in
                let data = file.availableData
                if data.isEmpty { file.readabilityHandler = nil; continuation.finish() }
                else { continuation.yield(data) }
            }
        }
    }

    private func finishOutput() { continuation.finish() }

    private func accept(_ data: Data, isLog: Bool) {
        if isLog {
            log.append(data)
            if log.count > 131_072 { log = Data(log.suffix(131_072)) }
            return
        }
        pending.append(data)
        while let newline = pending.firstIndex(of: 10) {
            do {
                guard newline <= 4_194_304 else { throw GateFailure("tailnet JSON 줄 상한 초과") }
                continuation.yield(try JSONDecoder().decode(Event.self, from: pending.prefix(upTo: newline)))
            } catch {
                failure = GateFailure("tailnet JSON 사건 해독 실패")
                continuation.finish()
            }
            pending.removeSubrange(...newline)
        }
        if pending.count > 4_194_304 {
            failure = GateFailure("tailnet 미완성 JSON 줄 상한 초과")
            continuation.finish()
        }
    }

    private func event(_ kind: String, id: Int? = nil, timeout: Duration = .seconds(35)) async throws -> Event {
        let waiting = "tailnet \(kind) (명령 id \(id ?? 0))"
        var result: Event
        if let id, let buffered = early.removeValue(forKey: id) {
            result = buffered
        } else {
            result = try await nextEvent(events, waitingFor: waiting, timeout: timeout)
            while let other = result.id, other != id, background.contains(other) {
                early[other] = result
                result = try await nextEvent(events, waitingFor: waiting, timeout: timeout)
            }
        }
        if let id { background.remove(id) }
        if let failure { throw failure }
        guard result.event != "error" else { throw GateFailure("tailnet \(kind): \(redacted(result.message ?? "내용 없음"))") }
        guard result.event == kind, result.id == id else {
            throw GateFailure("tailnet 기대 \(kind)/\(id ?? 0), 실제 \(result.event)/\(result.id ?? 0)")
        }
        return result
    }

    func command(_ value: Command, expecting kind: String) async throws -> Event {
        let previous = commandTail
        let operation = Task {
            await previous?.value
            return try await performCommand(value, expecting: kind)
        }
        commandTail = Task { _ = await operation.result }
        return try await operation.value
    }

    /// actor 재진입 중에도 명령 하나의 응답을 끝까지 받은 뒤 다음 명령을 보낸다.
    private func performCommand(_ value: Command, expecting kind: String) async throws -> Event {
        var value = value
        nextID += 1
        value.id = nextID
        try write(value)
        return try await event(kind, id: value.id)
    }

    /// 응답을 기다리지 않고 보낸다. 도구가 뒤에서 처리하는 `peerHTTP`에만 쓴다(README: 다른 명령 응답이 먼저 올 수 있다).
    /// 응답은 `response(to:expecting:timeout:)`로 받는다. 그사이 다른 명령을 보내도 된다.
    func send(_ value: Command) throws -> Int {
        var value = value
        nextID += 1
        value.id = nextID
        background.insert(value.id)
        try write(value)
        return value.id
    }

    /// `send(_:)`로 보낸 명령의 응답. 다른 명령과 같은 차례를 지켜 사건 흐름을 한 곳에서만 읽는다.
    func response(to id: Int, expecting kind: String, timeout: Duration) async throws -> Event {
        let previous = commandTail
        let operation = Task {
            await previous?.value
            return try await event(kind, id: id, timeout: timeout)
        }
        commandTail = Task { _ = await operation.result }
        return try await operation.value
    }

    /// 관문의 단계 경계를 표준 출력에 남긴다. 시험이 도중에 끝나도 어느 단계였는지 로그에 남는다.
    func checkpoint(_ stage: String) {
        try? FileHandle.standardOutput.write(contentsOf: Data("[관문 \(Date().ISO8601Format())] \(stage)\n".utf8))
    }

    private func write(_ command: Command) throws {
        guard process.isRunning else { throw GateFailure("tailnet \(command.cmd) 전에 프로세스 종료") }
        var data = try JSONEncoder().encode(command)
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }

    func inject(_ response: MapInjection, into nodeKey: String) async throws {
        _ = try await command(.init(cmd: "injectMapResponse", nodeKey: nodeKey, response: response), expecting: "injected")
    }

    func diagnostics() -> String {
        let status = !started ? "시작 안 됨" : (process.isRunning ? "실행 중" : "종료 \(process.terminationStatus)")
        return "tailnet: \(status)\n\(redacted(String(decoding: log, as: UTF8.self)))"
    }

    func stop() async {
        guard !stopped else { return }
        stopped = true
        if process.isRunning { try? write(.init(cmd: "quit")) }
        try? input.fileHandleForWriting.close()
        if process.isRunning {
            // 시험 Task가 취소되어도 프로세스 회수는 독립된 정리 Task에서 끝낸다.
            let exits = exits
            let pid = process.processIdentifier
            await Task.detached {
                do { _ = try await nextEvent(exits, waitingFor: "tailnet 정상 종료", timeout: .seconds(3)) }
                catch { _ = kill(pid, SIGKILL) }
            }.value
            if process.isRunning { process.waitUntilExit() }
        }
        output.fileHandleForReading.readabilityHandler = nil
        errors.fileHandleForReading.readabilityHandler = nil
        for reader in readers { reader.cancel(); await reader.value }
        readers = []
        continuation.finish()
        try? output.fileHandleForReading.close()
        try? errors.fileHandleForReading.close()
    }
}
