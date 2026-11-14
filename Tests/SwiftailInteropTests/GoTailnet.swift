import Darwin
import Foundation

/// tailnet JSON 줄 규약의 필요한 필드만 해석한다(Tools/interop/README.md).
actor GoTailnet {
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
    private var lastCommand = "없음"
    private var tracingCommands = false

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
        let result = try await nextEvent(events, waitingFor: "tailnet \(kind) (명령 id \(id ?? 0))", timeout: timeout)
        if let failure { throw failure }
        guard result.event != "error" else { throw GateFailure("tailnet \(kind): \(redacted(result.message ?? "내용 없음"))") }
        guard result.event == kind, result.id == id else {
            throw GateFailure("tailnet 기대 \(kind)/\(id ?? 0), 실제 \(result.event)/\(result.id ?? 0)")
        }
        return result
    }

    func command(_ value: Command, expecting kind: String) async throws -> Event {
        var value = value
        nextID += 1
        value.id = nextID
        lastCommand = value.cmd
        if tracingCommands || value.cmd == "addPeer" { checkpoint("\(value.cmd) 쓰기 직전") }
        try write(value)
        if tracingCommands { checkpoint("\(value.cmd) 쓰기 반환") }
        let result = try await event(kind, id: value.id)
        if tracingCommands || value.cmd == "addPeer" { checkpoint("\(value.cmd) 응답 수신") }
        return result
    }

    /// SIGPIPE가 관찰된 새 Go 피어 단계에서는 모든 명령의 경계를 기록한다.
    func traceCommands() { tracingCommands = true }

    /// 신호로 시험이 끝나도 마지막 단계·명령·도구 생존 여부를 표준 출력에 남긴다.
    func checkpoint(_ stage: String) {
        let noSignal = fcntl(input.fileHandleForWriting.fileDescriptor, F_GETNOSIGPIPE)
        let line = "[관문 \(Date().ISO8601Format())] \(stage), 마지막 명령 \(lastCommand), tailnet 실행 중 \(process.isRunning), 입력 NOSIGPIPE \(noSignal)\n"
        try? FileHandle.standardOutput.write(contentsOf: Data(line.utf8))
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
