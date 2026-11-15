import Darwin
import Foundation
import Synchronization
import SwiftailBase
import SwiftailDERP
import SwiftailIO

/// 환경 변수 `SWIFTAIL_TAILNET`: `sh Scripts/build-interop-tools.sh tailnet`이 만든 도구의 경로. 없으면 시험을 건너뛴다.
let tailnetBinary = ProcessInfo.processInfo.environment["SWIFTAIL_TAILNET"].flatMap { $0.isEmpty ? nil : $0 }

struct ToolFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// 도구의 표준 출력에서 `ready` 한 줄을 찾고, 표준 오류는 진단용으로 끝부분만 쥔다.
private final class TailnetOutput: Sendable {
    struct Ready: Decodable, Sendable {
        struct DERP: Decodable, Sendable {
            let regionID: Int
            let host: String
            let port: Int
        }
        let event: String
        let derp: DERP?
    }

    let ready: AsyncStream<Ready>
    private let readyContinuation: AsyncStream<Ready>.Continuation
    private let pending = Mutex(Data())
    private let log = Mutex(Data())

    init() {
        (ready, readyContinuation) = AsyncStream.makeStream(of: Ready.self, bufferingPolicy: .bufferingNewest(1))
    }

    func accept(standardOutput data: Data) {
        let lines = pending.withLock { buffer -> [Data] in
            buffer.append(data)
            var lines: [Data] = []
            while let newline = buffer.firstIndex(of: 10) {
                lines.append(Data(buffer.prefix(upTo: newline)))
                buffer.removeSubrange(...newline)
            }
            if buffer.count > 1 << 20 { buffer = Data() }
            return lines
        }
        for line in lines {
            if let ready = try? JSONDecoder().decode(Ready.self, from: line), ready.event == "ready" { readyContinuation.yield(ready) }
        }
    }

    func accept(standardError data: Data) {
        log.withLock { buffer in
            buffer.append(data)
            if buffer.count > 32 * 1024 { buffer = Data(buffer.suffix(32 * 1024)) }
        }
    }

    /// 키·사용자 경로가 도구의 로그에 섞여 있어도 보고에 남기지 않는다.
    var logText: String {
        var text = log.withLock { String(decoding: $0, as: UTF8.self) }
        for pattern in [#"(?:privkey|nodekey|discokey|mkey):[0-9a-fA-F]+"#, #"/Users/[^\s\"']+"#] {
            text = text.replacingOccurrences(of: pattern, with: "<가림>", options: .regularExpression)
        }
        return text
    }
}

/// `tailnet` 도구 프로세스 하나. 도구는 루프백에 자체 서명 TLS의 Go DERP 서버를 띄운다.
///
/// `run`은 본문이 끝나든 던지든 도구를 반드시 끝낸다: 표준 입력에 `quit`을 쓰고 닫아 정상 종료를 기다리고, 3초 안에
/// 끝나지 않으면 SIGKILL을 보낸다.
actor TailnetProcess {
    private let process = Process()
    private let input = Pipe()
    private let standardOutput = Pipe()
    private let standardError = Pipe()
    private let output = TailnetOutput()
    private let exits: AsyncStream<Void>
    private let exitContinuation: AsyncStream<Void>.Continuation
    private var isStarted = false
    private var isStopped = false

    private init() {
        (exits, exitContinuation) = AsyncStream.makeStream(of: Void.self)
    }

    /// 도구를 띄우고 DERP 서버가 준비되면 `body`에 그 접속 정보를 준다.
    static func run<Result: Sendable>(
        binary: String, _ body: @Sendable (DERPServer) async throws -> Result
    ) async throws -> Result {
        let tool = TailnetProcess()
        do {
            let server = try await tool.start(binary: binary)
            let result = try await body(server)
            await tool.stop()
            return result
        } catch {
            let log = tool.output.logText
            await tool.stop()
            if !log.isEmpty { print("tailnet 로그(끝부분):\n\(log)") }
            throw error
        }
    }

    private func start(binary: String) async throws -> DERPServer {
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = standardOutput
        process.standardError = standardError
        // 종료한 도구에 쓰는 명령이 SIGPIPE로 시험 프로세스까지 죽이지 않게 한다.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw ToolFailure("표준 입력에 F_SETNOSIGPIPE를 걸지 못했다 (errno \(errno))")
        }
        let exitContinuation = exitContinuation
        process.terminationHandler = { _ in
            exitContinuation.yield()
            exitContinuation.finish()
        }
        let output = output
        standardOutput.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil } else { output.accept(standardOutput: data) }
        }
        standardError.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil } else { output.accept(standardError: data) }
        }
        try process.run()
        isStarted = true

        let readyStream = output.ready
        let ready = try await withTimeout(.seconds(15)) {
            for await ready in readyStream { return ready }
            throw ToolFailure("ready를 보내기 전에 표준 출력이 닫혔다")
        }
        guard let derp = ready.derp, let port = UInt16(exactly: derp.port) else { throw ToolFailure("ready에 DERP 정보가 없다") }
        return DERPServer(hostName: derp.host, targets: IPAddress(derp.host).map { [.address($0)] } ?? [.hostName], port: port, verification: .noneForTests)
    }

    private func stop() async {
        guard !isStopped else { return }
        isStopped = true
        if isStarted, process.isRunning {
            try? input.fileHandleForWriting.write(contentsOf: Data("{\"cmd\":\"quit\"}\n".utf8))
        }
        try? input.fileHandleForWriting.close()
        if isStarted {
            let exits = exits
            do {
                try await withTimeout(.seconds(3)) { for await _ in exits { return } }
            } catch {
                kill(process.processIdentifier, SIGKILL)
                _ = try? await withTimeout(.seconds(3)) { for await _ in exits { return } }
            }
        }
        standardOutput.fileHandleForReading.readabilityHandler = nil
        standardError.fileHandleForReading.readabilityHandler = nil
        try? standardOutput.fileHandleForReading.close()
        try? standardError.fileHandleForReading.close()
    }
}
