import Darwin
import Foundation

let h2serverBinary = ProcessInfo.processInfo.environment["SWIFTAIL_H2SERVER"].flatMap { $0.isEmpty ? nil : $0 }

struct H2InteropFailure: Error, CustomStringConvertible, Sendable {
    let description: String
    init(_ description: String) { self.description = description }
}

/// 표준 출력은 JSON 줄, 표준 오류는 진단으로 모으는 독립 Go 서버다.
actor GoH2Server {
    private struct Event: Decodable {
        let event: String
        let port: UInt16?
        let message: String?
    }

    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let errors = Pipe()
    private var readers: [Task<Void, Never>] = []
    private var pending = Data()
    private var log = Data()
    private var port: UInt16?
    private var failure: H2InteropFailure?

    func start() async throws -> UInt16 {
        guard let binary = h2serverBinary else { throw H2InteropFailure("SWIFTAIL_H2SERVER가 없음") }
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        // 종료와 명령 쓰기가 겹쳐도 SIGPIPE로 시험 프로세스가 죽지 않게 한다.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw H2InteropFailure("서버 입력 F_SETNOSIGPIPE 실패: \(errno)")
        }
        for (handle, isLog) in [(output.fileHandleForReading, false), (errors.fileHandleForReading, true)] {
            let stream = Self.read(handle)
            readers.append(Task { [weak self] in
                for await data in stream { await self?.accept(data, isLog: isLog) }
            })
        }
        try process.run()
        let deadline = ContinuousClock.now + .seconds(15)
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if let failure { throw failure }
            if let port { return port }
            guard process.isRunning else { throw H2InteropFailure("ready 전에 서버 종료") }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw H2InteropFailure("서버 ready 제한 시간 15초 초과")
    }

    /// Foundation 콜백을 순서가 보존되는 AsyncStream으로 옮겨 actor에서만 상태를 바꾼다.
    private static func read(_ handle: FileHandle) -> AsyncStream<Data> {
        AsyncStream { continuation in
            handle.readabilityHandler = { file in
                // read(upToCount:)는 짧은 ready 줄 뒤에도 채워질 때까지 기다릴 수 있다.
                let data = file.availableData
                if data.isEmpty {
                    file.readabilityHandler = nil
                    continuation.finish()
                } else { continuation.yield(data) }
            }
        }
    }

    private func accept(_ data: Data, isLog: Bool) {
        if isLog {
            log.append(data)
            if log.count > 262_144 { log = Data(log.suffix(262_144)) }
            return
        }
        pending.append(data)
        guard pending.count <= 65_536 else { recordFailure("서버 JSON 줄 상한 초과"); return }
        while let newline = pending.firstIndex(of: 10) {
            do {
                let event = try JSONDecoder().decode(Event.self, from: pending.prefix(upTo: newline))
                if event.event == "ready", let value = event.port, value > 0 { port = value }
                else { recordFailure("서버 사건 \(event.event): \(event.message ?? "내용 없음")") }
            } catch { recordFailure("서버 JSON 해석 실패: \(error)") }
            pending.removeSubrange(...newline)
        }
    }

    private func recordFailure(_ message: String) { failure = H2InteropFailure(message) }

    func command(_ command: String) throws {
        guard process.isRunning else { throw H2InteropFailure("명령 전에 서버 종료") }
        var data = try JSONEncoder().encode(["cmd": command])
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }

    func diagnostics() -> String {
        "서버 로그: \(String(decoding: log, as: UTF8.self))\n서버 파이프: \(failure?.description ?? "오류 없음")"
    }

    func stop() async {
        if process.isRunning { try? command("quit") }
        try? input.fileHandleForWriting.close()
        let deadline = ContinuousClock.now + .seconds(2)
        while process.isRunning, ContinuousClock.now < deadline {
            // 취소된 시험에서도 반드시 프로세스 회수를 끝낸다.
            try? await Task.sleep(for: .milliseconds(10))
        }
        if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
        let killedDeadline = ContinuousClock.now + .seconds(2)
        while process.isRunning, ContinuousClock.now < killedDeadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
        output.fileHandleForReading.readabilityHandler = nil
        errors.fileHandleForReading.readabilityHandler = nil
        for reader in readers { reader.cancel() }
        readers = []
        try? output.fileHandleForReading.close()
        try? errors.fileHandleForReading.close()
    }
}
