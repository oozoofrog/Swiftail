import Darwin
import Foundation

let h2serverBinary = ProcessInfo.processInfo.environment["SWIFTAIL_H2SERVER"].flatMap { $0.isEmpty ? nil : $0 }

struct H2InteropFailure: Error, CustomStringConvertible, Sendable {
    let description: String
    init(_ description: String) { self.description = description }
}

/// A standalone Go server whose stdout is collected as JSON lines and stderr as diagnostics.
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
        guard let binary = h2serverBinary else { throw H2InteropFailure("SWIFTAIL_H2SERVER is missing") }
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        // Prevent SIGPIPE from killing the test process if shutdown overlaps a command write.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw H2InteropFailure("F_SETNOSIGPIPE failed on server input: \(errno)")
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
            guard process.isRunning else { throw H2InteropFailure("Server exited before ready") }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw H2InteropFailure("Server exceeded the 15-second ready timeout")
    }

    /// Moves Foundation callbacks into an AsyncStream that preserves their order, so state changes only in the actor.
    private static func read(_ handle: FileHandle) -> AsyncStream<Data> {
        AsyncStream { continuation in
            handle.readabilityHandler = { file in
                // read(upToCount:) can wait for the buffer to fill even after a short ready line.
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
        guard pending.count <= 65_536 else { recordFailure("Server JSON line exceeds the limit"); return }
        while let newline = pending.firstIndex(of: 10) {
            do {
                let event = try JSONDecoder().decode(Event.self, from: pending.prefix(upTo: newline))
                if event.event == "ready", let value = event.port, value > 0 { port = value }
                else { recordFailure("Server event \(event.event): \(event.message ?? "no details")") }
            } catch { recordFailure("Could not decode server JSON: \(error)") }
            pending.removeSubrange(...newline)
        }
    }

    private func recordFailure(_ message: String) { failure = H2InteropFailure(message) }

    func command(_ command: String) throws {
        guard process.isRunning else { throw H2InteropFailure("Server exited before the command") }
        var data = try JSONEncoder().encode(["cmd": command])
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }

    func diagnostics() -> String {
        "Server log: \(String(decoding: log, as: UTF8.self))\nServer pipe: \(failure?.description ?? "no error")"
    }

    func stop() async {
        if process.isRunning { try? command("quit") }
        try? input.fileHandleForWriting.close()
        let deadline = ContinuousClock.now + .seconds(2)
        while process.isRunning, ContinuousClock.now < deadline {
            // Always finish reaping the process, even if the test is canceled.
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
