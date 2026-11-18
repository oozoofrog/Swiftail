import Darwin
import Foundation
import Synchronization
import SwiftailBase
import SwiftailDERP
import SwiftailIO

/// The `SWIFTAIL_TAILNET` environment variable points to the tool built by `sh Scripts/build-interop-tools.sh tailnet`. Tests are skipped if it is absent.
let tailnetBinary = ProcessInfo.processInfo.environment["SWIFTAIL_TAILNET"].flatMap { $0.isEmpty ? nil : $0 }

struct ToolFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Looks for a `ready` line on the tool's standard output and retains only the tail of standard error for diagnostics.
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

    /// Keeps keys and user paths out of the report even if they appear in the tool's logs.
    var logText: String {
        var text = log.withLock { String(decoding: $0, as: UTF8.self) }
        for pattern in [#"(?:privkey|nodekey|discokey|mkey):[0-9a-fA-F]+"#, #"/Users/[^\s\"']+"#] {
            text = text.replacingOccurrences(of: pattern, with: "<redacted>", options: .regularExpression)
        }
        return text
    }
}

/// A single `tailnet` tool process. The tool starts a Go DERP server on loopback with self-signed TLS.
///
/// Whether the body returns or throws, `run` always stops the tool. It writes `quit` to standard input and closes it, waits for a normal exit, and
/// sends SIGKILL if the process does not exit within 3 seconds.
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

    /// Starts the tool and passes its connection information to `body` once the DERP server is ready.
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
            if !log.isEmpty { print("tailnet log (tail):\n\(log)") }
            throw error
        }
    }

    private func start(binary: String) async throws -> DERPServer {
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = standardOutput
        process.standardError = standardError
        // Keep a write to an exited tool from killing the test process with SIGPIPE.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw ToolFailure("Could not set F_SETNOSIGPIPE on standard input (errno \(errno))")
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
            throw ToolFailure("Standard output closed before ready was sent")
        }
        guard let derp = ready.derp, let port = UInt16(exactly: derp.port) else { throw ToolFailure("ready contains no DERP information") }
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
