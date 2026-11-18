import Darwin
import Foundation

/// Decodes only the fields needed from the tailnet line-delimited JSON protocol (Tools/interop/README.md).
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
            /// Node key expiration from `nodes` (server side) and `peerStatus` (as seen by the Go peer). UTC RFC 3339, or "" if absent.
            let keyExpiry: String?
            /// In `peerStatus`, whether Go marked the peer expired (computed only from a full netmap).
            let expired: Bool?
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
        // M8 ③ DERP certificate commands (README "DERP Certificate Pinning").
        let derpTLSHandshakes: Int?
        let derpServerNames: [String]?
        let certName: String?
        let presented: Int?
        let stunRequests: Int?
        let transferID: Int?
        let transfers: [Transfer]?
        // M7 host gate commands (README "M7 Host Gate Commands").
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
        // Tailnet Lock gate commands (README "Tailnet Lock Gate Commands"). `lockStatus` uses the `nodeKey`, `name`, and `enabled` fields above.
        let head: String?
        let lockKey: String?
        let nodeKeySigned: Bool?
        let trustedKeys: [String]?
        let visiblePeers: [String]?
        let filteredPeers: [String]?
        let controlHead: String?
        let controlDisabled: Bool?
        let authKey: String?
        let alreadyDisabled: Bool?
        let registrations: [LockRegistration]?
        // Logout gate (README "Logout").
        let backendState: String?
    }

    /// `setDNSLog` and `lockRequests` share the `requests` field. The former carries `name`, `type`, and `value`.
    /// The latter carries `path`, `nodeKey`, and `head`.
    struct SetDNSRequest: Decodable, Sendable {
        let name: String?
        let type: String?
        let value: String?
        let path: String?
        let nodeKey: String?
        let head: String?
    }

    /// One `lockRegistrations` line. `nlKey` and `oldNodeKey` are empty strings if zero.
    struct LockRegistration: Decodable, Sendable {
        let nodeKey: String
        let oldNodeKey: String
        let nlKey: String
        let signature: String
        let signatureError: String
        let resignRequested: Bool
        let wrappedKeyTrace: Bool
        /// Whether the request carried `Auth`.
        let auth: Bool
        /// The request's `Expiry` string, exactly as it appeared on the wire.
        let expiry: String
        /// `Expiry` in Unix seconds, or 0 for a zero time.
        let expiryUnix: Int64
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
        var mode: String? = nil
        // Tailnet Lock gate commands.
        var authKey: String? = nil
        var lockKey: String? = nil
        var addKeys: [String]? = nil
        var removeKeys: [String]? = nil
        var wrongSecret: Bool? = nil
        var omitTKAInfo: Bool? = nil
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
    /// ID of a command sent without waiting for the response (`peerHTTP`). Its response may arrive after responses to other commands.
    private var background: Set<Int> = []
    /// Responses to `background` commands received first while waiting for another command.
    private var early: [Int: Event] = [:]

    init(temporaryDirectory: URL) {
        var environment = ProcessInfo.processInfo.environment
        // Even after a forced exit, outer cleanup also removes the Go peers' state directories.
        environment["TMPDIR"] = temporaryDirectory.path
        process.environment = environment
        (events, continuation) = AsyncStream.makeStream(of: Event.self)
        (exits, exitContinuation) = AsyncStream.makeStream(of: Int32.self)
    }

    func start() async throws -> Event {
        guard let binary = tailnetBinary else { throw GateFailure("SWIFTAIL_TAILNET is missing") }
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        // Keep a command write during shutdown from killing the test process with SIGPIPE.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw GateFailure("Setting F_SETNOSIGPIPE on tailnet input failed (errno \(errno))")
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
                guard newline <= 4_194_304 else { throw GateFailure("tailnet JSON line exceeds the limit") }
                continuation.yield(try JSONDecoder().decode(Event.self, from: pending.prefix(upTo: newline)))
            } catch {
                failure = GateFailure("Could not decode tailnet JSON event")
                continuation.finish()
            }
            pending.removeSubrange(...newline)
        }
        if pending.count > 4_194_304 {
            failure = GateFailure("Incomplete tailnet JSON line exceeds the limit")
            continuation.finish()
        }
    }

    private func event(_ kind: String, id: Int? = nil, timeout: Duration = .seconds(35)) async throws -> Event {
        let waiting = "tailnet \(kind) (command id \(id ?? 0))"
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
        guard result.event != "error" else { throw GateFailure("tailnet \(kind): \(redacted(result.message ?? "no details"))") }
        guard result.event == kind, result.id == id else {
            throw GateFailure("tailnet expected \(kind)/\(id ?? 0), got \(result.event)/\(result.id ?? 0)")
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

    /// Receives each command's full response before sending the next command, even during actor reentrancy.
    private func performCommand(_ value: Command, expecting kind: String) async throws -> Event {
        var value = value
        nextID += 1
        value.id = nextID
        try write(value)
        return try await event(kind, id: value.id)
    }

    /// Sends without waiting for a response. Used only for `peerHTTP`, which the tool handles in the background (README: other commands may receive responses first).
    /// Receives the response via `response(to:expecting:timeout:)`. Other commands can be sent in the meantime.
    func send(_ value: Command) throws -> Int {
        var value = value
        nextID += 1
        value.id = nextID
        background.insert(value.id)
        try write(value)
        return value.id
    }

    /// The response to a command sent via `send(_:)`. Takes its turn with other commands so only one place reads the event stream.
    func response(to id: Int, expecting kind: String, timeout: Duration) async throws -> Event {
        let previous = commandTail
        let operation = Task {
            await previous?.value
            return try await event(kind, id: id, timeout: timeout)
        }
        commandTail = Task { _ = await operation.result }
        return try await operation.value
    }

    /// Writes gate stage boundaries to standard output so the log shows the stage even if the test ends early.
    func checkpoint(_ stage: String) {
        try? FileHandle.standardOutput.write(contentsOf: Data("[gate \(Date().ISO8601Format())] \(stage)\n".utf8))
    }

    private func write(_ command: Command) throws {
        guard process.isRunning else { throw GateFailure("tailnet exited before \(command.cmd)") }
        var data = try JSONEncoder().encode(command)
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }

    func inject(_ response: MapInjection, into nodeKey: String) async throws {
        _ = try await command(.init(cmd: "injectMapResponse", nodeKey: nodeKey, response: response), expecting: "injected")
    }

    func diagnostics() -> String {
        let status = !started ? "not started" : (process.isRunning ? "running" : "exited \(process.terminationStatus)")
        return "tailnet: \(status)\n\(redacted(String(decoding: log, as: UTF8.self)))"
    }

    func stop() async {
        guard !stopped else { return }
        stopped = true
        if process.isRunning { try? write(.init(cmd: "quit")) }
        try? input.fileHandleForWriting.close()
        if process.isRunning {
            // Finish reaping the process in a separate cleanup Task even if the test Task is canceled.
            let exits = exits
            let pid = process.processIdentifier
            await Task.detached {
                do { _ = try await nextEvent(exits, waitingFor: "normal tailnet shutdown", timeout: .seconds(3)) }
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
