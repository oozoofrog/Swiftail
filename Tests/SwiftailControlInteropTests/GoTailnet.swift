import Darwin
import Foundation

/// Decodes only the needed fields of the tailnet JSON-line protocol (Tools/interop/README.md).
actor GoTailnet {
    struct Event: Decodable, Sendable {
        struct DERP: Decodable, Sendable {
            let regionID: Int64
            let host: String
            let port: Int
            let stunPort: Int
        }
        struct Node: Decodable, Sendable {
            let nodeKey: String
            let addresses: [String]
            let name: String?
        }
        let event: String
        let id: Int?
        let controlURL: URL?
        let magicDNSSuffix: String?
        let derp: DERP?
        let nodeKey: String?
        let addresses: [String]?
        let fqdn: String?
        let nodes: [Node]?
        let peers: [Node]?
        let message: String?
    }

    struct Command: Encodable, Sendable {
        var id = 0
        let cmd: String
        var name: String? = nil
        var nodeKey: String? = nil
        var response: MapInjection? = nil
        var requireAuth: Bool? = nil
        var authKey: String? = nil
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

    init() {
        (events, continuation) = AsyncStream.makeStream(of: Event.self)
        (exits, exitContinuation) = AsyncStream.makeStream(of: Int32.self)
    }

    func start() async throws -> Event {
        guard let binary = tailnetBinary else { throw GateFailure("SWIFTAIL_TAILNET is missing") }
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        // Prevents a command write during shutdown from killing the test process with SIGPIPE.
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw GateFailure("F_SETNOSIGPIPE failed on tailnet input (errno \(errno))")
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
                guard newline <= 4_194_304 else { throw GateFailure("Tailnet JSON line exceeds the limit") }
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
        let result = try await nextEvent(events, waitingFor: "tailnet \(kind) (command ID \(id ?? 0))", timeout: timeout)
        if let failure { throw failure }
        guard result.event != "error" else { throw GateFailure("tailnet \(kind): \(redacted(result.message ?? "no details"))") }
        guard result.event == kind, result.id == id else {
            throw GateFailure("tailnet expected \(kind)/\(id ?? 0), actual \(result.event)/\(result.id ?? 0)")
        }
        return result
    }

    func command(_ value: Command, expecting kind: String) async throws -> Event {
        var value = value
        nextID += 1
        value.id = nextID
        try write(value)
        return try await event(kind, id: value.id)
    }

    private func write(_ command: Command) throws {
        guard process.isRunning else { throw GateFailure("Process exited before tailnet \(command.cmd)") }
        var data = try JSONEncoder().encode(command)
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }

    func inject(_ response: MapInjection, into nodeKey: String) async throws {
        _ = try await command(.init(cmd: "injectMapResponse", nodeKey: nodeKey, response: response), expecting: "injected")
    }

    func diagnostics() -> String {
        let status = !started ? "Not started" : (process.isRunning ? "Running" : "Exited \(process.terminationStatus)")
        return "tailnet: \(status)\n\(redacted(String(decoding: log, as: UTF8.self)))"
    }

    func stop() async {
        guard !stopped else { return }
        stopped = true
        if process.isRunning { try? write(.init(cmd: "quit")) }
        try? input.fileHandleForWriting.close()
        if process.isRunning {
            // Finishes reaping the process in an independent cleanup Task even if the test Task is canceled.
            let exits = exits
            let pid = process.processIdentifier
            await Task.detached {
                do { _ = try await nextEvent(exits, waitingFor: "Clean tailnet shutdown", timeout: .seconds(3)) }
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

/// Sends only deltas whose meaning survives re-encoding by the tool. Unit tests cover the distinction between null and empty arrays.
struct MapInjection: Encodable, Sendable {
    struct Peer: Encodable, Sendable {
        let ID: Int64
        let Key: String
        let Name: String
        let Addresses: [String]
        let AllowedIPs: [String]
        let Online: Bool
    }
    struct Patch: Encodable, Sendable {
        let NodeID: Int64
        let DERPRegion: Int64
        let Endpoints: [String]
    }
    struct DNS: Encodable, Sendable {
        struct Resolver: Encodable, Sendable { let Addr: String }
        let Resolvers: [Resolver]
        let Domains: [String]
        let Proxied: Bool
    }
    var PeersChanged: [Peer]? = nil
    var PeersRemoved: [Int64]? = nil
    var PeersChangedPatch: [Patch]? = nil
    var OnlineChange: [String: Bool]? = nil
    var DNSConfig: DNS? = nil
}
