import CryptoKit
import Foundation
import SwiftailBase

struct InteropFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

let wgpeerBinary = ProcessInfo.processInfo.environment["SWIFTAIL_WGPEER"].flatMap { $0.isEmpty ? nil : $0 }

/// A line-delimited JSON boundary for wgpeer. Keys are used only as configuration input and are omitted from diagnostics.
actor GoPeer {
    struct Configuration: Encodable {
        let privateKey: String
        let peerPublicKey: String
        let peerEndpoint: String
        let allowedIPs: [String]
        var listenPort = 0
    }

    struct Event: Decodable, Sendable {
        let event: String
        let message: String?
        let listenPort: UInt16?
        let publicKey: String?
        let packet: String?
        let lastHandshakeSec: Int64?
        let lastHandshakeNsec: Int64?
        let txBytes: Int64?
        let rxBytes: Int64?
    }

    private struct Command: Encodable {
        let cmd: String
        var packet: String? = nil
    }

    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let errors = Pipe()
    private var worker: Task<Void, Never>?
    private var pending = Data()
    private var log = Data()
    private var events: [Event] = []
    private var failure: InteropFailure?
    private var stopped = false
    private var closed = false

    func start(configuration: Configuration) throws {
        guard let binary = wgpeerBinary else { throw InteropFailure("SWIFTAIL_WGPEER is missing") }
        process.executableURL = URL(fileURLWithPath: binary)
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors
        try makeNonblocking(output.fileHandleForReading.fileDescriptor)
        try makeNonblocking(errors.fileHandleForReading.fileDescriptor)
        try suppressBrokenPipe(input.fileHandleForWriting.fileDescriptor)
        try process.run()
        do {
            try write(configuration)
            worker = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.pump()
                    do { try await Task.sleep(for: .milliseconds(5)) } catch { break }
                }
            }
        } catch {
            forceStop(process)
            throw error
        }
    }

    private func write(_ value: some Encodable) throws {
        guard process.isRunning else { throw InteropFailure("wgpeer exited") }
        var line = try JSONEncoder().encode(value)
        line.append(10)
        try input.fileHandleForWriting.write(contentsOf: line)
    }

    func send(_ packet: [UInt8]) throws { try write(Command(cmd: "send", packet: packet.hex)) }

    func stats() async throws -> Event {
        try write(Command(cmd: "stats"))
        return try await event("stats")
    }

    func event(_ kind: String, timeout: Duration = .seconds(12)) async throws -> Event {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if let failure { throw failure }
            if let index = events.firstIndex(where: { $0.event == kind }) {
                return events.remove(at: index)
            }
            if let error = events.first(where: { $0.event == "error" }) {
                throw InteropFailure("wgpeer: \(error.message ?? "unknown error")")
            }
            guard process.isRunning else { throw InteropFailure("wgpeer exited before event \(kind)") }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw InteropFailure("Timed out waiting for wgpeer \(kind) (\(timeout))")
    }

    func packet(timeout: Duration = .seconds(12)) async throws -> [UInt8] {
        let value = try await event("recv", timeout: timeout)
        guard let hex = value.packet, let bytes = [UInt8](hex: hex) else {
            throw InteropFailure("Invalid packet format in wgpeer recv")
        }
        return bytes
    }

    /// Fails if any recv arrives during the observation window. Negative verification is also time-limited.
    func expectSilence(for duration: Duration) async throws {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if let failure { throw failure }
            guard !events.contains(where: { $0.event == "recv" || $0.event == "error" }) else {
                throw InteropFailure("Go delivered a packet that should have been dropped or printed an error")
            }
            guard process.isRunning else { throw InteropFailure("wgpeer exited during negative verification") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private func pump() {
        guard !closed else { return }
        do {
            log.append(try readAvailable(errors.fileHandleForReading))
            if log.count > 262_144 { log = log.suffix(262_144) }
            pending.append(try readAvailable(output.fileHandleForReading))
            guard pending.count <= 1_048_576 else { throw InteropFailure("wgpeer JSON line exceeds the limit") }
            while let newline = pending.firstIndex(of: 10) {
                let line = pending.prefix(upTo: newline)
                let decoded = try JSONDecoder().decode(Event.self, from: line)
                events.append(decoded)
                pending.removeSubrange(...newline)
            }
        } catch { failure = InteropFailure("Could not parse wgpeer output: \(error)") }
    }

    func diagnostics() -> String {
        pump()
        // Also redact peer identifiers that wireguard-go derives from part of a public key.
        return String(decoding: log, as: UTF8.self).replacingOccurrences(
            of: #"peer\([^)]*\)"#, with: "peer(test peer)", options: .regularExpression
        )
    }

    func stop() async {
        guard !stopped else { return }
        stopped = true
        if process.isRunning { try? write(Command(cmd: "quit")) }
        try? input.fileHandleForWriting.close()
        let deadline = ContinuousClock.now + .seconds(2)
        while process.isRunning, ContinuousClock.now < deadline {
            pump()
            try? await Task.sleep(for: .milliseconds(10))
        }
        if process.isRunning { forceStop(process) }
        let killDeadline = ContinuousClock.now + .seconds(2)
        while process.isRunning, ContinuousClock.now < killDeadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
        pump()
        worker?.cancel()
        worker = nil
        closed = true
        try? output.fileHandleForReading.close()
        try? errors.fileHandleForReading.close()
    }
}
