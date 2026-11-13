import CryptoKit
import Foundation
import SwiftailBase

struct InteropFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

let wgpeerBinary = ProcessInfo.processInfo.environment["SWIFTAIL_WGPEER"].flatMap { $0.isEmpty ? nil : $0 }

/// wgpeer의 한 줄 JSON 경계. 키는 설정 입력에만 쓰고 진단에는 포함하지 않는다.
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
        guard let binary = wgpeerBinary else { throw InteropFailure("SWIFTAIL_WGPEER가 없음") }
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
        guard process.isRunning else { throw InteropFailure("wgpeer가 종료됨") }
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
                throw InteropFailure("wgpeer: \(error.message ?? "알 수 없는 오류")")
            }
            guard process.isRunning else { throw InteropFailure("wgpeer가 사건 \(kind) 전에 종료됨") }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw InteropFailure("wgpeer의 \(kind) 제한 시간 초과 (\(timeout))")
    }

    func packet(timeout: Duration = .seconds(12)) async throws -> [UInt8] {
        let value = try await event("recv", timeout: timeout)
        guard let hex = value.packet, let bytes = [UInt8](hex: hex) else {
            throw InteropFailure("wgpeer recv의 packet 형식 오류")
        }
        return bytes
    }

    /// 관측 구간 내 recv가 하나라도 오면 실패한다. 음성 검증도 시간 제한을 갖는다.
    func expectSilence(for duration: Duration) async throws {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if let failure { throw failure }
            guard !events.contains(where: { $0.event == "recv" || $0.event == "error" }) else {
                throw InteropFailure("버려야 할 패킷을 Go가 전달했거나 error를 출력함")
            }
            guard process.isRunning else { throw InteropFailure("음성 검증 중 wgpeer 종료") }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private func pump() {
        guard !closed else { return }
        do {
            log.append(try readAvailable(errors.fileHandleForReading))
            if log.count > 262_144 { log = log.suffix(262_144) }
            pending.append(try readAvailable(output.fileHandleForReading))
            guard pending.count <= 1_048_576 else { throw InteropFailure("wgpeer JSON 줄 상한 초과") }
            while let newline = pending.firstIndex(of: 10) {
                let line = pending.prefix(upTo: newline)
                let decoded = try JSONDecoder().decode(Event.self, from: line)
                events.append(decoded)
                pending.removeSubrange(...newline)
            }
        } catch { failure = InteropFailure("wgpeer 출력 해석 실패: \(error)") }
    }

    func diagnostics() -> String {
        pump()
        // wireguard-go가 공개 키의 일부로 만든 peer 식별자도 보고에서 가린다.
        return String(decoding: log, as: UTF8.self).replacingOccurrences(
            of: #"peer\([^)]*\)"#, with: "peer(시험 피어)", options: .regularExpression
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
