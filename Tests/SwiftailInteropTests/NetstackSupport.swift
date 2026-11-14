import CryptoKit
import Darwin
import Foundation
import Swiftail
import SwiftailBase
import Testing

/// 전송 규약의 LCG64. 청크가 낱말 중간에서 끊겨도 바이트열은 같다(Tools/interop/README.md).
struct NetstackStream {
    var state: UInt64
    private var word: UInt64 = 0
    private var remaining = 0

    init(seed: UInt64) { state = seed }

    mutating func bytes(_ count: Int) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(count)
        for _ in 0..<count {
            if remaining == 0 {
                state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                word = state
                remaining = 8
            }
            result.append(UInt8(truncatingIfNeeded: word))
            word >>= 8
            remaining -= 1
        }
        return result
    }

    static func header(count: UInt64, seed: UInt64) -> [UInt8] {
        [count, seed].flatMap { word in
            stride(from: 56, through: 0, by: -8).map { UInt8(truncatingIfNeeded: word >> $0) }
        }
    }
}

struct NetstackDigest: Sendable {
    let count: UInt64
    let sha256: String
}

struct NetstackMeasurement: Sendable {
    let seconds: Double
    let bytesPerSecond: Double
}

/// 수신의 무진행 구간만 잰다. 송신 버퍼에 넣은 양으로 수신 진전을 대신하지 않는다.
actor NetstackProgress {
    var received: UInt64 = 0
    var eof = false
    var finishedWriting = false
    var receivedAfterFIN: UInt64 = 0

    func add(_ count: Int) {
        received += UInt64(count)
        if finishedWriting { receivedAfterFIN += UInt64(count) }
    }
    func finishRead() { eof = true }
    func finishWrite() { finishedWriting = true }
}

/// CPU 시간은 프로세스 전체의 누적값이다. 다른 시험의 부하도 포함함을 결과에 명시한다.
struct NetstackResources {
    let cpuSeconds: Double
    let footprint: UInt64?

    static func sample() -> Self {
        var usage = rusage()
        let usageOK = getrusage(RUSAGE_SELF, &usage) == 0
        let cpu = usageOK ? Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec)
            + Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1_000_000 : 0
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        // Darwin task_info가 정수 포인터를 요구하므로 이 호출에만 재바인딩을 가둔다. 외부 버퍼를 보관하지 않는다.
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return Self(cpuSeconds: cpu, footprint: result == KERN_SUCCESS ? info.phys_footprint : nil)
    }
}

/// 취소 가능한 공개 API의 기한이다. 기한까지 실제로 기다린 뒤 자식 Task를 취소하고 회수한다.
func netstackDeadline<T: Sendable>(
    _ stage: String, seconds: Int = 60, _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        defer { group.cancelAll() }
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw GateFailure("\(stage): \(seconds)초 제한 초과")
        }
        return try #require(try await group.next())
    }
}

func netstackWait(_ stage: String, seconds: Int = 25,
                  _ predicate: () async throws -> Bool) async throws {
    let deadline = ContinuousClock.now + .seconds(seconds)
    repeat {
        if try await predicate() { return }
        try await Task.sleep(for: .milliseconds(100))
    } while ContinuousClock.now < deadline
    throw GateFailure("\(stage): \(seconds)초 제한 초과")
}

func netstackAccept(_ listener: TailnetListener) async throws -> TailnetConnection {
    try await netstackDeadline("리스너 accept") {
        var iterator = listener.makeAsyncIterator()
        return try #require(await iterator.next())
    }
}

func netstackPreface(_ connection: TailnetConnection) async throws -> (count: UInt64, seed: UInt64) {
    var bytes: [UInt8] = []
    while bytes.count < 16 {
        guard let chunk = try await connection.read(upTo: 16 - bytes.count) else {
            throw GateFailure("16바이트 전송 머리 중 EOF: \(bytes.count)바이트")
        }
        bytes += chunk
    }
    let count = bytes.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    let seed = bytes.suffix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    guard count <= 4_294_967_296 else { throw GateFailure("전송 머리의 길이가 4GiB 초과") }
    return (count, seed)
}

func netstackSend(_ connection: TailnetConnection, count: UInt64, seed: UInt64,
                  progress: NetstackProgress) async throws -> NetstackDigest {
    var stream = NetstackStream(seed: seed)
    var hash = SHA256()
    var sent: UInt64 = 0
    while sent < count {
        let bytes = stream.bytes(Int(min(32_768, count - sent)))
        try await connection.write(bytes)
        hash.update(data: Data(bytes))
        sent += UInt64(bytes.count)
    }
    try await connection.finishWriting()
    await progress.finishWrite()
    return .init(count: sent, sha256: Array(hash.finalize()).hex)
}

func netstackReceive(_ connection: TailnetConnection, count: UInt64, seed: UInt64,
                     progress: NetstackProgress) async throws -> NetstackDigest {
    var stream = NetstackStream(seed: seed)
    var hash = SHA256()
    var received: UInt64 = 0
    while let bytes = try await connection.read(upTo: 32_768) {
        guard !bytes.isEmpty, received + UInt64(bytes.count) <= count else {
            throw GateFailure("수신 길이 오류: 누적 \(received), 청크 \(bytes.count), 기대 \(count)")
        }
        guard bytes == stream.bytes(bytes.count) else {
            throw GateFailure("LCG64 바이트 불일치: 오프셋 \(received), 청크 \(bytes.count)")
        }
        hash.update(data: Data(bytes))
        received += UInt64(bytes.count)
        await progress.add(bytes.count)
    }
    await progress.finishRead()
    #expect(received == count, "EOF에서 기대 바이트 수와 일치해야 한다")
    return .init(count: received, sha256: Array(hash.finalize()).hex)
}

func netstackTransfers(_ tool: GoTailnet) async throws -> [GoTailnet.Transfer] {
    try #require(await tool.command(.init(cmd: "transfers", name: "go-peer-a"), expecting: "transfers").transfers)
}

func netstackDial(_ gate: Gate, port: UInt16 = 9_100, count: UInt64, seed: UInt64 = 1,
                  ipv4: Bool = true, timeout: Int = 600) async throws -> Int {
    try #require(await gate.tool.command(.init(cmd: "peerDial", name: "go-peer-a",
        to: try gate.local.address(ipv4: ipv4).description, port: port,
        send: count, seed: seed, timeoutSec: timeout), expecting: "peerDial").transferID)
}

private enum NetstackTransferPart: Sendable {
    case sent(NetstackDigest)
    case received(NetstackDigest)
    case peer(GoTailnet.Transfer, longestPause: Double, peakFootprint: UInt64)
}

/// 쓰기·읽기·Go 진행 조회를 함께 기다린다. 명령 조회는 이 Task 하나만 해 Go JSON 응답을 섞지 않는다.
@discardableResult
func netstackExchange(_ gate: Gate, connection: TailnetConnection, stage: String,
                      sendCount: UInt64, receiveCount: UInt64, sendSeed: UInt64 = 1,
                      receiveSeed: UInt64 = 1, transferID: Int? = nil,
                      requireReadAfterFIN: Bool = false, timeoutSeconds: Int = 600) async throws -> NetstackMeasurement {
    let started = ContinuousClock.now
    let resources = NetstackResources.sample()
    let progress = NetstackProgress()
    await gate.tool.checkpoint("M6 \(stage) 시작: 송신 \(sendCount), 수신 \(receiveCount)바이트")
    do {
        let result = try await withThrowingTaskGroup(of: NetstackTransferPart.self) { group in
            defer { group.cancelAll() }
            group.addTask { .sent(try await netstackSend(connection, count: sendCount, seed: sendSeed, progress: progress)) }
            group.addTask { .received(try await netstackReceive(connection, count: receiveCount, seed: receiveSeed, progress: progress)) }
            group.addTask {
                var localCount: UInt64 = 0
                var peerCount: UInt64 = 0
                var localChanged = started
                var peerChanged = started
                var longest: Double = 0
                var peak = resources.footprint ?? 0
                var nextLog = started + .seconds(10)
                while true {
                    try Task.checkCancellation()
                    let now = ContinuousClock.now
                    let received = await progress.received
                    let eof = await progress.eof
                    let transfers = try await netstackTransfers(gate.tool)
                    let peer = transfers.first {
                        if let transferID { return $0.transferID == transferID }
                        return $0.remote == connection.localEndpoint.description
                    }
                    if received != localCount {
                        longest = max(longest, localChanged.duration(to: now).netstackSeconds)
                        localCount = received
                        localChanged = now
                    }
                    if let peer, peer.received != peerCount {
                        longest = max(longest, peerChanged.duration(to: now).netstackSeconds)
                        peerCount = peer.received
                        peerChanged = now
                    }
                    peak = max(peak, NetstackResources.sample().footprint ?? 0)
                    if let peer, peer.state == "error" {
                        throw GateFailure("\(stage): Go 오류 \(redacted(peer.error)); Swift 수신 \(received), Go 송신 \(peer.sent)·수신 \(peer.received), \(peer.elapsedMs)ms")
                    }
                    if let peer, peer.state == "complete", eof {
                        return .peer(peer, longestPause: longest, peakFootprint: peak)
                    }
                    let localPause = localChanged.duration(to: now).netstackSeconds
                    let peerPause = peerChanged.duration(to: now).netstackSeconds
                    if (!eof && received < receiveCount && localPause >= 30)
                        || (peerCount < sendCount && peerPause >= 30) {
                        throw GateFailure("\(stage): 30초 수신 무진행; Swift \(received)/\(receiveCount), Go \(peerCount)/\(sendCount), 경과 \(started.duration(to: now))")
                    }
                    guard now < started + .seconds(timeoutSeconds) else { throw GateFailure("\(stage): \(timeoutSeconds)초 제한 초과") }
                    if now >= nextLog {
                        await gate.tool.checkpoint("M6 \(stage) 진행: Swift 수신 \(received), Go 수신 \(peerCount)바이트, 경과 \(started.duration(to: now))")
                        nextLog = now + .seconds(10)
                    }
                    try await Task.sleep(for: .milliseconds(250))
                }
            }
            var sent: NetstackDigest?
            var received: NetstackDigest?
            var peer: GoTailnet.Transfer?
            var pause = 0.0
            var peak: UInt64 = 0
            for try await part in group {
                switch part {
                case .sent(let value): sent = value
                case .received(let value): received = value
                case let .peer(value, longestPause, peakFootprint): peer = value; pause = longestPause; peak = peakFootprint
                }
            }
            return (try #require(sent), try #require(received), try #require(peer), pause, peak)
        }
        let (sent, received, peer, pause, peak) = result
        try #require(sent.count == sendCount && sent.count == peer.received)
        try #require(received.count == receiveCount && received.count == peer.sent)
        try #require(sent.sha256 == peer.receivedSHA256)
        try #require(received.sha256 == peer.sentSHA256)
        try #require(peer.state == "complete" && peer.error.isEmpty)
        try #require(pause < 30)
        if requireReadAfterFIN { try #require(await progress.receivedAfterFIN > 0, "FIN 뒤에도 반대 방향 데이터가 와야 한다") }
        let seconds = started.duration(to: .now).netstackSeconds
        let rate = Double(sent.count + received.count) / seconds
        let cpu = NetstackResources.sample().cpuSeconds - resources.cpuSeconds
        await gate.tool.checkpoint("M6 \(stage) 완료: 송신 \(sent.count) SHA256=\(sent.sha256), 수신 \(received.count) SHA256=\(received.sha256), 해시 교차 일치, \(seconds)초, \(rate)바이트/초(양방향 합), 최장 수신 간격 \(pause)초, 프로세스 CPU \(cpu)초, phys_footprint 표본 최고 \(peak)바이트")
        await connection.close()
        return .init(seconds: seconds, bytesPerSecond: rate)
    } catch {
        await gate.tool.checkpoint("M6 \(stage) 실패: 경과 \(started.duration(to: .now)), Swift 수신 \(await progress.received)바이트, \(redacted(String(describing: error)))")
        await connection.abort()
        throw error
    }
}

extension Duration {
    var netstackSeconds: Double { Double(components.seconds) + Double(components.attoseconds) / 1e18 }
}

/// UDP 에코를 소비하지 않는 .inProcess 장치에서는 작은 TCP 전송으로 직접 경로를 준비한다.
func netstackPrepare(_ gate: Gate, relayed: Bool = false) async throws -> String {
    _ = try await gate.tool.command(.init(cmd: "peerServe", name: "go-peer-a", port: 9_100, timeoutSec: 600), expecting: "peerServe")
    let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
    let fqdn = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
    if relayed {
        // Go가 올린 모든 후보 포트를 막는다. 실제 LAN 주소는 로그에 남기지 않는다.
        var ports: Set<UInt16> = []
        try await netstackWait("Go UDP 후보") {
            let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
            ports = Set((status.selfAddrs ?? []).compactMap(IPEndpoint.init).map(\.port))
            return !ports.isEmpty
        }
        await gate.node.setBlockedUDPPorts(ports)
    }
    let deadline = ContinuousClock.now + .seconds(25)
    repeat {
        let connection = try await netstackDeadline("직접·DERP 경로 준비 connect") {
            try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
        }
        try await connection.write(NetstackStream.header(count: 3, seed: 1))
        try await netstackExchange(gate, connection: connection, stage: "경로 준비", sendCount: 3, receiveCount: 3)
        let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
        let goDirect = status.peers?.first { $0.nodeKey == gate.local.key }?.curAddr?.isEmpty == false
        let path = await gate.node.path(toPeerNamed: fqdn)
        if relayed, path == .relayed(derpRegion: 1), !goDirect {
            await gate.tool.checkpoint("M6 양쪽 DERP 경로 확인 (setBlockedUDPPorts)")
            return fqdn
        }
        if !relayed, case .direct = path, goDirect {
            await gate.tool.checkpoint("M6 양쪽 직접 경로 확인")
            return fqdn
        }
        try await Task.sleep(for: .milliseconds(200))
    } while ContinuousClock.now < deadline
    throw GateFailure("M6 양쪽 경로 확인 25초 제한 초과")
}
