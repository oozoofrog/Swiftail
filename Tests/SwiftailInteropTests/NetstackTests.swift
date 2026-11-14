import CryptoKit
import Foundation
import Swiftail
import SwiftailBase
import Testing

@Suite("M6 관문 (가): Swift TCP ↔ Go gVisor", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M6 관문을 건너뜁니다"), .serialized, .timeLimit(.minutes(60)))
struct NetstackTests {
    private static let large: UInt64 = 104_857_600

    @Test("전송 도우미: 공개 LCG64 벡터와 청크 경계")
    func streamVector() {
        var whole = NetstackStream(seed: 1)
        var split = NetstackStream(seed: 1)
        let bytes = whole.bytes(32)
        #expect(bytes.hex == "7c00fd43ac6f576c1b1b4a86b38668820eaa972099e1faa5c5579311cd550362")
        #expect(Array(SHA256.hash(data: Data(bytes))).hex == "d96bbb8821f933a5b368b9c127d725ed65b2d2f89f5b6d4505545306e834537d")
        #expect(split.bytes(3) + split.bytes(9) + split.bytes(20) == bytes)
        #expect(NetstackStream.header(count: 3, seed: 1) == [0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    @Test("항목 1·3: Swift listen, Go dial, IPv4·IPv6 작은 전송과 100MiB 양방향")
    func swiftListens() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            for ipv4 in [true, false] {
                for size: UInt64 in ipv4 ? [3, Self.large] : [3, 10_485_760, Self.large] {
                    let id = try await netstackDial(gate, port: listener.port, count: size, ipv4: ipv4)
                    let connection = try await netstackAccept(listener)
                    #expect(connection.remoteEndpoint.address == (try gate.peer.address(ipv4: ipv4)))
                    #expect(connection.localEndpoint.port == listener.port)
                    let preface = try await netstackPreface(connection)
                    #expect(preface.count == size && preface.seed == 1)
                    try await netstackExchange(gate, connection: connection,
                        stage: "1·3 Swift listen IPv\(ipv4 ? 4 : 6) \(size)",
                        sendCount: preface.count, receiveCount: size, transferID: id)
                }
            }
            await listener.close()
        }
    }

    @Test("항목 2·3: Swift connect, Go listen, IP·FQDN·짧은 이름과 100MiB 양방향")
    func swiftConnects() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            let fqdn = try await netstackPrepare(gate)
            let short = String(try #require(fqdn.split(separator: ".").first))
            let hosts = [try gate.peer.address().description, try gate.peer.address(ipv4: false).description, fqdn, short]
            for host in hosts {
                let sizes: [UInt64] = IPAddress(host)?.isIPv4 == false ? [3, 10_485_760, Self.large] : [3, Self.large]
                for size in sizes {
                    let connection = try await netstackDeadline("항목 2·3 connect") {
                        try await gate.node.connect(to: host, port: 9_100)
                    }
                    let family = connection.remoteEndpoint.address.isIPv4 ? "IPv4" : "IPv6"
                    let kind = IPAddress(host) == nil ? (host == short ? "짧은 이름" : "FQDN") : family
                    #expect(connection.remoteEndpoint.port == 9_100)
                    #expect(gate.peer.addresses.contains(connection.remoteEndpoint.address))
                    try await connection.write(NetstackStream.header(count: size, seed: 1))
                    try await netstackExchange(gate, connection: connection, stage: "2·3 Swift connect \(kind) \(size)",
                        sendCount: size, receiveCount: size)
                }
            }
        }
    }

    @Test("항목 4: setBlockedUDPPorts로 직접 경로를 막은 DERP 100MiB 양방향")
    func derpTransfer() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            let fqdn = try await netstackPrepare(gate, relayed: true)
            let listener = try await gate.node.listen(port: 9_101)
            let id = try await netstackDial(gate, port: listener.port, count: Self.large)
            let connection = try await netstackAccept(listener)
            let preface = try await netstackPreface(connection)
            try await netstackExchange(gate, connection: connection, stage: "4 DERP 100MiB",
                sendCount: preface.count, receiveCount: Self.large, transferID: id)
            #expect(await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1))
            let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
            #expect(status.peers?.first { $0.nodeKey == gate.local.key }?.curAddr == "")
            await listener.close()
        }
    }

    @Test("항목 5: 양방향 리스너 없는 포트는 제한 시간 전에 refused")
    func refusedConnections() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let started = ContinuousClock.now
            await #expect(throws: ConnectionError.refused) {
                try await netstackDeadline("Swift refused", seconds: 10) {
                    try await gate.node.connect(to: gate.peer.address().description, port: 9_199)
                }
            }
            let id = try await netstackDial(gate, port: 9_199, count: 3, timeout: 10)
            try await netstackWait("Go connection refused", seconds: 9) {
                let transfer = try await netstackTransfers(gate.tool).first { $0.transferID == id }
                guard let transfer, transfer.state == "error" else { return false }
                #expect(transfer.error.contains("refused"))
                #expect(transfer.elapsedMs < 10_000)
                await gate.tool.checkpoint("M6 5 Go 오류: \(redacted(transfer.error.replacingOccurrences(of: transfer.remote, with: "<시험 주소>"))), \(transfer.elapsedMs)ms")
                return true
            }
            await gate.tool.checkpoint("M6 5 양방향 refused 완료: \(started.duration(to: .now))")
        }
    }

    @Test("항목 6: 먼저 finishWriting한 뒤에도 반대 방향을 EOF까지 읽는다")
    func halfClose() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let connection = try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
            try await connection.write(NetstackStream.header(count: 1_048_576, seed: 7))
            try await netstackExchange(gate, connection: connection, stage: "6 비대칭 반닫힘",
                sendCount: 3, receiveCount: 1_048_576, sendSeed: 2, receiveSeed: 7, requireReadAfterFIN: true)
            await #expect(throws: ConnectionError.closed) { try await connection.write([1]) }
        }
    }

    @Test("항목 6: Swift abort를 Go가 connection reset으로 읽는다")
    func swiftAbort() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            let id = try await netstackDial(gate, port: listener.port, count: 0)
            let connection = try await netstackAccept(listener)
            _ = try await netstackPreface(connection)
            // Go의 쓰기가 끝난 뒤 끊어, 도구가 쓰기 실패 대신 읽기의 RST를 보고하게 한다.
            #expect(try await connection.read() == nil)
            await connection.abort()
            await #expect(throws: ConnectionError.closed) { try await connection.read() }
            try await netstackWait("Go reset 오류") {
                guard let transfer = try await netstackTransfers(gate.tool).first(where: { $0.transferID == id }),
                      transfer.state == "error" else { return false }
                #expect(transfer.error.localizedCaseInsensitiveContains("reset"))
                await gate.tool.checkpoint("M6 6 Swift abort: Go \(redacted(transfer.error.replacingOccurrences(of: transfer.remote, with: "<시험 주소>"))), 송신 \(transfer.sent), 수신 \(transfer.received), \(transfer.elapsedMs)ms")
                return true
            }
            await listener.close()
        }
    }

    @Test("항목 6: 잘못된 머리 뒤 읽지 않은 데이터를 닫는 Go의 RST")
    func goReset() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let connection = try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
            // Go 도구는 4GiB 초과 머리에서 연결을 닫는다. 뒤의 미독 데이터가 gVisor의 RST를 유발한다.
            try await connection.write(NetstackStream.header(count: 4_294_967_297, seed: 1) + [UInt8](repeating: 1, count: 32_768))
            await #expect(throws: ConnectionError.reset) {
                try await netstackDeadline("Go RST", seconds: 10) { try await connection.read() }
            }
            await connection.abort()
            let transfers = try await netstackTransfers(gate.tool)
            let transfer = try #require(transfers.first { $0.remote.isEmpty && $0.state == "error" })
            #expect(transfer.error.contains("4GiB"))
            await gate.tool.checkpoint("M6 6 Go RST: \(redacted(transfer.error)), \(transfer.elapsedMs)ms")
        }
    }

    @Test("항목 7: 32개 동시 연결마다 양방향 4MiB, phys_footprint 표본")
    func concurrentConnections() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            var connections: [(TailnetConnection, Int)] = []
            for _ in 0..<32 {
                let id = try await netstackDial(gate, port: listener.port, count: 4_194_304)
                let connection = try await netstackAccept(listener)
                _ = try await netstackPreface(connection)
                connections.append((connection, id))
            }
            try await withThrowingTaskGroup(of: Void.self) { group in
                for (index, pair) in connections.enumerated() {
                    group.addTask {
                        try await netstackExchange(gate, connection: pair.0, stage: "7 동시 연결 \(index + 1)/32",
                            sendCount: 4_194_304, receiveCount: 4_194_304, transferID: pair.1)
                    }
                }
                try await group.waitForAll()
            }
            await listener.close()
        }
    }

    @Test("항목 8·9·N3: 0%·1%·5% 손실, 20MiB, 30초 수신 무진행 금지")
    func packetLoss() async throws {
        var rates: [Double: Double] = [:]
        for loss in [0.0, 0.01, 0.05] {
            do {
                try await withGate(direct: false, device: .inProcess) { gate in
                    _ = try await netstackPrepare(gate)
                    let listener = try await gate.node.listen(port: 9_101)
                    await gate.node.setInProcessLoss(rate: loss, seed: 0x4d_36)
                    let id = try await netstackDial(gate, port: listener.port, count: 20_971_520, timeout: 1_800)
                    let connection = try await netstackAccept(listener)
                    let preface = try await netstackPreface(connection)
                    let measurement = try await netstackExchange(gate, connection: connection, stage: "8·9 손실 \(Int(loss * 100))% 씨앗 19766",
                        sendCount: preface.count, receiveCount: 20_971_520, transferID: id, timeoutSeconds: 1_800)
                    rates[loss] = measurement.bytesPerSecond
                    await listener.close()
                }
            } catch {
                Issue.record(error, "손실 \(Int(loss * 100))% 씨앗 19766")
            }
        }
        if let baseline = rates[0], let onePercent = rates[0.01] {
            let ratio = onePercent / baseline
            await lossNote("M6 N3: 0%=\(baseline), 1%=\(onePercent), 5%=\(rates[0.05].map(String.init(describing:)) ?? "미완료")바이트/초, 1%/0%=\(ratio), M6-10 기준(0.1 미만)=\(ratio < 0.1)")
        } else {
            await lossNote("M6 N3: 0% 또는 1% 전송 미완료로 처리량 비율 판정 불가")
        }
    }

    @Test("리스너 닫기: 대기 흐름 종료·받아 간 연결 유지·미수락 연결 RST")
    func listenerClose() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            let id = try await netstackDial(gate, port: listener.port, count: 3)
            let accepted = try await netstackAccept(listener)
            _ = try await netstackPreface(accepted)
            let queued = try await netstackDial(gate, port: listener.port, count: 3)
            try await netstackWait("미수락 연결의 데이터 송신") {
                try await netstackTransfers(gate.tool).contains { $0.transferID == queued && $0.sent == 3 }
            }
            await listener.close()
            var iterator = listener.makeAsyncIterator()
            #expect(await iterator.next() == nil)
            try await netstackExchange(gate, connection: accepted, stage: "리스너 close 뒤 받은 연결 유지",
                sendCount: 3, receiveCount: 3, transferID: id)
            try await netstackWait("미수락 연결 RST") {
                guard let transfer = try await netstackTransfers(gate.tool).first(where: { $0.transferID == queued }),
                      transfer.state == "error" else { return false }
                #expect(transfer.error.localizedCaseInsensitiveContains("reset"))
                return true
            }
            let reopened = try await gate.node.listen(port: listener.port)
            let waiting = Task { () -> TailnetConnection? in
                var iterator = reopened.makeAsyncIterator()
                return await iterator.next()
            }
            await reopened.close()
            #expect(await waiting.value == nil)
        }
    }

    @Test("항목 10: 33번째 미수락 연결은 대기하고 자리가 나면 맺어진다")
    func acceptQueueLimit() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            for _ in 0..<32 {
                let id = try await netstackDial(gate, port: listener.port, count: 0)
                try await netstackWait("accept 대기열 채우기") {
                    try await netstackTransfers(gate.tool).contains { $0.transferID == id && $0.state == "running" }
                }
            }
            let id = try await netstackDial(gate, port: listener.port, count: 0)
            try await assertDialWaits(gate, id: id, stage: "33번째 미수락")
            let first = try await netstackAccept(listener)
            try await netstackWait("accept 자리 반환 뒤 연결") {
                try await netstackTransfers(gate.tool).contains { $0.transferID == id && $0.state == "running" }
            }
            await first.abort()
            await listener.close()
        }
    }

    @Test("항목 10: 한 피어의 65번째 연결은 대기하고 자리가 나면 맺어진다")
    func connectionLimit() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            // 상대 주소 하나의 연결은 64개까지다(계약 동작 S "검토에서 고친 것"). 전체 256개 상한은 피어가 넷 넘게 있어야
            // 닿으므로 단위 시험(`StackLimitTests`)이 본다. 준비 전송의 TIME-WAIT가 끼지 않도록 새 노드에서 바로 채운다.
            let listener = try await gate.node.listen(port: 9_101)
            var connections: [TailnetConnection] = []
            for _ in 0..<64 {
                _ = try await netstackDial(gate, port: listener.port, count: 0)
                connections.append(try await netstackAccept(listener))
            }
            let id = try await netstackDial(gate, port: listener.port, count: 0)
            try await assertDialWaits(gate, id: id, stage: "65번째 연결")
            await connections.removeFirst().abort()
            let next = try await netstackAccept(listener)
            try await netstackWait("연결 자리 반환 뒤 연결") {
                try await netstackTransfers(gate.tool).contains { $0.transferID == id && $0.state == "running" }
            }
            #expect(await gate.node.status.state == .running)
            await next.abort()
            for connection in connections { await connection.abort() }
            await listener.close()
        }
    }

    @Test("첫 사용처 6: testcontrol에 Swift .inProcess 노드 둘을 붙여 listen·connect")
    func twoSwiftNodes() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m6-second-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: directory) }
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            #expect(nodes.count >= 2)
            // 기존 시험 서버의 controlURL을 새 계정 없이 재사용한다(README 예제와 같은 공개 API).
            let controlURL = try #require(gate.controlURL)
            let server = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-5e6f7a8b",
                controlURL: controlURL), device: .inProcess)
            let listener = try await server.listen(port: 9_200)
            let run = Task { try await server.run() }
            do {
                let addresses = try await running(server)
                let address = try #require(addresses.first { $0.isIPv4 })
                try await netstackWait("Swift 노드 둘의 상호 netmap 반영") {
                    let clientStatus = await gate.node.status
                    let serverStatus = await server.status
                    return clientStatus.peerCount >= 2 && serverStatus.peerCount >= 2
                }
                let pair = try await netstackDeadline("Swift 노드 둘 교환") {
                    let accepted = Task { try await netstackAccept(listener) }
                    let client = try await gate.node.connect(to: address.description, port: 9_200)
                    let peer = try await accepted.value
                    #expect(client.remoteEndpoint.address == address)
                    #expect(peer.remoteEndpoint.address == (try gate.local.address()))
                    try await client.write([1, 2, 3])
                    try await client.finishWriting()
                    var request: [UInt8] = []
                    while let bytes = try await peer.read() { request += bytes }
                    #expect(request == [1, 2, 3])
                    try await peer.write([4, 5])
                    try await peer.finishWriting()
                    var response: [UInt8] = []
                    while let bytes = try await client.read() { response += bytes }
                    #expect(response == [4, 5])
                    await client.close()
                    await peer.close()
                    return true
                }
                #expect(pair)
                await gate.tool.checkpoint("M6 Swift 노드 둘: 3바이트 요청·2바이트 응답, 반닫힘·EOF·remoteEndpoint 일치")
                await listener.close()
                run.cancel()
                try await run.value
            } catch {
                await listener.close()
                run.cancel()
                _ = await run.result
                throw error
            }
        }
    }
}

private func assertDialWaits(_ gate: Gate, id: Int, stage: String) async throws {
    let until = ContinuousClock.now + .seconds(2)
    repeat {
        let transfer = try #require(await netstackTransfers(gate.tool).first { $0.transferID == id })
        #expect(transfer.state == "dialing", "\(stage): SYN에 응답하지 않아야 한다")
        try await Task.sleep(for: .milliseconds(100))
    } while ContinuousClock.now < until
    await gate.tool.checkpoint("M6 10 \(stage): 2초 동안 dialing·연결 미성립")
}

private func lossNote(_ message: String) async {
    try? FileHandle.standardOutput.write(contentsOf: Data("[관문 \(Date().ISO8601Format())] \(message)\n".utf8))
}
