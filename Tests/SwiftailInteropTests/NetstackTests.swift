import CryptoKit
import Foundation
import Swiftail
import SwiftailBase
import Testing

@Suite("M6 gate (a): Swift TCP ↔ Go gVisor", .enabled(if: tailnetBinary != nil,
    "Skipping the M6 gate because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(60)))
struct NetstackTests {
    private static let large: UInt64 = 104_857_600

    @Test("Transfer helper covers public LCG64 vectors and chunk boundaries")
    func streamVector() {
        var whole = NetstackStream(seed: 1)
        var split = NetstackStream(seed: 1)
        let bytes = whole.bytes(32)
        #expect(bytes.hex == "7c00fd43ac6f576c1b1b4a86b38668820eaa972099e1faa5c5579311cd550362")
        #expect(Array(SHA256.hash(data: Data(bytes))).hex == "d96bbb8821f933a5b368b9c127d725ed65b2d2f89f5b6d4505545306e834537d")
        #expect(split.bytes(3) + split.bytes(9) + split.bytes(20) == bytes)
        #expect(NetstackStream.header(count: 3, seed: 1) == [0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    @Test("Items 1 and 3: Swift listen, Go dial, small IPv4 and IPv6 transfers and 100MiB in both directions")
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

    @Test("Items 2 and 3: Swift connect, Go listen, IP, FQDN, short name, and 100MiB in both directions")
    func swiftConnects() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            let fqdn = try await netstackPrepare(gate)
            let short = String(try #require(fqdn.split(separator: ".").first))
            let hosts = [try gate.peer.address().description, try gate.peer.address(ipv4: false).description, fqdn, short]
            for host in hosts {
                let sizes: [UInt64] = IPAddress(host)?.isIPv4 == false ? [3, 10_485_760, Self.large] : [3, Self.large]
                for size in sizes {
                    let connection = try await netstackDeadline("Items 2 and 3 connect") {
                        try await gate.node.connect(to: host, port: 9_100)
                    }
                    let family = connection.remoteEndpoint.address.isIPv4 ? "IPv4" : "IPv6"
                    let kind = IPAddress(host) == nil ? (host == short ? "short name" : "FQDN") : family
                    #expect(connection.remoteEndpoint.port == 9_100)
                    #expect(gate.peer.addresses.contains(connection.remoteEndpoint.address))
                    try await connection.write(NetstackStream.header(count: size, seed: 1))
                    try await netstackExchange(gate, connection: connection, stage: "2·3 Swift connect \(kind) \(size)",
                        sendCount: size, receiveCount: size)
                }
            }
        }
    }

    @Test("Item 4: 100MiB in both directions over DERP with direct paths blocked by setBlockedUDPPorts")
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

    @Test("Item 5: ports without listeners are refused before the timeout in both directions")
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
                await gate.tool.checkpoint("M6 5 Go error: \(redacted(transfer.error.replacingOccurrences(of: transfer.remote, with: "<test address>"))), \(transfer.elapsedMs)ms")
                return true
            }
            await gate.tool.checkpoint("M6 5 refused in both directions: \(started.duration(to: .now))")
        }
    }

    @Test("Item 6: after calling finishWriting first, still reads the opposite direction to EOF")
    func halfClose() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let connection = try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
            try await connection.write(NetstackStream.header(count: 1_048_576, seed: 7))
            try await netstackExchange(gate, connection: connection, stage: "6 asymmetric half-close",
                sendCount: 3, receiveCount: 1_048_576, sendSeed: 2, receiveSeed: 7, requireReadAfterFIN: true)
            await #expect(throws: ConnectionError.closed) { try await connection.write([1]) }
        }
    }

    @Test("Item 6: Go reads Swift abort as connection reset")
    func swiftAbort() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            let id = try await netstackDial(gate, port: listener.port, count: 0)
            let connection = try await netstackAccept(listener)
            _ = try await netstackPreface(connection)
            // Disconnect after Go finishes writing so the tool reports the RST on read instead of a write failure.
            #expect(try await connection.read() == nil)
            await connection.abort()
            await #expect(throws: ConnectionError.closed) { try await connection.read() }
            try await netstackWait("Go reset error") {
                guard let transfer = try await netstackTransfers(gate.tool).first(where: { $0.transferID == id }),
                      transfer.state == "error" else { return false }
                #expect(transfer.error.localizedCaseInsensitiveContains("reset"))
                await gate.tool.checkpoint("M6 6 Swift abort: Go \(redacted(transfer.error.replacingOccurrences(of: transfer.remote, with: "<test address>"))), sent \(transfer.sent), received \(transfer.received), \(transfer.elapsedMs)ms")
                return true
            }
            await listener.close()
        }
    }

    @Test("Item 6: Go sends RST when closing with unread data after an invalid header")
    func goReset() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let connection = try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
            // The Go tool closes the connection on a header exceeding 4GiB. The unread data after it triggers gVisor's RST.
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

    @Test("Item 7: 4MiB in both directions on each of 32 concurrent connections, with phys_footprint sampling")
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
                        try await netstackExchange(gate, connection: pair.0, stage: "7 concurrent connection \(index + 1)/32",
                            sendCount: 4_194_304, receiveCount: 4_194_304, transferID: pair.1)
                    }
                }
                try await group.waitForAll()
            }
            await listener.close()
        }
    }

    @Test("Items 8, 9, and N3: 0%, 1%, and 5% loss, 20MiB, with no 30-second stall in receive progress")
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
                    let measurement = try await netstackExchange(gate, connection: connection, stage: "8 and 9 loss \(Int(loss * 100))% seed 19766",
                        sendCount: preface.count, receiveCount: 20_971_520, transferID: id, timeoutSeconds: 1_800)
                    rates[loss] = measurement.bytesPerSecond
                    await listener.close()
                }
            } catch {
                Issue.record(error, "Loss \(Int(loss * 100))% seed 19766")
            }
        }
        if let baseline = rates[0], let onePercent = rates[0.01] {
            let ratio = onePercent / baseline
            await lossNote("M6 N3: 0%=\(baseline), 1%=\(onePercent), 5%=\(rates[0.05].map(String.init(describing:)) ?? "incomplete") bytes/second, 1%/0%=\(ratio), M6-10 criterion (below 0.1)=\(ratio < 0.1)")
        } else {
            await lossNote("M6 N3: cannot determine the throughput ratio because a 0% or 1% transfer is incomplete")
        }
    }

    /// In simultaneous bidirectional transfers, ACKs travel with data and gVisor does not count them as duplicate ACKs (netstack contract behavior F5). Record a separate value closer
    /// to real use, where the large transfer goes in one direction.
    @Test("Item 8 supplement: record one-way 20MiB throughput at 0% and 1% loss")
    func oneWayLoss() async throws {
        let size: UInt64 = 20_971_520
        for (name, sendCount, receiveCount) in [("Swift→Go", size, UInt64(3)), ("Go→Swift", UInt64(3), size)] {
            var rates: [Double: Double] = [:]
            for loss in [0.0, 0.01] {
                try await withGate(direct: false, device: .inProcess) { gate in
                    _ = try await netstackPrepare(gate)
                    await gate.node.setInProcessLoss(rate: loss, seed: 0x4d_36)
                    let connection = try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
                    try await connection.write(NetstackStream.header(count: receiveCount, seed: 7))
                    let measurement = try await netstackExchange(gate, connection: connection,
                        stage: "8 one-way \(name) loss \(Int(loss * 100))%",
                        sendCount: sendCount, receiveCount: receiveCount, sendSeed: 2, receiveSeed: 7, timeoutSeconds: 1_800)
                    rates[loss] = measurement.bytesPerSecond
                }
            }
            if let baseline = rates[0], let onePercent = rates[0.01] {
                await lossNote("M6 one-way \(name): 0%=\(baseline), 1%=\(onePercent) bytes/second, 1%/0%=\(onePercent / baseline)")
            }
        }
    }

    @Test("Closing the listener ends the waiting stream, preserves accepted connections, and resets unaccepted connections")
    func listenerClose() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            let id = try await netstackDial(gate, port: listener.port, count: 3)
            let accepted = try await netstackAccept(listener)
            _ = try await netstackPreface(accepted)
            let queued = try await netstackDial(gate, port: listener.port, count: 3)
            try await netstackWait("Data sent on the unaccepted connection") {
                try await netstackTransfers(gate.tool).contains { $0.transferID == queued && $0.sent == 3 }
            }
            await listener.close()
            var iterator = listener.makeAsyncIterator()
            #expect(await iterator.next() == nil)
            try await netstackExchange(gate, connection: accepted, stage: "Accepted connection stays open after listener close",
                sendCount: 3, receiveCount: 3, transferID: id)
            try await netstackWait("RST on unaccepted connection") {
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

    @Test("Item 10: a peer's 17th unaccepted connection waits and connects when a slot opens")
    func acceptQueueLimit() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            _ = try await netstackPrepare(gate)
            let listener = try await gate.node.listen(port: 9_101)
            // One peer gets 16 slots in the listener's queue of 32 (contract behavior S, "Per-Peer Share"). Reaching the overall queue limit takes two peers,
            // so `StackLimitTests` covers it with a unit test.
            for _ in 0..<16 {
                let id = try await netstackDial(gate, port: listener.port, count: 0)
                try await netstackWait("Filling the accept queue") {
                    try await netstackTransfers(gate.tool).contains { $0.transferID == id && $0.state == "running" }
                }
            }
            let id = try await netstackDial(gate, port: listener.port, count: 0)
            try await assertDialWaits(gate, id: id, stage: "17th unaccepted connection")
            let first = try await netstackAccept(listener)
            try await netstackWait("Connect after an accept slot is freed") {
                try await netstackTransfers(gate.tool).contains { $0.transferID == id && $0.state == "running" }
            }
            await first.abort()
            await listener.close()
        }
    }

    @Test("Item 10: a peer's 65th connection waits and connects when a slot opens")
    func connectionLimit() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            // Connections to one remote address are limited to 64 (contract behavior S, "Changes from Review"). Reaching the overall limit of 256 takes more than four peers,
            // so `StackLimitTests` covers it with a unit test. Fill the limit immediately on a fresh node to avoid TIME-WAIT from the setup transfer.
            let listener = try await gate.node.listen(port: 9_101)
            var connections: [TailnetConnection] = []
            for _ in 0..<64 {
                _ = try await netstackDial(gate, port: listener.port, count: 0)
                connections.append(try await netstackAccept(listener))
            }
            let id = try await netstackDial(gate, port: listener.port, count: 0)
            try await assertDialWaits(gate, id: id, stage: "65th connection")
            await connections.removeFirst().abort()
            let next = try await netstackAccept(listener)
            try await netstackWait("Connect after a connection slot is freed") {
                try await netstackTransfers(gate.tool).contains { $0.transferID == id && $0.state == "running" }
            }
            #expect(await gate.node.status.state == .running)
            await next.abort()
            for connection in connections { await connection.abort() }
            await listener.close()
        }
    }

    @Test("First adopter 6: listen and connect with two Swift .inProcess nodes on testcontrol")
    func twoSwiftNodes() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m6-second-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: directory) }
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            #expect(nodes.count >= 2)
            // Reuse the existing test server's controlURL without a new account (same public API as the README example).
            let controlURL = try #require(gate.controlURL)
            let server = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-5e6f7a8b",
                controlURL: controlURL), device: .inProcess)
            let listener = try await server.listen(port: 9_200)
            let run = Task { try await server.run() }
            do {
                let addresses = try await running(server)
                let address = try #require(addresses.first { $0.isIPv4 })
                try await netstackWait("Both Swift nodes appear in each other's netmaps") {
                    let clientStatus = await gate.node.status
                    let serverStatus = await server.status
                    return clientStatus.peerCount >= 2 && serverStatus.peerCount >= 2
                }
                let pair = try await netstackDeadline("Exchange between two Swift nodes") {
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
                await gate.tool.checkpoint("M6 two Swift nodes: 3-byte request, 2-byte response, half-close, EOF, and matching remoteEndpoint")
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
        #expect(transfer.state == "dialing", "\(stage): must not respond to SYN")
        try await Task.sleep(for: .milliseconds(100))
    } while ContinuousClock.now < until
    await gate.tool.checkpoint("M6 10 \(stage): dialing for 2 seconds without establishing a connection")
}

private func lossNote(_ message: String) async {
    try? FileHandle.standardOutput.write(contentsOf: Data("[gate \(Date().ISO8601Format())] \(message)\n".utf8))
}
