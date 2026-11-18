import SwiftailBase
import SwiftailDERP
import Testing

/// Connects two `DERPClient` instances with distinct keys to the Go DERP server (`tailnet` tool, self-signed TLS).
/// Interop tests 1–5 under "Tests" in the `docs/contracts/SwiftailDERP.md` contract.
@Suite("DERP interop with the Go DERP server", .enabled(if: tailnetBinary != nil, "Skipping because SWIFTAIL_TAILNET is missing"))
struct DERPInteropTests {
    private func binary() throws -> String {
        try #require(tailnetBinary)
    }

    @Test("Both clients become connected. Network framework TLS is established with the Go test server")
    func bothConnect() async throws {
        try await TailnetProcess.run(binary: binary()) { server in
            let a = DERPTestNode(server: server), b = DERPTestNode(server: server)
            var watchA = DERPWatcher(a), watchB = DERPWatcher(b)
            try await running(a) {
                try await running(b) {
                    try await watchA.waitForConnected()
                    try await watchB.waitForConnected()
                }
            }
        }
    }

    @Test("Packets go A → B and B → A at 1 byte, 1,280 bytes, and 65,536 bytes. The sender key is correct")
    func exchangePackets() async throws {
        try await TailnetProcess.run(binary: binary()) { server in
            let a = DERPTestNode(server: server), b = DERPTestNode(server: server)
            var watchA = DERPWatcher(a), watchB = DERPWatcher(b)
            try await running(a) {
                try await running(b) {
                    try await watchA.waitForConnected()
                    try await watchB.waitForConnected()
                    try await establishPath(from: a, to: b, receiverWatcher: &watchB)

                    for size in [1, 1_280, 65_536] {
                        let packet = samplePacket(size: size)
                        await a.client.send(packet, to: b.publicKey)
                        #expect(try await watchB.waitForPacket(packet) == a.publicKey)
                        await b.client.send(packet, to: a.publicKey)
                        #expect(try await watchA.waitForPacket(packet) == b.publicKey)
                    }
                }
            }
        }
    }

    @Test("Sending to a key unknown to the server does not disconnect")
    func sendToUnknownKey() async throws {
        try await TailnetProcess.run(binary: binary()) { server in
            let a = DERPTestNode(server: server), b = DERPTestNode(server: server)
            let nobody = DERPTestNode(server: server)
            var watchA = DERPWatcher(a), watchB = DERPWatcher(b)
            try await running(a) {
                try await running(b) {
                    try await watchA.waitForConnected()
                    try await watchB.waitForConnected()
                    try await establishPath(from: a, to: b, receiverWatcher: &watchB)

                    await a.client.send(samplePacket(size: 1_280), to: nobody.publicKey)
                    // Round trips still work on the same connection afterward. A disconnect would have produced a `disconnected` event.
                    let packet = samplePacket(size: 100)
                    await a.client.send(packet, to: b.publicKey)
                    _ = try await watchB.waitForPacket(packet)
                    await b.client.send(packet, to: a.publicKey)
                    _ = try await watchA.waitForPacket(packet)
                    #expect(watchA.disconnectedCount == 0)
                    #expect(watchA.connectedCount == 1)
                }
            }
        }
    }

    @Test("Canceling B leaves A working, and restarting B restores packet exchange")
    func peerLeavesAndReturns() async throws {
        try await TailnetProcess.run(binary: binary()) { server in
            let a = DERPTestNode(server: server), b = DERPTestNode(server: server)
            var watchA = DERPWatcher(a), watchB = DERPWatcher(b)
            try await running(a) {
                try await watchA.waitForConnected()
                try await running(b) {
                    try await watchB.waitForConnected()
                    try await establishPath(from: a, to: b, receiverWatcher: &watchB)
                    let packet = samplePacket(size: 64)
                    await b.client.send(packet, to: a.publicKey)
                    _ = try await watchA.waitForPacket(packet)
                }

                // Canceling B's `run()` closed the socket. The server sends PeerGone to A, which previously received a packet from B.
                try await watchA.waitForPeerGone(b.publicKey)

                // Restart B with the same key.
                let returned = DERPTestNode(server: server, privateKey: b.privateKey)
                var watchReturned = DERPWatcher(returned)
                try await running(returned) {
                    try await watchReturned.waitForConnected()
                    try await establishPath(from: a, to: returned, receiverWatcher: &watchReturned)
                    let packet = samplePacket(size: 1_280)
                    await returned.client.send(packet, to: a.publicKey)
                    #expect(try await watchA.waitForPacket(packet) == returned.publicKey)
                    await a.client.send(packet, to: returned.publicKey)
                    #expect(try await watchReturned.waitForPacket(packet) == a.publicKey)
                }
                #expect(watchA.disconnectedCount == 0)
            }
        }
    }

    @Test("Stays connected for over 70 seconds, past the server's KeepAlive interval (60 seconds + [0, 5) seconds)", .timeLimit(.minutes(3)))
    func staysUpPastKeepAlive() async throws {
        try await TailnetProcess.run(binary: binary()) { server in
            let a = DERPTestNode(server: server), b = DERPTestNode(server: server)
            var watchA = DERPWatcher(a), watchB = DERPWatcher(b)
            try await running(a) {
                try await running(b) {
                    try await watchA.waitForConnected()
                    try await watchB.waitForConnected()
                    try await establishPath(from: a, to: b, receiverWatcher: &watchB)

                    // Wait for time to pass. A disconnect during this interval leaves a `disconnected` event in the event stream.
                    try await Task.sleep(for: .seconds(72), clock: .continuous)

                    let packet = samplePacket(size: 512)
                    await a.client.send(packet, to: b.publicKey)
                    _ = try await watchB.waitForPacket(packet)
                    await b.client.send(packet, to: a.publicKey)
                    _ = try await watchA.waitForPacket(packet)
                    #expect(watchA.disconnectedCount == 0 && watchB.disconnectedCount == 0)
                    #expect(watchA.connectedCount == 1 && watchB.connectedCount == 1)
                }
            }
        }
    }
}
