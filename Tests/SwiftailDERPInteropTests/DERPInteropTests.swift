import SwiftailBase
import SwiftailDERP
import Testing

/// Go DERP 서버(`tailnet` 도구, 자체 서명 TLS)에 `DERPClient` 둘을 서로 다른 키로 붙인다.
/// 계약 `docs/contracts/SwiftailDERP.md` "시험"의 상호 운용 1~5.
@Suite("DERP 상호 운용: Go DERP 서버", .enabled(if: tailnetBinary != nil, "SWIFTAIL_TAILNET가 없어 건너뜀"))
struct DERPInteropTests {
    private func binary() throws -> String {
        try #require(tailnetBinary)
    }

    @Test("양쪽이 connected가 된다: Network 프레임워크 TLS가 Go 시험 서버와 맺어진다")
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

    @Test("A → B, B → A로 패킷이 간다: 1바이트, 1,280바이트, 65,536바이트. 보낸 쪽 키가 맞다")
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

    @Test("서버가 모르는 키로 보내도 연결이 끊기지 않는다")
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
                    // 그 뒤에도 같은 연결로 왕복이 된다. 연결이 끊겼다면 `disconnected`가 지나갔을 것이다.
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

    @Test("B를 취소해도 A는 정상이고, B를 다시 띄우면 다시 주고받는다")
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

                // B의 `run()`이 취소되어 소켓이 닫혔다. 서버는 B에게서 받은 적 있는 A에게 PeerGone을 보낸다.
                try await watchA.waitForPeerGone(b.publicKey)

                // 같은 키로 B를 다시 띄운다.
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

    @Test("70초 넘게 유지된다: 서버의 KeepAlive(60초 + [0, 5)초)를 넘긴다", .timeLimit(.minutes(3)))
    func staysUpPastKeepAlive() async throws {
        try await TailnetProcess.run(binary: binary()) { server in
            let a = DERPTestNode(server: server), b = DERPTestNode(server: server)
            var watchA = DERPWatcher(a), watchB = DERPWatcher(b)
            try await running(a) {
                try await running(b) {
                    try await watchA.waitForConnected()
                    try await watchB.waitForConnected()
                    try await establishPath(from: a, to: b, receiverWatcher: &watchB)

                    // 시간이 흐르기를 기다린다. 이 사이 연결이 끊기면 사건 흐름에 `disconnected`가 남는다.
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
