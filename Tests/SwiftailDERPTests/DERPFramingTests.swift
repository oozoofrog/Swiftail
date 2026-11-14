import SwiftailBase
import SwiftailDERP
import Testing

/// 노트 3장의 바이트 표 그대로의 고정 벡터.
@Suite("DERP 프레임")
struct DERPFramingTests {
    @Test("SendPacket: 타입 0x04, 길이 32 + n, 목적지 키, 패킷")
    func sendPacketBytes() throws {
        var connection = try DERPFixtures.readyConnection()
        try connection.send([0xAA, 0xBB, 0xCC], to: DERPFixtures.nodeKey(0x11))
        let expected: [UInt8] = [0x04, 0, 0, 0, 35] + [UInt8](repeating: 0x11, count: 32) + [0xAA, 0xBB, 0xCC]
        #expect(connection.takeOutboundBytes() == expected)
    }

    @Test("SendPacket은 프레임마다 한 덩어리로 순서대로 쌓인다")
    func sendPacketsInOrder() throws {
        var connection = try DERPFixtures.readyConnection()
        try connection.send([1], to: DERPFixtures.nodeKey(1))
        try connection.send([2, 2], to: DERPFixtures.nodeKey(2))
        let expected = DERPFixtures.Server.frame(0x04, [UInt8](repeating: 1, count: 32) + [1])
            + DERPFixtures.Server.frame(0x04, [UInt8](repeating: 2, count: 32) + [2, 2])
        #expect(connection.takeOutboundBytes() == expected)
    }

    @Test("RecvPacket: 앞 32바이트가 보낸 쪽 키, 나머지가 패킷. 키만 있으면 빈 패킷")
    func recvPacket() throws {
        var connection = try DERPFixtures.readyConnection()
        let peer = try DERPFixtures.nodeKey(0x22)
        #expect(try connection.receive(DERPFixtures.Server.recvPacket(from: peer, [5, 6])) == [.packet([5, 6], from: peer)])
        #expect(try connection.receive(DERPFixtures.Server.recvPacket(from: peer, [])) == [.packet([], from: peer)])
    }

    @Test("32바이트 미만의 RecvPacket·PeerGone은 버리고 연결을 유지한다")
    func shortBodiesAreDropped() throws {
        var connection = try DERPFixtures.readyConnection()
        let short = [UInt8](repeating: 1, count: 31)
        #expect(try connection.receive(DERPFixtures.Server.frame(0x05, short)).isEmpty)
        #expect(try connection.receive(DERPFixtures.Server.frame(0x08, short)).isEmpty)
        #expect(try connection.receive(DERPFixtures.Server.frame(0x05, [])).isEmpty)
        let peer = try DERPFixtures.nodeKey(0x22)
        #expect(try connection.receive(DERPFixtures.Server.recvPacket(from: peer, [1])) == [.packet([1], from: peer)])
    }

    @Test("PeerGone의 이유 코드: 0 disconnected, 1 notHere, 그 밖은 그대로, 이유 바이트가 없으면 disconnected")
    func peerGoneReasons() throws {
        var connection = try DERPFixtures.readyConnection()
        let peer = try DERPFixtures.nodeKey(0x33)
        let cases: [([UInt8], DERPConnection.PeerGoneReason)] = [
            ([0x00], .disconnected), ([0x01], .notHere), ([0xF0], .unknown(0xF0)), ([0x42], .unknown(0x42)), ([], .disconnected),
        ]
        for (reason, expected) in cases {
            #expect(try connection.receive(DERPFixtures.Server.frame(0x08, peer.rawValue + reason)) == [.peerGone(peer, reason: expected)])
        }
    }

    @Test("Ping은 같은 8바이트의 Pong이 되어 나간다. 8바이트 미만은 버리고 넘치는 바이트는 자른다")
    func pingPong() throws {
        var connection = try DERPFixtures.readyConnection()
        let value: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        #expect(try connection.receive(DERPFixtures.Server.frame(0x12, value)).isEmpty)
        #expect(connection.takeOutboundBytes() == [0x13, 0, 0, 0, 8] + value)

        #expect(try connection.receive(DERPFixtures.Server.frame(0x12, Array(value.dropLast()))).isEmpty)
        #expect(connection.takeOutboundBytes().isEmpty)

        #expect(try connection.receive(DERPFixtures.Server.frame(0x12, value + [9, 9])).isEmpty)
        #expect(connection.takeOutboundBytes() == [0x13, 0, 0, 0, 8] + value)
    }

    @Test("모르는 프레임·Health·Restarting·KeepAlive·Pong·PeerPresent를 건너뛰고 그 뒤 프레임을 읽는다")
    func skipsUnhandledFrames() throws {
        var connection = try DERPFixtures.readyConnection()
        let peer = try DERPFixtures.nodeKey(0x44)
        let skipped = DERPFixtures.Server.frame(0xEE, [1, 2, 3])
            + DERPFixtures.Server.frame(0x14, Array("overloaded".utf8))
            + DERPFixtures.Server.frame(0x15, [0, 0, 0, 1, 0, 0, 0, 2])
            + DERPFixtures.Server.frame(0x06, [])
            + DERPFixtures.Server.frame(0x13, [UInt8](repeating: 0, count: 8))
            + DERPFixtures.Server.frame(0x09, [UInt8](repeating: 1, count: 32))
        let events = try connection.receive(skipped + DERPFixtures.Server.recvPacket(from: peer, [7]))
        #expect(events == [.packet([7], from: peer)])
        #expect(connection.takeOutboundBytes().isEmpty)
    }
}
