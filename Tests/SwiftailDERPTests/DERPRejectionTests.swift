import SwiftailBase
import SwiftailDERP
import Testing

/// 서버가 규격을 어기거나 한도를 넘을 때: 오류의 종류, 받아 둔 바이트 버리기, 실패 뒤 `closed`.
@Suite("DERP 거절과 한도")
struct DERPRejectionTests {
    /// 실패한 연결은 이후 모든 호출이 `closed`이고 내보낼 바이트도 없다.
    private func expectClosed(_ connection: inout DERPConnection, sourceLocation: SourceLocation = #_sourceLocation) throws {
        #expect(throws: DERPError.closed, sourceLocation: sourceLocation) { try connection.receive([0x06, 0, 0, 0, 0]) }
        #expect(throws: DERPError.closed, sourceLocation: sourceLocation) { try connection.send([1], to: DERPFixtures.nodeKey(1)) }
        #expect(connection.takeOutboundBytes().isEmpty, sourceLocation: sourceLocation)
    }

    @Test("101이 아닌 상태는 upgradeRejected다")
    func notSwitchingProtocols() throws {
        for status in [200, 400, 426, 503] {
            var connection = try DERPFixtures.connection()
            let response = "HTTP/1.1 \(status) Nope\r\nContent-Length: 0\r\n\r\n"
            #expect(throws: DERPError.upgradeRejected(status: status)) { try connection.receive(Array(response.utf8)) }
            try expectClosed(&connection)
        }
    }

    @Test("101이 아니면 머리가 이상해도 상태가 먼저다")
    func statusBeforeMalformedHeader() throws {
        var connection = try DERPFixtures.connection()
        #expect(throws: DERPError.upgradeRejected(status: 404)) { try connection.receive(Array("HTTP/1.1 404 No\r\nbad header line\r\n\r\n".utf8)) }
    }

    @Test("응답 머리가 형식에 맞지 않거나 16KiB를 넘으면 malformed다")
    func malformedHead() throws {
        var garbage = try DERPFixtures.connection()
        #expect(throws: DERPError.malformed) { try garbage.receive(Array("not http\r\n\r\n".utf8)) }
        try expectClosed(&garbage)

        var huge = try DERPFixtures.connection()
        #expect(throws: DERPError.malformed) { try huge.receive([UInt8](repeating: UInt8(ascii: "a"), count: 16 * 1024 + 1)) }
        try expectClosed(&huge)
    }

    @Test("magic이 틀린 ServerKey는 handshakeFailed다")
    func wrongMagic() throws {
        var connection = try DERPFixtures.connection()
        var body = try DERPFixtures.bytes(DERPFixtures.serverPublic)
        body = [UInt8](repeating: 0x44, count: 8) + body
        #expect(throws: DERPError.handshakeFailed) { try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x01, body)) }
        try expectClosed(&connection)
    }

    @Test("ServerKey 본문이 40바이트 미만이거나 1,024바이트를 넘으면 handshakeFailed다")
    func serverKeyLengths() throws {
        let valid = try DERPFixtures.Server.magic + DERPFixtures.bytes(DERPFixtures.serverPublic)
        for body in [Array(valid.dropLast()), valid + [UInt8](repeating: 0, count: 1_025 - valid.count)] {
            var connection = try DERPFixtures.connection()
            #expect(throws: DERPError.handshakeFailed) { try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x01, body)) }
            try expectClosed(&connection)
        }
        // 정확히 1,024바이트는 받는다.
        var accepted = try DERPFixtures.connection()
        let events = try accepted.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x01, valid + [UInt8](repeating: 0, count: 1_024 - valid.count)))
        #expect(events == [.ready])
    }

    @Test("ServerKey 자리에 다른 프레임이 오면 handshakeFailed다")
    func firstFrameIsNotServerKey() throws {
        var connection = try DERPFixtures.connection()
        #expect(throws: DERPError.handshakeFailed) { try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x06, [])) }
        try expectClosed(&connection)
    }

    @Test("열리지 않는 ServerInfo는 handshakeFailed, 열렸지만 JSON이 아니면 malformed다")
    func badServerInfo() throws {
        var tampered = try DERPFixtures.readyConnection()
        var frame = try DERPFixtures.Server.serverInfoFrame()
        frame[frame.count - 1] ^= 0x01
        #expect(throws: DERPError.handshakeFailed) { try tampered.receive(frame) }
        try expectClosed(&tampered)

        var tooShort = try DERPFixtures.readyConnection()
        #expect(throws: DERPError.handshakeFailed) { try tooShort.receive(DERPFixtures.Server.frame(0x03, [UInt8](repeating: 0, count: 23))) }

        var notJSON = try DERPFixtures.readyConnection()
        #expect(throws: DERPError.malformed) { try notJSON.receive(DERPFixtures.Server.serverInfoFrame(Array("not json".utf8))) }
        try expectClosed(&notJSON)
    }

    @Test("프레임 본문은 1MiB까지 받고 1MiB + 1바이트는 머리만 보고 frameTooLarge다")
    func frameBodyLimit() throws {
        var accepted = try DERPFixtures.readyConnection()
        #expect(try accepted.receive(DERPFixtures.Server.frame(0xEE, [UInt8](repeating: 0, count: 1 << 20))).isEmpty)

        // 본문이 한 바이트도 오기 전에 거절한다. 한도를 넘는 메모리를 쌓지 않는다.
        var connection = try DERPFixtures.readyConnection()
        let length = UInt32(1 << 20) + 1
        let head: [UInt8] = [0x05, UInt8(length >> 24), UInt8(truncatingIfNeeded: length >> 16), UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)]
        #expect(throws: DERPError.frameTooLarge) { try connection.receive(head) }
        try expectClosed(&connection)
    }

    @Test("답하지 않은 Pong이 64KiB를 넘으면 tooManyPendingReplies, takeOutboundBytes가 비우면 다시 받는다")
    func pendingReplyLimit() throws {
        let ping = DERPFixtures.Server.frame(0x12, [UInt8](repeating: 7, count: 8))
        // Pong 하나는 13바이트이므로 5,041개(65,533바이트)까지는 들어간다.
        let allowed = 65_536 / 13
        var connection = try DERPFixtures.readyConnection()
        #expect(try connection.receive([UInt8]((0..<allowed).map { _ in ping }.joined())).isEmpty)
        #expect(connection.takeOutboundBytes().count == allowed * 13)
        #expect(try connection.receive([UInt8]((0..<allowed).map { _ in ping }.joined())).isEmpty)

        // 꺼내지 않은 채 하나 더 넣으면 넘는다.
        #expect(throws: DERPError.tooManyPendingReplies) { try connection.receive(ping + ping) }
        try expectClosed(&connection)
    }

    @Test("준비 전 send는 notReady이고 연결을 끝내지 않는다")
    func sendBeforeReady() throws {
        var connection = try DERPFixtures.connection()
        let peer = try DERPFixtures.nodeKey(1)
        #expect(throws: DERPError.notReady) { try connection.send([1], to: peer) }
        #expect(try connection.receive(DERPFixtures.Server.upgradeResponse).isEmpty)
        #expect(throws: DERPError.notReady) { try connection.send([1], to: peer) }
        #expect(try connection.receive(DERPFixtures.Server.serverKeyFrame()) == [.ready])
        try connection.send([1], to: peer)
    }

    @Test("패킷은 65,536바이트까지 보내고 65,537바이트는 packetTooLarge다. 연결은 산다")
    func packetSizeLimit() throws {
        var connection = try DERPFixtures.readyConnection()
        let peer = try DERPFixtures.nodeKey(1)
        try connection.send([UInt8](repeating: 0, count: 65_536), to: peer)
        #expect(connection.takeOutboundBytes().count == 5 + 32 + 65_536)
        #expect(throws: DERPError.packetTooLarge) { try connection.send([UInt8](repeating: 0, count: 65_537), to: peer) }
        #expect(connection.takeOutboundBytes().isEmpty)
        try connection.send([1], to: peer)
    }

    @Test("실패하면 아직 프레임이 되지 못한 받은 바이트도 버린다")
    func failureDropsBufferedBytes() throws {
        var connection = try DERPFixtures.readyConnection()
        // 1MiB 초과 프레임 머리 뒤에 올바른 프레임이 붙어 와도 처리되지 않는다.
        let peer = try DERPFixtures.nodeKey(1)
        let bad: [UInt8] = [0x05, 0xFF, 0xFF, 0xFF, 0xFF]
        #expect(throws: DERPError.frameTooLarge) { try connection.receive(bad + DERPFixtures.Server.recvPacket(from: peer, [1])) }
        try expectClosed(&connection)
    }
}
