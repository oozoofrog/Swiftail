import SwiftailBase
import SwiftailDERP
import Testing

/// Checks the error type, discarding received bytes, and reaching `closed` after failure when a server violates the spec or exceeds a limit.
@Suite("DERP rejection and limits")
struct DERPRejectionTests {
    /// After a connection fails, all subsequent calls return `closed` and there are no outbound bytes.
    private func expectClosed(_ connection: inout DERPConnection, sourceLocation: SourceLocation = #_sourceLocation) throws {
        #expect(throws: DERPError.closed, sourceLocation: sourceLocation) { try connection.receive([0x06, 0, 0, 0, 0]) }
        #expect(throws: DERPError.closed, sourceLocation: sourceLocation) { try connection.send([1], to: DERPFixtures.nodeKey(1)) }
        #expect(connection.takeOutboundBytes().isEmpty, sourceLocation: sourceLocation)
    }

    @Test("A status other than 101 yields upgradeRejected")
    func notSwitchingProtocols() throws {
        for status in [200, 400, 426, 503] {
            var connection = try DERPFixtures.connection()
            let response = "HTTP/1.1 \(status) Nope\r\nContent-Length: 0\r\n\r\n"
            #expect(throws: DERPError.upgradeRejected(status: status)) { try connection.receive(Array(response.utf8)) }
            try expectClosed(&connection)
        }
    }

    @Test("For a status other than 101, the status takes precedence even if the header is malformed")
    func statusBeforeMalformedHeader() throws {
        var connection = try DERPFixtures.connection()
        #expect(throws: DERPError.upgradeRejected(status: 404)) { try connection.receive(Array("HTTP/1.1 404 No\r\nbad header line\r\n\r\n".utf8)) }
    }

    @Test("A malformed response header or one exceeding 16KiB yields malformed")
    func malformedHead() throws {
        var garbage = try DERPFixtures.connection()
        #expect(throws: DERPError.malformed) { try garbage.receive(Array("not http\r\n\r\n".utf8)) }
        try expectClosed(&garbage)

        var huge = try DERPFixtures.connection()
        #expect(throws: DERPError.malformed) { try huge.receive([UInt8](repeating: UInt8(ascii: "a"), count: 16 * 1024 + 1)) }
        try expectClosed(&huge)
    }

    @Test("ServerKey with incorrect magic yields handshakeFailed")
    func wrongMagic() throws {
        var connection = try DERPFixtures.connection()
        var body = try DERPFixtures.bytes(DERPFixtures.serverPublic)
        body = [UInt8](repeating: 0x44, count: 8) + body
        #expect(throws: DERPError.handshakeFailed) { try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x01, body)) }
        try expectClosed(&connection)
    }

    @Test("A ServerKey body shorter than 40 bytes or longer than 1,024 bytes yields handshakeFailed")
    func serverKeyLengths() throws {
        let valid = try DERPFixtures.Server.magic + DERPFixtures.bytes(DERPFixtures.serverPublic)
        for body in [Array(valid.dropLast()), valid + [UInt8](repeating: 0, count: 1_025 - valid.count)] {
            var connection = try DERPFixtures.connection()
            #expect(throws: DERPError.handshakeFailed) { try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x01, body)) }
            try expectClosed(&connection)
        }
        // Accepts exactly 1,024 bytes.
        var accepted = try DERPFixtures.connection()
        let events = try accepted.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x01, valid + [UInt8](repeating: 0, count: 1_024 - valid.count)))
        #expect(events == [.ready])
    }

    @Test("A different frame in place of ServerKey yields handshakeFailed")
    func firstFrameIsNotServerKey() throws {
        var connection = try DERPFixtures.connection()
        #expect(throws: DERPError.handshakeFailed) { try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.frame(0x06, [])) }
        try expectClosed(&connection)
    }

    @Test("ServerInfo that cannot be opened yields handshakeFailed. ServerInfo that opens but is not JSON yields malformed")
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

    @Test("Frame bodies up to 1MiB are accepted and 1MiB + 1 byte yields frameTooLarge based on the header alone")
    func frameBodyLimit() throws {
        var accepted = try DERPFixtures.readyConnection()
        #expect(try accepted.receive(DERPFixtures.Server.frame(0xEE, [UInt8](repeating: 0, count: 1 << 20))).isEmpty)

        // Rejects before even one byte of the body arrives. Memory does not grow beyond the limit.
        var connection = try DERPFixtures.readyConnection()
        let length = UInt32(1 << 20) + 1
        let head: [UInt8] = [0x05, UInt8(length >> 24), UInt8(truncatingIfNeeded: length >> 16), UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)]
        #expect(throws: DERPError.frameTooLarge) { try connection.receive(head) }
        try expectClosed(&connection)
    }

    @Test("More than 64KiB of pending Pong replies yields tooManyPendingReplies. Pings are accepted again after takeOutboundBytes drains the replies")
    func pendingReplyLimit() throws {
        let ping = DERPFixtures.Server.frame(0x12, [UInt8](repeating: 7, count: 8))
        // A Pong is 13 bytes, so up to 5,041 (65,533 bytes) fit.
        let allowed = 65_536 / 13
        var connection = try DERPFixtures.readyConnection()
        #expect(try connection.receive([UInt8]((0..<allowed).map { _ in ping }.joined())).isEmpty)
        #expect(connection.takeOutboundBytes().count == allowed * 13)
        #expect(try connection.receive([UInt8]((0..<allowed).map { _ in ping }.joined())).isEmpty)

        // Adding one more without draining them exceeds the limit.
        #expect(throws: DERPError.tooManyPendingReplies) { try connection.receive(ping + ping) }
        try expectClosed(&connection)
    }

    @Test("Calling send before readiness yields notReady and leaves the connection open")
    func sendBeforeReady() throws {
        var connection = try DERPFixtures.connection()
        let peer = try DERPFixtures.nodeKey(1)
        #expect(throws: DERPError.notReady) { try connection.send([1], to: peer) }
        #expect(try connection.receive(DERPFixtures.Server.upgradeResponse).isEmpty)
        #expect(throws: DERPError.notReady) { try connection.send([1], to: peer) }
        #expect(try connection.receive(DERPFixtures.Server.serverKeyFrame()) == [.ready])
        try connection.send([1], to: peer)
    }

    @Test("Sends packets up to 65,536 bytes. A packet of 65,537 bytes yields packetTooLarge and leaves the connection open")
    func packetSizeLimit() throws {
        var connection = try DERPFixtures.readyConnection()
        let peer = try DERPFixtures.nodeKey(1)
        try connection.send([UInt8](repeating: 0, count: 65_536), to: peer)
        #expect(connection.takeOutboundBytes().count == 5 + 32 + 65_536)
        #expect(throws: DERPError.packetTooLarge) { try connection.send([UInt8](repeating: 0, count: 65_537), to: peer) }
        #expect(connection.takeOutboundBytes().isEmpty)
        try connection.send([1], to: peer)
    }

    @Test("Failure also discards received bytes that have yet to form a frame")
    func failureDropsBufferedBytes() throws {
        var connection = try DERPFixtures.readyConnection()
        // A valid frame following a frame header for more than 1MiB is never processed.
        let peer = try DERPFixtures.nodeKey(1)
        let bad: [UInt8] = [0x05, 0xFF, 0xFF, 0xFF, 0xFF]
        #expect(throws: DERPError.frameTooLarge) { try connection.receive(bad + DERPFixtures.Server.recvPacket(from: peer, [1])) }
        try expectClosed(&connection)
    }
}
